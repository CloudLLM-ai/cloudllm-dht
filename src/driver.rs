//! The tokio UDP driver over the sans-IO core (feature `tokio-driver`).
//!
//! Not a libtorrent port: asio plays this role there (`dht_tracker`'s
//! `send_fun`, its deadline timers and the session's UDP sockets). See
//! `docs/ARCHITECTURE.md` sections 1 and 5.
//!
//! [`DhtHandle::bind`] binds UDP sockets, spawns one task that owns the
//! [`Dht`] and loops over three things: a datagram arrived, a command came
//! from a handle, the next timer is due. Every handle method sends a
//! command and awaits the answer, so the public API is plain `async fn`s.
//! The task ends when the last handle is dropped or [`DhtHandle::shutdown`]
//! is called.
//!
//! # Examples
//!
//! ```no_run
//! use cloudllm_dht::driver::DhtHandle;
//! use cloudllm_dht::settings::DhtSettings;
//! use cloudllm_dht::Sha1Hash;
//!
//! # async fn demo() -> std::io::Result<()> {
//! let dht = DhtHandle::bind(&["0.0.0.0:6881".parse().unwrap()], DhtSettings::default()).await?;
//! dht.bootstrap(&["router.bittorrent.com:6881"]).await?;
//! let peers = dht.lookup_peers(Sha1Hash::from_hex("e3811b9539cacff680e418124272177c47477157").unwrap(),
//!                              std::time::Duration::from_secs(10)).await;
//! println!("{peers:?}");
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::announce_flags::AnnounceFlags;
use crate::bencode::Entry;
use crate::dht_state::DhtState;
use crate::events::{Event, OpId};
use crate::item::Item;
use crate::node_id::NodeId;
use crate::settings::DhtSettings;
use crate::time::{Clock, SystemClock, Time};
use crate::tracker::{Dht, DhtBuilder, SocketErrorKind, SocketId};
use crate::types::PublicKey;

/// Largest datagram the driver reads. DHT messages are far smaller;
/// libtorrent reads 1300 bytes.
const RECV_BUFFER: usize = 2048;

type Reply<T> = oneshot::Sender<T>;

/// What a handle asks the task to do.
enum Command {
    Bootstrap {
        routers: Vec<SocketAddr>,
        done: Reply<()>,
    },
    GetPeers {
        info_hash: NodeId,
        sink: mpsc::UnboundedSender<Vec<SocketAddr>>,
    },
    Announce {
        info_hash: NodeId,
        port: u16,
        flags: AnnounceFlags,
    },
    GetImmutable {
        target: NodeId,
        reply: Reply<Option<Entry>>,
    },
    GetMutable {
        pk: PublicKey,
        salt: Vec<u8>,
        reply: Reply<Option<Item>>,
    },
    PutImmutable {
        data: Entry,
        reply: Reply<(NodeId, usize)>,
    },
    PutMutable {
        pk: PublicKey,
        salt: Vec<u8>,
        data_cb: Arc<dyn Fn(&mut Item) + Send + Sync>,
        reply: Reply<usize>,
    },
    Sample {
        ep: SocketAddr,
        target: NodeId,
        reply: Reply<Option<SampleReply>>,
    },
    Direct {
        ep: SocketAddr,
        request: Entry,
        reply: Reply<Option<Entry>>,
    },
    State(Reply<DhtState>),
    Shutdown,
}

/// A BEP 51 answer (see [`Event::SampleInfohashes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleReply {
    /// The node's ID.
    pub nid: NodeId,
    /// How long it asks us to wait before sampling it again.
    pub interval: Duration,
    /// How many info-hashes it stores.
    pub num: u32,
    /// A sample of them.
    pub samples: Vec<NodeId>,
    /// Nodes it suggests sampling next.
    pub nodes: Vec<(NodeId, SocketAddr)>,
}

/// A running DHT: clone it freely, every clone talks to the same task.
#[derive(Clone)]
pub struct DhtHandle {
    cmd: mpsc::UnboundedSender<Command>,
    events: broadcast::Sender<Event>,
    local: Arc<Vec<SocketAddr>>,
}

impl std::fmt::Debug for DhtHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtHandle")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl DhtHandle {
    /// Binds one UDP socket per address (usually one IPv4 and one IPv6
    /// wildcard, or `127.0.0.1:0` for tests) and starts the DHT with fresh
    /// state. Use [`DhtHandle::bind_with`] to restore saved state or inject
    /// storage and randomness.
    ///
    /// # Errors
    ///
    /// Any error from binding a socket.
    pub async fn bind(addrs: &[SocketAddr], settings: DhtSettings) -> io::Result<Self> {
        Self::bind_with(addrs, Dht::builder(settings)).await
    }

    /// [`DhtHandle::bind`] with a configured builder (state, storage, rng).
    ///
    /// # Errors
    ///
    /// Any error from binding a socket.
    pub async fn bind_with(addrs: &[SocketAddr], builder: DhtBuilder) -> io::Result<Self> {
        let clock = SystemClock::new();
        let mut dht = builder.build();
        let mut sockets = Vec::new();
        let mut local = Vec::new();
        for a in addrs {
            let s = Arc::new(UdpSocket::bind(a).await?);
            let bound = s.local_addr()?;
            // an unspecified bind has no usable external address yet
            let external = (!bound.ip().is_unspecified()).then(|| bound.ip());
            let id = dht.add_socket(bound, external, clock.now());
            sockets.push((id, s));
            local.push(bound);
        }
        dht.start(clock.now());
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (events, _) = broadcast::channel(1024);
        tokio::spawn(run(dht, sockets, clock, cmd_rx, events.clone()));
        Ok(Self {
            cmd: cmd_tx,
            events,
            local: Arc::new(local),
        })
    }

    /// The addresses the sockets are bound to.
    #[must_use]
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local
    }

    /// A stream of every [`Event`] the DHT produces, for logging or custom
    /// handling. A receiver that falls behind loses the oldest events
    /// (`RecvError::Lagged`).
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn send(&self, c: Command) {
        // the task is gone only after shutdown; a late command is dropped
        // and its reply channel closes, which the caller sees as `None`
        let _ = self.cmd.send(c);
    }

    async fn ask<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> Option<T> {
        let (tx, rx) = oneshot::channel();
        self.send(make(tx));
        rx.await.ok()
    }

    /// Resolves `routers` (`host:port` strings, for example
    /// `router.bittorrent.com:6881`), registers them as router nodes and
    /// bootstraps; returns when the bootstrap lookup has finished on every
    /// socket.
    ///
    /// # Errors
    ///
    /// The resolution error if none of the names resolves.
    pub async fn bootstrap(&self, routers: &[&str]) -> io::Result<()> {
        let mut eps = Vec::new();
        let mut last_err = None;
        for r in routers {
            match tokio::net::lookup_host(r).await {
                Ok(it) => eps.extend(it),
                Err(e) => last_err = Some(e),
            }
        }
        if eps.is_empty() {
            return Err(last_err
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no routers")));
        }
        self.bootstrap_endpoints(eps).await;
        Ok(())
    }

    /// [`DhtHandle::bootstrap`] with resolved endpoints.
    pub async fn bootstrap_endpoints(&self, routers: Vec<SocketAddr>) {
        let _ = self.ask(|done| Command::Bootstrap { routers, done }).await;
    }

    /// Starts a `get_peers` lookup and returns the stream of peers as nodes
    /// answer. The stream ends when the receiver is dropped. See
    /// [`DhtHandle::lookup_peers`] for the collect-for-a-while form.
    #[must_use]
    pub fn get_peers(&self, info_hash: NodeId) -> mpsc::UnboundedReceiver<Vec<SocketAddr>> {
        let (sink, rx) = mpsc::unbounded_channel();
        self.send(Command::GetPeers { info_hash, sink });
        rx
    }

    /// Runs a `get_peers` lookup and collects the distinct peers it finds
    /// within `wait`.
    pub async fn lookup_peers(&self, info_hash: NodeId, wait: Duration) -> Vec<SocketAddr> {
        let mut rx = self.get_peers(info_hash);
        let mut peers: Vec<SocketAddr> = Vec::new();
        let deadline = tokio::time::Instant::now() + wait;
        while let Ok(Some(batch)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            for p in batch {
                if !peers.contains(&p) {
                    peers.push(p);
                }
            }
        }
        peers
    }

    /// Looks `info_hash` up and announces `port` (0 means each socket's own
    /// port) to the closest nodes. Fire and forget, as in libtorrent.
    pub fn announce(&self, info_hash: NodeId, port: u16, flags: AnnounceFlags) {
        self.send(Command::Announce {
            info_hash,
            port,
            flags,
        });
    }

    /// Fetches an immutable item (BEP 44). `None` if nobody has it.
    pub async fn get_immutable(&self, target: NodeId) -> Option<Entry> {
        self.ask(|reply| Command::GetImmutable { target, reply })
            .await
            .flatten()
    }

    /// Fetches the best mutable item (BEP 44) for `pk` and `salt`. `None`
    /// if nobody has one.
    pub async fn get_mutable(&self, pk: PublicKey, salt: &[u8]) -> Option<Item> {
        let salt = salt.to_vec();
        self.ask(|reply| Command::GetMutable { pk, salt, reply })
            .await
            .flatten()
    }

    /// Stores an immutable item; returns its target and how many nodes
    /// acknowledged.
    pub async fn put_immutable(&self, data: Entry) -> Option<(NodeId, usize)> {
        self.ask(|reply| Command::PutImmutable { data, reply })
            .await
    }

    /// Stores a mutable item: `data_cb` receives the best item the network
    /// holds (empty if none) and must leave the signed item to store in it
    /// (see [`Dht::put_mutable_item`]). Returns the number of nodes that
    /// acknowledged.
    pub async fn put_mutable(
        &self,
        pk: PublicKey,
        salt: &[u8],
        data_cb: Arc<dyn Fn(&mut Item) + Send + Sync>,
    ) -> Option<usize> {
        let salt = salt.to_vec();
        self.ask(|reply| Command::PutMutable {
            pk,
            salt,
            data_cb,
            reply,
        })
        .await
    }

    /// Asks `ep` for a BEP 51 sample of its info-hashes.
    pub async fn sample_infohashes(&self, ep: SocketAddr, target: NodeId) -> Option<SampleReply> {
        self.ask(|reply| Command::Sample { ep, target, reply })
            .await
            .flatten()
    }

    /// Sends an arbitrary request to `ep` and returns the reply dictionary,
    /// or `None` if it timed out.
    pub async fn direct_request(&self, ep: SocketAddr, request: Entry) -> Option<Entry> {
        self.ask(|reply| Command::Direct { ep, request, reply })
            .await
            .flatten()
    }

    /// The state to persist (`DhtState::encode`): node IDs and routing-table
    /// endpoints.
    pub async fn save_state(&self) -> Option<DhtState> {
        self.ask(Command::State).await
    }

    /// Stops the task; pending requests resolve to `None`.
    pub fn shutdown(&self) {
        self.send(Command::Shutdown);
    }
}

/// Requests waiting for an event, keyed by what identifies their answer.
#[derive(Default)]
struct Pending {
    peers: HashMap<NodeId, Vec<mpsc::UnboundedSender<Vec<SocketAddr>>>>,
    immutable: HashMap<OpId, Reply<Option<Entry>>>,
    mutable: HashMap<OpId, Reply<Option<Item>>>,
    puts: HashMap<OpId, PutWaiter>,
    samples: HashMap<SocketAddr, Vec<Reply<Option<SampleReply>>>>,
    direct: HashMap<u64, Reply<Option<Entry>>>,
    bootstrap: Vec<(usize, Reply<()>)>,
}

enum PutWaiter {
    Immutable(Reply<(NodeId, usize)>),
    Mutable(Reply<usize>),
}

impl Pending {
    fn resolve_op(&mut self, op: OpId, result: &Event) {
        match result {
            Event::GetItemDone {
                item,
                authoritative: true,
                ..
            } => {
                if let Some(r) = self.immutable.remove(&op) {
                    let _ = r.send((!item.is_empty()).then(|| item.value().clone()));
                }
                if let Some(r) = self.mutable.remove(&op) {
                    let _ = r.send((!item.is_empty()).then(|| item.clone()));
                }
            }
            Event::PutDone {
                target, responses, ..
            } => match self.puts.remove(&op) {
                Some(PutWaiter::Immutable(r)) => {
                    let _ = r.send((*target, *responses));
                }
                Some(PutWaiter::Mutable(r)) => {
                    let _ = r.send(*responses);
                }
                None => {}
            },
            _ => {}
        }
    }

    fn resolve(&mut self, ev: &Event) {
        match ev {
            Event::GetPeersReply { target, peers } => {
                if let Some(v) = self.peers.get_mut(target) {
                    v.retain(|s| s.send(peers.clone()).is_ok());
                }
            }
            Event::Operation { op, result } => self.resolve_op(*op, result),
            Event::OperationCancelled { op } => {
                // dropping the senders makes the callers see `None`
                self.immutable.remove(op);
                self.mutable.remove(op);
                self.puts.remove(op);
            }
            Event::SampleInfohashes {
                from,
                nid,
                interval,
                num,
                samples,
                nodes,
            } => {
                for r in self.samples.remove(from).into_iter().flatten() {
                    let _ = r.send(Some(SampleReply {
                        nid: *nid,
                        interval: *interval,
                        num: *num,
                        samples: samples.clone(),
                        nodes: nodes.clone(),
                    }));
                }
            }
            Event::DirectResponse { token, reply, .. } => {
                if let Some(r) = self.direct.remove(token) {
                    let _ = r.send(reply.clone());
                }
            }
            Event::BootstrapDone => {
                for (remaining, _) in &mut self.bootstrap {
                    *remaining = remaining.saturating_sub(1);
                }
                let (done, waiting): (Vec<_>, Vec<_>) =
                    self.bootstrap.drain(..).partition(|(n, _)| *n == 0);
                self.bootstrap = waiting;
                for (_, r) in done {
                    let _ = r.send(());
                }
            }
            _ => {}
        }
    }
}

fn io_kind(e: &io::Error) -> SocketErrorKind {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => SocketErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset => SocketErrorKind::ConnectionReset,
        io::ErrorKind::ConnectionAborted => SocketErrorKind::ConnectionAborted,
        _ => SocketErrorKind::Other,
    }
}

/// Flushes the DHT's output: datagrams to their sockets, events to the
/// waiting requests and to subscribers.
async fn flush(
    dht: &mut Dht,
    sockets: &[(SocketId, Arc<UdpSocket>)],
    pending: &mut Pending,
    events: &broadcast::Sender<Event>,
    clock: &SystemClock,
) {
    while let Some(d) = dht.poll_transmit() {
        let Some((_, sock)) = sockets.iter().find(|(id, _)| *id == d.socket) else {
            continue;
        };
        if let Err(e) = sock.send_to(&d.payload, d.to).await {
            dht.socket_error(io_kind(&e), d.to, clock.now());
        }
    }
    for ev in dht.drain_events() {
        pending.resolve(&ev);
        // no subscribers is fine
        let _ = events.send(ev);
    }
}

/// How long to sleep when the DHT has no timer pending.
const IDLE: Duration = Duration::from_secs(3600);

/// A datagram read by a socket's reader task.
struct Inbound {
    socket: SocketId,
    from: SocketAddr,
    data: Vec<u8>,
}

/// Reads one socket forever, handing datagrams to the main loop. Read
/// errors (some platforms report ICMP unreachables this way, without the
/// peer) do not stop the reader; a closed channel does.
async fn reader(id: SocketId, sock: Arc<UdpSocket>, tx: mpsc::UnboundedSender<Inbound>) {
    let mut buf = vec![0u8; RECV_BUFFER];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, from)) => {
                let data = buf[..n].to_vec();
                if tx
                    .send(Inbound {
                        socket: id,
                        from,
                        data,
                    })
                    .is_err()
                {
                    return;
                }
            }
            Err(e) if matches!(io_kind(&e), SocketErrorKind::Other) => {
                // a persistent failure would spin; back off briefly
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {}
        }
    }
}

async fn run(
    mut dht: Dht,
    sockets: Vec<(SocketId, Arc<UdpSocket>)>,
    clock: SystemClock,
    mut cmd: mpsc::UnboundedReceiver<Command>,
    events: broadcast::Sender<Event>,
) {
    let mut pending = Pending::default();
    let (in_tx, mut inbound) = mpsc::unbounded_channel();
    let readers: Vec<_> = sockets
        .iter()
        .map(|(id, s)| tokio::spawn(reader(*id, Arc::clone(s), in_tx.clone())))
        .collect();
    drop(in_tx);
    let mut token = 0u64;
    flush(&mut dht, &sockets, &mut pending, &events, &clock).await;
    loop {
        let now = clock.now();
        let sleep = dht
            .next_timeout()
            .map_or(IDLE, |t| t - now.min(t))
            .max(Duration::from_millis(1));
        tokio::select! {
            () = tokio::time::sleep(sleep) => {
                dht.poll(clock.now());
            }
            Some(d) = inbound.recv() => {
                dht.incoming_packet(d.socket, d.from, &d.data, clock.now());
            }
            c = cmd.recv() => {
                let Some(c) = c else { break };
                if !handle(&mut dht, c, &mut pending, &mut token, clock.now()) {
                    break;
                }
            }
        }
        flush(&mut dht, &sockets, &mut pending, &events, &clock).await;
    }
    readers.iter().for_each(tokio::task::JoinHandle::abort);
}

/// Executes one command; `false` means shut down.
fn handle(dht: &mut Dht, c: Command, pending: &mut Pending, token: &mut u64, now: Time) -> bool {
    match c {
        Command::Bootstrap { routers, done } => {
            for r in &routers {
                dht.add_router_node(*r);
            }
            pending.bootstrap.push((dht.sockets().count(), done));
            dht.bootstrap(&routers, now);
        }
        Command::GetPeers { info_hash, sink } => {
            pending.peers.entry(info_hash).or_default().push(sink);
            dht.get_peers(info_hash, now);
        }
        Command::Announce {
            info_hash,
            port,
            flags,
        } => dht.announce(info_hash, port, flags, now),
        Command::GetImmutable { target, reply } => {
            let op = dht.get_immutable_item(target, now);
            pending.immutable.insert(op, reply);
        }
        Command::GetMutable { pk, salt, reply } => {
            let op = dht.get_mutable_item(pk, &salt, now);
            pending.mutable.insert(op, reply);
        }
        Command::PutImmutable { data, reply } => {
            let op = dht.put_immutable_item(data, now);
            pending.puts.insert(op, PutWaiter::Immutable(reply));
        }
        Command::PutMutable {
            pk,
            salt,
            data_cb,
            reply,
        } => {
            let op = dht.put_mutable_item(pk, &salt, data_cb, now);
            pending.puts.insert(op, PutWaiter::Mutable(reply));
        }
        Command::Sample { ep, target, reply } => {
            pending.samples.entry(ep).or_default().push(reply);
            dht.sample_infohashes(ep, target, now);
        }
        Command::Direct { ep, request, reply } => {
            *token += 1;
            pending.direct.insert(*token, reply);
            dht.direct_request(ep, request, *token, now);
        }
        Command::State(reply) => {
            let _ = reply.send(dht.state());
        }
        Command::Shutdown => {
            dht.shutdown(now);
            return false;
        }
    }
    true
}
