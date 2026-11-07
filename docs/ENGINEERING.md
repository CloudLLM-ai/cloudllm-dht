# Engineering pipeline

How cloudllm_dht is built, tested, audited and measured, and how to reproduce
every CI job on your own machine. The layout is meant to be copied to the other
CloudLLM-ai Rust crates: the workflow files are thin, the logic is in the
`Makefile` and in `scripts/`, and this page is the manual.

## The shape of it

| Workflow | Triggers | What it answers |
|---|---|---|
| `ci.yml` | push to master, pull request, manual | Does it build, lint, test, document, hold its MSRV, meet the coverage gate, and replay the fuzz corpora? |
| `audit.yml` | push to master, pull request, **daily**, manual | Is any dependency vulnerable, unmaintained, yanked, wrongly licensed or from an unexpected source? |
| `fuzz.yml` | **weekly** (Monday), manual, called by `security.yml` | Does coverage-guided fuzzing of every target find anything new? |
| `bench.yml` | **weekly** (Sunday), manual, pull requests touching `src/` or `benches/` (advisory) | Did anything get slower? |
| `soak.yml` | **weekly** (Saturday), manual | Does a simulated network under churn and BEP 44 traffic keep working and keep its state bounded? |
| `security.yml` | **weekly** (Monday), manual | One review: audit, security lints, unsafe inventory, a longer fuzz pass. |

Rules the workflows follow:

- **A step is a `make` target.** `make fmt-check`, `make coverage`, `make deny`
  do the same thing on your laptop and on the runner. If you change what a job
  does, you change the `Makefile` or a script, not YAML.
- **Actions are pinned by major version** (`actions/checkout@v4`,
  `taiki-e/install-action@v2`) and tools by exact version (`cargo-deny@0.20.2`,
  `cargo-fuzz 0.13.2`). Dependabot opens a pull request when a newer action
  exists.
- **No secrets.** Every workflow runs with `contents: read` (bench also reads
  `actions` to fetch the previous baseline). Nothing pushes to the repository;
  a person commits corpora and baselines.
- **Shared setup is a composite action** (`.github/actions/setup-fuzz`), so the
  nightly toolchain and the `cargo-fuzz` version live in one file.
- Each workflow file opens with a comment saying what it is for and which doc
  section to read.

## Reproducing a job locally

| Job | Command | Needs |
|---|---|---|
| Format, check, clippy, tests, docs | `make ci` (or one of `make fmt-check`, `check`, `clippy`, `test`, `doc`) | stable Rust |
| MSRV | `make msrv` | `rustup toolchain install 1.88` |
| Dependency policy | `make deny` | `cargo install cargo-deny` |
| Coverage | `make coverage` (`make coverage-open` to view) | `cargo install cargo-llvm-cov`, `rustup component add llvm-tools-preview` |
| Security lints | `make clippy-security` | stable Rust |
| Fuzz build and corpus replay | `make fuzz-build fuzz-replay` | nightly, `cargo install cargo-fuzz` |
| Fuzz one target | `make fuzz TARGET=dht_ops FUZZ_SECONDS=300` | same |
| Minimize a corpus | `make fuzz-cmin TARGET=dht_ops` | same |
| Benchmarks | `make bench bench-json`, then `make bench-baseline bench-compare` | `gh` logged in, for the baseline |
| Soak | `make soak SOAK_SECONDS=600` | stable Rust, `ps` |

`make help` lists every target.

## Dependency policy

`audit.yml`, `deny.toml`, `.github/dependabot.yml`.

`cargo deny check` runs four checks from `deny.toml`, on every push and pull
request and once a day (an advisory can appear against a dependency that did
not change):

- **advisories**: RustSec vulnerabilities, unmaintained and yanked crates. Any
  hit fails.
- **licenses**: an allowlist of exactly the licenses the tree uses today (MIT,
  Apache-2.0 with and without the LLVM exception, BSD-3-Clause, Unicode-3.0).
  A new license is a decision for a person.
- **bans**: wildcard version requirements are denied; duplicate versions of one
  crate are a warning (today `syn`).
- **sources**: crates.io only.

There are no advisory `ignore` entries: the dependency tree (`crc32c`,
`curve25519-dalek`, `getrandom`, `sha1`, `sha2`, `thiserror`, and tokio behind
`tokio-driver`) has no findings. When one appears, an entry needs the advisory
id and the reason it cannot hurt us.

**Dependabot** opens weekly pull requests for Cargo (the crate and `fuzz/`) and
for GitHub Actions, grouping minor and patch updates. Every one runs the full
CI before anyone merges it.

## Coverage

`ci.yml` job `coverage`, `scripts/coverage_gate.py`.

`make coverage` runs the whole test suite under `cargo llvm-cov`, writes an
HTML report, an `lcov.info` and a `summary.json` into `target/coverage/`, and
fails when any of **regions, functions or lines** is under **90%**. CI uploads
the HTML and lcov as the `coverage-report` artifact and writes the table into
the job summary.

Measured on 2026-11-06, `src/` only:

| Metric | Before this work | After |
|---|---:|---:|
| Regions | 90.91% | 93.07% |
| Functions | 89.96% | 93.04% |
| Lines | 91.15% | 93.17% |

Functions were under the bar, so the gate would have failed on day one. What
was added (behavior tests, not padding): `tests/tracker_surface.rs` drives the
`Dht` control surface an embedder uses and no test touched (the request hook,
replaced settings, counters, socket errors, direct requests, external-address
changes, `state`, `status`, `add_node`, `sample_infohashes`), and
`tests/value_types.rs` pins the public value types (the redacted `SecretKey`
debug output, `Entry` builders, conversions and rendering, `Sha1Hash` views).

**Nothing is excluded** (`COVERAGE_IGNORE` in the `Makefile` matches no file).
The tokio driver is covered by `tests/driver.rs` on loopback sockets; the one
test that needs the Internet, `tests/live.rs`, is `#[ignore]`d and not counted.

**Branch coverage is not measured here.** It needs nightly and the unstable
`-Z coverage-options=branch` flag, whose behavior has changed between
nightlies, so a gate on it would break CI when the toolchain moves, not when
the code does. `make coverage-branch` prints it for a person who wants to look
(mentischat, which has the same setup, measured 79.9% on it, well under what
its region and line coverage showed). Turn a branch gate on when the flag is stable.

The gate is 90% on purpose and the measured numbers are above it, so an
ordinary change does not trip it and a change that adds a lot of untested code
does. Raise the number as the margin grows; never lower it to land a change.

## Fuzzing

`ci.yml` job `fuzz`, `fuzz.yml`, `fuzz/`.

Every parser of untrusted bytes and every state machine reachable from outside
has a target in `fuzz/fuzz_targets/`, asserting invariants rather than just
"does not panic".

| Target | Surface |
|---|---|
| `bdecode` | the bencode decoder, on arbitrary datagrams |
| `message_parse` | decode, the per-query verifier tables, compact node and endpoint parsing, typed tokens |
| `node_incoming` | the whole receive path: `Dht::incoming_packet` with arbitrary bytes from arbitrary endpoints |
| `item_verify` | BEP 44 item authentication, the gate every remote `put` passes |
| `traversal_replies` | what every traversal does with an untrusted response (get_peers, bootstrap, get, put, sample_infohashes, direct requests) |
| `routing_table_ops` | the routing table under an arbitrary operation sequence |
| `storage_ops` | `DefaultStorage` against its own counters under colliding announces, evictions and expiry |
| `state_load` | the saved-state loader |
| `dht_ops` | `Dht` as callers drive it: an arbitrary interleaving of operations and late, dropped or duplicated datagrams |

The tokio driver only moves datagrams between a socket and
`Dht::incoming_packet`, which `node_incoming` covers, so it has no target of its
own.

**Per push**, `ci.yml` builds every target and replays the committed corpora
(`make fuzz-build fuzz-replay`, seconds). **Weekly**, `fuzz.yml` fuzzes every
target for five minutes (`seconds` input on a manual run); the matrix comes from
`make fuzz-targets` (`cargo fuzz list`), so a new target is fuzzed without
editing the workflow. `security.yml` calls it again with 15 minutes per target.

**When a run finds something**: the job fails and uploads
`fuzz-crashes-<target>`. Download it, minimize with
`cargo +nightly fuzz tmin <target> <file>`, turn it into a named regression
test under `tests/`, fix it, add the input to `fuzz/corpus/<target>/`, and write
the changelog line.

**Corpus growth**: every run uploads `fuzz-corpus-<target>` (30 days). A person
downloads it into `fuzz/corpus/<target>/`, runs `make fuzz-cmin TARGET=<target>`
so only inputs that add coverage stay, and commits the result. CI never pushes.

## Weekly security audit

`security.yml`.

One run, Monday 05:11 UTC, four jobs. Findings are in the job summaries.

1. **audit**: `make deny` (a gate, as above) and `cargo audit` (a report; see
   the table above for why it says more than `cargo deny`).
2. **lints**: `make clippy-security` on shipped code (`--lib`, not tests).
   - *Gate*, clean today: `clippy::unwrap_used`, `todo`, `unimplemented`,
     `dbg_macro`, `mem_forget` are denied. This job and `ci.yml`'s `verify`
     job are separate, so a new `unwrap()` is caught here; promote the gate into
     `ci.yml` by adding `make clippy-security` after `make clippy` if you want it
     per push.
   - *Report*, not clean today (counts on 2026-11-06): `arithmetic_side_effects`
     215, `indexing_slicing` 145, `expect_used` 30, `panic` 3. They are listed per
     file in the summary. They are not gated because they are mostly
     intentional: bounds are checked on the line above, counters cannot
     overflow in a process lifetime, and the `expect`s and `panic!`s are mostly
     invariants of constants and of data the same function just built. The
     arithmetic and indexing counts are high because the crate is a port of
     libtorrent's bit-twiddling Kademlia code (IDs, distances, buckets). Burn them down file by file and move a lint
     into the gate when its count reaches zero.
3. **unsafe**: `cargo geiger`, an inventory of `unsafe` in the dependency tree
   (report). Our own crate is `#![forbid(unsafe_code)]` in `src/lib.rs`, which the compiler enforces on every build, so the inventory
   is only about dependencies.
4. **fuzz**: the longer pass over every target, 15 minutes each.

**Proposal, not implemented: an AI review.** A scheduled job could hand the
week's diff (`git log --since=1.week -p -- src/`) to a model with a
security-reviewer prompt and open an issue with its findings. It is left out
because it needs an API key stored as a repository secret and sends source to a
third party; if it is wanted, the key should be scoped to that one job, the
output should be an issue (never a commit or a status check that blocks), and
findings should be treated as leads to verify, not as results.

## Benchmarks

`bench.yml`, `scripts/bench.py`, `benches/`.

`make bench` runs the Criterion suite in `benches/` (`routing_table`: `find_node`
on a full table, `node_seen` into a populated table and on a known node,
`classify_prefix`). `make bench-json` reduces them to
`target/bench/current.json`: the **median** time of each benchmark in
nanoseconds, medians because a mean is dragged around by the one slow iteration
a noisy neighbour causes.

- **Schedule**: Sunday 03:41 UTC on master. The run uploads `bench-results`
  (kept 90 days); those artifacts are the history. The baseline for a run is
  the `bench-results` of the previous successful scheduled run
  (`make bench-baseline`, needs `gh`).
- **Threshold**: `BENCH_THRESHOLD=25` percent. A benchmark more than 25% slower
  than its baseline is flagged with a warning annotation and a row in the job
  summary, and fails a *scheduled* run.
- **Why so wide**: GitHub-hosted runners are shared virtual machines. The same
  commit moves by 10 to 20% between runs on them (neighbours, CPU model and
  frequency), and the multi-pair benchmarks more than the single-thread ones.
  A tighter threshold would cry wolf every week and teach people to ignore it.
  A real regression is usually a multiple; 25% catches those and misses
  small drift, which is what a local `cargo bench` against a saved baseline
  (`cargo bench -- --save-baseline main`, then `--baseline main`) is for.
- **Pull requests** that touch `src/`, `benches/` or `Cargo.*` run the benches in
  Criterion's `--quick` mode and compare against the latest baseline, but only
  advisory: the job never fails on it. A manual run defaults to advisory as well
  (`advisory: false` makes it fail).
- **First run**: until a scheduled run has succeeded there is no baseline, and
  the summary says so. Trigger `bench.yml` manually on master once to seed it
  (a manual run uploads results but is not picked up as a baseline, which only
  scheduled runs provide; the first Sunday does it).

## Soak test

`soak.yml`, `tests/soak.rs`, `tests/sim_support/`.

A long, deterministic, in-memory simulation (the network of `tests/sim_support`,
in simulated time): 200 started nodes with seeded routing tables. Every round of
30 simulated seconds:

1. **Churn.** 2% of the online nodes go offline for one to four rounds (a switched
   off host: it sends and receives nothing and its timers stop), and 0.5% are
   replaced by fresh joiners with new IDs and addresses, seeded with 16 live nodes.
2. **Traffic.** Six operations at random online nodes: immutable puts and gets,
   mutable puts (eight publishers, rising sequence numbers) and gets, announces
   and `get_peers`.

The run lasts `SOAK_SECONDS` of wall clock (3600 in the weekly job), which is tens
of thousands of rounds: about 90 simulated hours in 100 seconds on a laptop, with
roughly 25,000 puts and 28,000 gets. It asserts:

1. **It keeps working.** Over the run at least 95% of puts are acknowledged by
   some node, at least 90% of immutable gets return the stored value, and at
   least 90% of mutable gets return a sequence number no lower than the highest
   acknowledged put. (Measured: 99.7%, 98.4% and 100%.)
2. **No operation leaks.** Every operation ends exactly once, within 20 rounds
   (a lookup that serially times out on offline nodes takes minutes of simulated
   time), nothing is reported for an operation that was not started, no node has
   more operations in flight than the soak started on it, and after the traffic
   stops and offline nodes return, none has any.
3. **State stays bounded.** Every 10 rounds, every online node's immutable items,
   mutable items and torrents are within the settings' caps (`max_dht_items`,
   `max_torrents`), its peers within `max_peers` per torrent, and its routing
   table (live and replacement entries) within its bucket capacity, however many
   items were put.
4. **Memory stays flat** (long run): the process's resident size at the end may
   not exceed 1.5x its level after warm-up plus 64 MiB. A 100 second run grew
   from 25.0 to 27.4 MiB over 10,000 rounds.

**Why the soak starts its nodes.** A `Dht` that was not `start`ed runs no timers,
so a request to a node that never answers waits forever (`next_timeout()` is
`None` while stopped; the one-lookup simulation tests never have dead nodes, so
they leave the nodes stopped). With the nodes stopped this soak saw a mutable get
that never ended once two nodes were offline. That is the documented sans-IO
contract, not a bug, but it is the first thing to check if an operation hangs.

`cargo test` runs `soak_smoke` (60 nodes, 20 rounds, assertions 1 to 3) so the
harness cannot rot. `make soak SOAK_SECONDS=600` runs `soak_long` locally;
`soak.yml` runs it for 3600 seconds every Saturday, with a 150 minute job limit.

## Adopting this in another crate

To copy the pipeline to another crate (it came from mentischat, and `mentisdb` is next):

1. Copy `.github/workflows/`, `.github/actions/`, `.github/dependabot.yml`,
   `deny.toml`, `scripts/` and the Makefile sections (`ci`, `msrv`, `deny`,
   `coverage*`, `clippy-security`, `bench*`, `soak`, `fuzz*`).
2. In `deny.toml`, start with an empty `ignore` list and add an entry (id and
   reason) only for a finding you have looked at. Check `[licenses] allow`
   against `cargo deny check licenses`.
3. In the `Makefile`, set `MSRV`, `COVERAGE_MIN`, `COVERAGE_IGNORE` (the files
   that genuinely cannot run in CI, with a reason in this document) and the
   `SECURITY_DENY` list (only lints the code is clean for).
4. Give the crate a soak scenario that fits it (a daemon binary: start it on
   port 0 and restart it mid-run, as mentischat's `tests/soak.rs` does; a
   sans-IO library: a simulation, as this crate's does). The thresholds are
   constants at the top of the file.
5. Add the badges to the README and adjust the schedule so the weekly jobs do
   not all start in the same minute.
6. Run each job once by hand (`workflow_dispatch`) and fix it until it is
   green before relying on it.
