//! Injectable time: the sans-IO core never reads the system clock.
//!
//! libtorrent calls `aux::time_now()` and `clock_type::now()` all over the
//! DHT; every one of those becomes a parameter or a [`Clock`] here, which is
//! what makes the traversal and routing-table state machines deterministic
//! and fuzzable.

use std::ops::{Add, Sub};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A point on a monotonic timeline, as the offset from an arbitrary epoch
/// (libtorrent `time_point`).
///
/// [`Time::ZERO`] doubles as libtorrent's `min_time()`: "never".
///
/// # Examples
///
/// ```
/// use cloudllm_dht::time::Time;
/// use std::time::Duration;
///
/// let t = Time::ZERO + Duration::from_secs(5);
/// assert_eq!(t - Time::ZERO, Duration::from_secs(5));
/// assert_eq!(Time::ZERO - t, Duration::ZERO); // saturating
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Time(Duration);

impl Time {
    /// The epoch, also libtorrent's `min_time()`.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// A time `d` after the epoch.
    #[must_use]
    pub const fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    /// The offset from the epoch.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.0
    }
}

impl Add<Duration> for Time {
    type Output = Time;
    fn add(self, d: Duration) -> Time {
        Time(self.0.saturating_add(d))
    }
}

impl Sub<Duration> for Time {
    type Output = Time;
    fn sub(self, d: Duration) -> Time {
        Time(self.0.saturating_sub(d))
    }
}

impl Sub<Time> for Time {
    type Output = Duration;
    /// The elapsed time, saturating at zero when `rhs` is later.
    fn sub(self, rhs: Time) -> Duration {
        self.0.saturating_sub(rhs.0)
    }
}

/// A source of [`Time`].
///
/// The DHT core takes `now` as an argument wherever it can; `Clock` is for
/// the places that must look it up themselves, and for drivers.
pub trait Clock {
    /// The current time on this clock's timeline.
    fn now(&self) -> Time;
}

/// A clock that only moves when told to: for tests and simulation.
///
/// Clones share the same timeline.
///
/// # Examples
///
/// ```
/// use cloudllm_dht::time::{Clock, ManualClock};
/// use std::time::Duration;
///
/// let c = ManualClock::new();
/// let c2 = c.clone();
/// c.advance(Duration::from_secs(3));
/// assert_eq!(c2.now().as_duration(), Duration::from_secs(3));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Arc<Mutex<Duration>>);

impl ManualClock {
    /// A clock at [`Time::ZERO`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Moves the clock forward (saturating).
    pub fn advance(&self, d: Duration) {
        let mut now = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *now = now.saturating_add(d);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Time {
        Time(
            *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// The real monotonic clock, anchored at its creation.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock(std::time::Instant);

impl SystemClock {
    /// Starts a clock whose epoch is now.
    #[must_use]
    pub fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Time {
        Time(self.0.elapsed())
    }
}
