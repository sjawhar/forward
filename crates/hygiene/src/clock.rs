//! Clock domains, kept apart by the type system.
//!
//! The two binaries use two different clocks, correctly, for different jobs:
//!
//! - The devbox authority measures grant lifetime with `Instant`
//!   (`CLOCK_MONOTONIC`). It is the machine that never sleeps, so monotonic
//!   time and wall-clock time do not diverge there.
//! - The laptop mirror measures its lease deadlines with [`BootTime`]
//!   (`CLOCK_BOOTTIME`), which *does* advance across suspend. That is what
//!   makes a slept laptop's cached lease expire at the same real instant the
//!   never-sleeping authority thinks it expires, instead of surviving the
//!   suspend with its remaining time intact.
//!
//! Comparing one to the other is always a bug, and before this crate the only
//! thing preventing it was that no code happened to do it. `BootTime` is a
//! distinct type rather than a bare `Duration` so that mixing the domains is a
//! compile error.

use std::time::Duration;

use nix::time::ClockId;

/// A point in time on `CLOCK_BOOTTIME`, as a duration since boot.
///
/// Deliberately not convertible to or from `Instant`: they are different
/// domains, and the whole purpose of this type is that the conversion cannot be
/// written by accident.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BootTime(Duration);

impl BootTime {
    /// Read the current boot time.
    ///
    /// # Errors
    ///
    /// Returns the `nix` error if `clock_gettime` fails, or if the kernel
    /// reports a negative component. Callers treat this as fatal: a process
    /// that cannot read the clock it enforces deadlines with must not keep
    /// serving, because every subsequent expiry decision would be a guess.
    pub fn now() -> Result<Self, ClockError> {
        let now = ClockId::CLOCK_BOOTTIME.now().map_err(ClockError::Read)?;
        let seconds = u64::try_from(now.tv_sec()).map_err(|_| ClockError::Negative)?;
        let nanoseconds = u32::try_from(now.tv_nsec()).map_err(|_| ClockError::Negative)?;
        Ok(Self(Duration::new(seconds, nanoseconds)))
    }

    /// This instant advanced by `duration`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// How much of `self` remains from `earlier`, saturating at zero.
    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Construct from a raw duration since boot. Tests build deadlines
    /// directly; production code goes through [`BootTime::now`].
    #[must_use]
    pub const fn from_duration_since_boot(duration: Duration) -> Self {
        Self(duration)
    }

    /// The raw duration since boot.
    ///
    /// Needed to hand an absolute `CLOCK_BOOTTIME` deadline to `timerfd`, which
    /// takes a `TimeSpec` and knows nothing about this type.
    #[must_use]
    pub const fn as_duration_since_boot(self) -> Duration {
        self.0
    }
}

/// Why a boot-time read failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClockError {
    /// `clock_gettime(CLOCK_BOOTTIME)` failed.
    Read(nix::Error),
    /// The kernel reported a negative seconds or nanoseconds component.
    Negative,
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "could not read CLOCK_BOOTTIME: {error}"),
            Self::Negative => write!(formatter, "CLOCK_BOOTTIME reported a negative component"),
        }
    }
}

impl std::error::Error for ClockError {}
