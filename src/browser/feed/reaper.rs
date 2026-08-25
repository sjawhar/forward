use std::fmt::Display;
use std::sync::Arc;
use std::thread;

use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use parking_lot::Mutex;

use super::{BootTime, RelayTokens};

#[derive(Default)]
pub(super) struct Reaper {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    timer: Option<Arc<TimerFd>>,
    started: bool,
}

impl Reaper {
    pub(super) fn schedule(self: &Arc<Self>, tokens: RelayTokens) {
        let (timer, start) = self.timer();
        self.arm(&timer, &tokens);
        if start {
            let reaper = Arc::clone(self);
            thread::Builder::new()
                .name("grant-expiry".to_owned())
                .spawn(move || worker(tokens, reaper, timer))
                .map(drop)
                .unwrap_or_else(|error| fatal("start", error));
        }
    }

    fn timer(&self) -> (Arc<TimerFd>, bool) {
        let mut state = self.state.lock();
        let timer = state.timer.get_or_insert_with(new_timer).clone();
        let start = !state.started;
        state.started = true;
        (timer, start)
    }

    fn arm(&self, timer: &TimerFd, tokens: &RelayTokens) {
        let _state = self.state.lock();
        set(timer, tokens.next_deadline()).unwrap_or_else(|error| fatal("set", error));
    }
}

fn new_timer() -> Arc<TimerFd> {
    TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::TFD_CLOEXEC)
        .map(Arc::new)
        .unwrap_or_else(|error| fatal("create", error))
}

fn worker(tokens: RelayTokens, reaper: Arc<Reaper>, timer: Arc<TimerFd>) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            timer.wait().unwrap_or_else(|error| fatal("wait", error));
            tokens.reap_expired();
            reaper.arm(&timer, &tokens);
        }
    }));
    if outcome.is_err() {
        eprintln!("forward: grant feed expiry worker panicked; exiting");
    }
    std::process::exit(1);
}

fn set(timer: &TimerFd, deadline: Option<BootTime>) -> nix::Result<()> {
    match deadline {
        Some(deadline) => timer.set(
            Expiration::OneShot(TimeSpec::from(deadline)),
            TimerSetTimeFlags::TFD_TIMER_ABSTIME,
        ),
        None => timer.unset(),
    }
}

fn fatal(context: &str, error: impl Display) -> ! {
    eprintln!("forward: grant feed expiry worker could not {context}: {error}");
    std::process::exit(1);
}
