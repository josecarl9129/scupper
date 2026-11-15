//! Per-record controls for deterministic confirmation transaction tests.
use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct State {
    expired: AtomicBool,
    lose_ack: AtomicBool,
}
fn controls() -> &'static Mutex<BTreeMap<PathBuf, Arc<State>>> {
    static CONTROLS: OnceLock<Mutex<BTreeMap<PathBuf, Arc<State>>>> = OnceLock::new();
    CONTROLS.get_or_init(Mutex::default)
}
fn state(root: &Path) -> Option<Arc<State>> {
    controls()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(root)
        .cloned()
}
/// Gives a test ample I/O time and allows explicit deadline/acknowledgement faults.
/// Controls affect only this state root, and disappear when the guard is dropped.
pub struct Control {
    root: PathBuf,
    state: Arc<State>,
}
impl Control {
    /// Install a 30-second test budget; production uses 500 ms.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        let state = Arc::new(State::default());
        controls()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(root.into(), Arc::clone(&state));
        Self {
            root: root.into(),
            state,
        }
    }
    /// Expire both caller acceptance and the worker's persistence fence now.
    pub fn expire(&self) {
        self.state.expired.store(true, Ordering::SeqCst);
    }
    /// Drop the acknowledgement after the transaction has finished.
    pub fn lose_ack(&self) {
        self.state.lose_ack.store(true, Ordering::SeqCst);
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        controls()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.root);
    }
}
pub(super) fn budget(root: &Path) -> Duration {
    if state(root).is_some() {
        Duration::from_secs(30)
    } else {
        super::CONFIRMATION_BUDGET
    }
}
pub(super) fn check(root: &Path) -> io::Result<()> {
    if state(root).is_some_and(|s| s.expired.load(Ordering::SeqCst)) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "injected confirmation deadline",
        ))
    } else {
        Ok(())
    }
}
pub(super) fn ack_lost(root: &Path) -> bool {
    state(root).is_some_and(|s| s.lose_ack.load(Ordering::SeqCst))
}
pub(super) fn receive(
    root: &Path,
    receive: &mpsc::Receiver<io::Result<()>>,
    deadline: Instant,
) -> Result<io::Result<()>, mpsc::RecvTimeoutError> {
    loop {
        if check(root).is_err() || Instant::now() >= deadline {
            return Err(mpsc::RecvTimeoutError::Timeout);
        }
        match receive.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10)),
        ) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            outcome => return outcome,
        }
    }
}
