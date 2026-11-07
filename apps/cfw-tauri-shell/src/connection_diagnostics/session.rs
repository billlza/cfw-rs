//! One in-flight diagnostic, cancellation, and provider quota backoff.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, watch};
use uuid::Uuid;

#[derive(Default)]
struct GateState {
    active: Option<(Uuid, watch::Sender<bool>)>,
    next_lookup: Option<Instant>,
    cancelled: Option<Uuid>,
}

pub(crate) struct DiagnosticsGate {
    state: Mutex<GateState>,
    pub(super) resolvers: Arc<Semaphore>,
}

impl Default for DiagnosticsGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            resolvers: Arc::new(Semaphore::new(4)),
        }
    }
}

pub(crate) struct Activity<'a> {
    gate: &'a DiagnosticsGate,
    pub(crate) cancelled: watch::Receiver<bool>,
}

impl DiagnosticsGate {
    pub(crate) fn begin(&self, id: Uuid, lookup: bool) -> Result<Activity<'_>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "diagnostic state is unavailable")?;
        if state.cancelled == Some(id) {
            return Err("cancelled".into());
        }
        if state.active.is_some() {
            return Err("diagnostics_busy".into());
        }
        if lookup {
            if state
                .next_lookup
                .is_some_and(|deadline| Instant::now() < deadline)
            {
                return Err("lookup_cooldown".into());
            }
            state.next_lookup = Some(Instant::now() + Duration::from_secs(60));
        }
        let (sender, cancelled) = watch::channel(false);
        state.active = Some((id, sender));
        Ok(Activity {
            gate: self,
            cancelled,
        })
    }

    pub(crate) fn cancel(&self, id: Uuid) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "diagnostic state is unavailable")?;
        if let Some((current, sender)) = &state.active {
            if *current != id {
                return Err("diagnostic request changed".into());
            }
            sender.send_replace(true);
        }
        state.cancelled = Some(id);
        Ok(())
    }

    pub(crate) fn block_lookup(&self) -> Result<(), String> {
        self.state
            .lock()
            .map_err(|_| "diagnostic state is unavailable")?
            .next_lookup = Some(Instant::now() + Duration::from_secs(24 * 60 * 60));
        Ok(())
    }
}

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        match self.gate.state.lock() {
            Ok(mut state) => state.active = None,
            Err(_) => eprintln!("diagnostic activity could not be released: state lock poisoned"),
        }
    }
}
