//! Admission for a single native initialization, independent of the renderer.
use std::sync::Mutex;

use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Preparing,
    Installed,
    Ready,
    Failed { installed: bool, error: String },
    Cancelled,
}

pub(crate) struct NativeStartup {
    phase: Mutex<Phase>,
    completion: watch::Sender<Option<Result<(), String>>>,
}

impl Default for NativeStartup {
    fn default() -> Self {
        Self {
            phase: Mutex::new(Phase::Preparing),
            completion: watch::channel(None).0,
        }
    }
}

impl NativeStartup {
    /// `install` must only publish prepared in-memory state and enqueue its
    /// coordinator task. Filesystem and OS calls belong before this boundary.
    pub(crate) fn install(
        &self,
        install: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| "native startup state lock failed")?;
        if *phase != Phase::Preparing {
            return Err("native startup installation was cancelled or already completed".into());
        }
        install()?;
        *phase = Phase::Installed;
        Ok(())
    }

    pub(crate) fn finish(&self, result: Result<(), String>) -> Result<(), String> {
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| "native startup state lock failed")?;
        if *phase == Phase::Cancelled {
            return Err("native startup was cancelled".into());
        }
        let installed = matches!(*phase, Phase::Installed);
        if !matches!(*phase, Phase::Preparing | Phase::Installed) {
            return Err("native startup already has a terminal result".into());
        }
        if result.is_ok() && !installed {
            return Err("native startup cannot be ready before engine installation".into());
        }
        *phase = match &result {
            Ok(()) => Phase::Ready,
            Err(error) => Phase::Failed {
                installed,
                error: error.clone(),
            },
        };
        self.completion.send_replace(Some(result));
        Ok(())
    }

    /// A GUI that has not admitted a coordinator can exit without waiting on
    /// Keychain. Cancellation prevents any late result from installing it.
    pub(crate) fn cancel_uninstalled(&self) -> Result<bool, String> {
        let mut phase = self
            .phase
            .lock()
            .map_err(|_| "native startup state lock failed")?;
        if matches!(
            *phase,
            Phase::Preparing
                | Phase::Failed {
                    installed: false,
                    ..
                }
                | Phase::Cancelled
        ) {
            *phase = Phase::Cancelled;
            self.completion
                .send_replace(Some(Err("native startup was cancelled".into())));
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn require_ready(&self) -> Result<(), String> {
        let phase = self
            .phase
            .lock()
            .map_err(|_| "native startup state lock failed")?;
        match &*phase {
            Phase::Ready => Ok(()),
            Phase::Failed { error, .. } => Err(format!("native initialization failed: {error}")),
            Phase::Cancelled => Err("native startup was cancelled".into()),
            Phase::Preparing | Phase::Installed => {
                Err("native initialization is still in progress".into())
            }
        }
    }

    pub(crate) async fn wait(&self) -> Result<(), String> {
        let mut completion = self.completion.subscribe();
        loop {
            if let Some(result) = completion.borrow_and_update().clone() {
                return result;
            }
            completion
                .changed()
                .await
                .map_err(|_| "native startup completion channel closed")?;
        }
    }
}

/// The entire blocking boundary runs on the blocking pool. No caller waits on
/// a std channel from the AppKit thread, including before Tauri's event loop.
pub(crate) async fn prepare_off_main<T: Send + 'static>(
    prepare: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(prepare)
        .await
        .map_err(|error| format!("native preparation task failed: {error}"))?
}
