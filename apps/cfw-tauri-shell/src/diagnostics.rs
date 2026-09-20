//! Local diagnostics are supervised separately from packet forwarding.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use cfw_core::{DiagnosticEntry, DiagnosticJournal, DiagnosticTopic};
use serde::Deserialize;
use tauri::{AppHandle, Manager, State, WebviewWindow};

const QUEUE_CAPACITY: usize = 128;

enum WriteCommand {
    Entry(DiagnosticTopic, DiagnosticEntry),
    Flush(mpsc::SyncSender<()>),
}

pub(crate) struct Diagnostics {
    sender: Option<mpsc::SyncSender<WriteCommand>>,
    failure: Arc<Mutex<Option<String>>>,
    dropped: Arc<AtomicU64>,
}

impl Diagnostics {
    pub(crate) fn start() -> Self {
        let failure = Arc::new(Mutex::new(None));
        let dropped = Arc::new(AtomicU64::new(0));
        let result = (|| {
            let store = crate::settings_store()?;
            let journal = DiagnosticJournal::new(&store.paths().logs_dir);
            let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
            let worker_failure = failure.clone();
            let worker_dropped = dropped.clone();
            std::thread::Builder::new()
                .name("cfm-diagnostics".into())
                .spawn(move || {
                    while let Ok(command) = receiver.recv() {
                        let mut startup = Vec::new();
                        let mut network = Vec::new();
                        let mut network_warnings = Vec::new();
                        let mut acknowledgements = Vec::new();
                        let mut add = |command| match command {
                            WriteCommand::Entry(DiagnosticTopic::Startup, entry) => {
                                startup.push(entry)
                            }
                            WriteCommand::Entry(DiagnosticTopic::Network, entry) => {
                                network.push(entry)
                            }
                            WriteCommand::Entry(DiagnosticTopic::NetworkWarnings, entry) => {
                                network_warnings.push(entry)
                            }
                            WriteCommand::Flush(sender) => acknowledgements.push(sender),
                        };
                        add(command);
                        for command in receiver.try_iter().take(QUEUE_CAPACITY - 1) {
                            add(command);
                        }
                        let lost = worker_dropped.swap(0, Ordering::AcqRel);
                        if lost != 0 {
                            match DiagnosticEntry::new(
                                "diagnostic_queue_overflow",
                                &format!("{lost} diagnostic entries were not queued"),
                            ) {
                                Ok(entry) => startup.push(entry),
                                Err(error) => record_failure(&worker_failure, &error.to_string()),
                            }
                        }
                        for (topic, entries) in [
                            (DiagnosticTopic::Startup, startup),
                            (DiagnosticTopic::Network, network),
                            (DiagnosticTopic::NetworkWarnings, network_warnings),
                        ] {
                            if let Err(error) = journal.append(topic, &entries) {
                                record_failure(&worker_failure, &error.to_string());
                            }
                        }
                        for sender in acknowledgements {
                            // The receiver can have reached its explicit deadline.
                            // No delayed callback changes application or network state.
                            if sender.send(()).is_err() {
                                eprintln!("diagnostic flush acknowledgement expired");
                            }
                        }
                        // Bound disk traffic during a failure storm. Producers never
                        // wait for filesystem locks, flushes, or the journal worker.
                        std::thread::sleep(Duration::from_millis(200));
                    }
                })
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(sender)
        })();
        let sender = match result {
            Ok(sender) => Some(sender),
            Err(error) => {
                record_failure(&failure, &error);
                None
            }
        };
        Self {
            sender,
            failure,
            dropped,
        }
    }

    pub(crate) fn record(&self, topic: DiagnosticTopic, code: &str, message: &str) {
        let Some(sender) = &self.sender else {
            return;
        };
        let entry = match DiagnosticEntry::new(code, message) {
            Ok(entry) => entry,
            Err(error) => {
                record_failure(&self.failure, &error.to_string());
                return;
            }
        };
        match sender.try_send(WriteCommand::Entry(topic, entry)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                record_failure(&self.failure, "diagnostic worker disconnected")
            }
        }
    }

    pub(crate) fn startup_step<T, E: std::fmt::Display>(
        &self,
        stage: &'static str,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.record(DiagnosticTopic::Startup, &format!("{stage}_started"), "");
        let started = std::time::Instant::now();
        let result = operation();
        let (outcome, detail) = match &result {
            Ok(_) => ("completed", String::new()),
            Err(error) => ("failed", format!("; {error}")),
        };
        self.record(
            DiagnosticTopic::Startup,
            &format!("{stage}_{outcome}"),
            &format!("elapsed_ms={}{}", started.elapsed().as_millis(), detail),
        );
        result
    }

    pub(crate) fn flush(&self) -> Result<(), String> {
        let sender = self
            .sender
            .as_ref()
            .ok_or("diagnostic worker is unavailable")?;
        let (reply, receive) = mpsc::sync_channel(1);
        sender
            .try_send(WriteCommand::Flush(reply))
            .map_err(|_| "diagnostic flush could not be queued")?;
        receive
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "diagnostic flush timed out")?;
        let failure = self
            .failure
            .lock()
            .map_err(|_| "diagnostic status lock failed")?;
        match failure.as_deref() {
            Some(error) => Err(format!("diagnostic storage failed: {error}")),
            None => Ok(()),
        }
    }
}

fn record_failure(status: &Mutex<Option<String>>, error: &str) {
    let error = cfw_core::redact_diagnostic_text(error);
    match status.lock() {
        Ok(mut previous) if previous.as_deref() != Some(error.as_str()) => {
            eprintln!("local diagnostics unavailable: {error}");
            *previous = Some(error);
        }
        Ok(_) => {}
        Err(_) => eprintln!("local diagnostic status lock failed"),
    }
}

pub(crate) fn record(app: &AppHandle, topic: DiagnosticTopic, code: &str, message: &str) {
    app.state::<Diagnostics>().record(topic, code, message);
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DashboardStartupCode {
    ScriptLoaded,
    Ready,
    ScriptFailed,
    BootstrapFailed,
    StartupTimeout,
    UnhandledRejection,
}

impl DashboardStartupCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScriptLoaded => "renderer_script_loaded",
            Self::Ready => "renderer_ready",
            Self::ScriptFailed => "renderer_script_failed",
            Self::BootstrapFailed => "renderer_bootstrap_failed",
            Self::StartupTimeout => "renderer_startup_timeout",
            Self::UnhandledRejection => "renderer_unhandled_rejection",
        }
    }
}

#[tauri::command]
pub(crate) async fn report_dashboard_startup(
    window: WebviewWindow,
    diagnostics: State<'_, Diagnostics>,
    code: DashboardStartupCode,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err("startup reports are restricted to the main window".into());
    }
    diagnostics.record(DiagnosticTopic::Startup, code.as_str(), "");
    let app = window.app_handle().clone();
    tauri::async_runtime::spawn_blocking(move || app.state::<Diagnostics>().flush())
        .await
        .map_err(|error| format!("startup diagnostic task failed: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_saturation_is_nonblocking_and_counted() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let diagnostics = Diagnostics {
            sender: Some(sender),
            failure: Arc::new(Mutex::new(None)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.record(DiagnosticTopic::Network, "request_error", "first");
        diagnostics.record(DiagnosticTopic::Network, "request_error", "second");
        assert_eq!(diagnostics.dropped.load(Ordering::Relaxed), 1);
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn a_disconnected_worker_is_an_explicit_failure() {
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let diagnostics = Diagnostics {
            sender: Some(sender),
            failure: Arc::new(Mutex::new(None)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        diagnostics.record(DiagnosticTopic::Startup, "renderer_ready", "");
        assert_eq!(
            diagnostics.failure.lock().unwrap().as_deref(),
            Some("diagnostic worker disconnected")
        );
        assert!(diagnostics.flush().is_err());
    }

    #[test]
    fn startup_report_accepts_only_closed_non_sensitive_codes() {
        assert!(serde_json::from_str::<DashboardStartupCode>("\"ready\"").is_ok());
        assert!(serde_json::from_str::<DashboardStartupCode>("\"secret=arbitrary-text\"").is_err());
        assert!(serde_json::from_str::<DashboardStartupCode>("{\"ready\":true}").is_err());
    }

    #[test]
    fn native_startup_steps_preserve_errors_and_redact_their_diagnostic_copy() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let diagnostics = Diagnostics {
            sender: Some(sender),
            failure: Arc::new(Mutex::new(None)),
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let error = "Keychain unavailable; token=private-value";
        assert_eq!(
            diagnostics.startup_step("engine", || Err::<(), _>(error)),
            Err(error)
        );
        assert_eq!(
            diagnostics.startup_step("menu", || Ok::<_, &str>(42)),
            Ok(42)
        );
        let entries: Vec<_> = receiver
            .try_iter()
            .map(|command| match command {
                WriteCommand::Entry(DiagnosticTopic::Startup, entry) => entry,
                _ => panic!("expected a native startup entry"),
            })
            .collect();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.code.as_str())
                .collect::<Vec<_>>(),
            [
                "engine_started",
                "engine_failed",
                "menu_started",
                "menu_completed"
            ]
        );
        assert!(entries[1].message.contains("Keychain unavailable"));
        assert!(!entries[1].message.contains("private-value"));
    }
}
