//! Ownership, supervision and the read loops of the controller's connection
//! and log streams.

use super::*;

/// Cancellable ownership for the two controller event streams. A reservation
/// closes the race between task creation and task completion, so stop/restart
/// cannot leave a stale "started" flag behind.
#[derive(Default)]
pub(crate) struct LiveStreams {
    connections: Mutex<StreamSlot>,
    logs: Mutex<StreamSlot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StreamKind {
    Connections,
    Logs,
}

impl StreamKind {
    fn name(self) -> &'static str {
        match self {
            Self::Connections => CONNECTIONS_STREAM,
            Self::Logs => REQUEST_LOG_STREAM,
        }
    }
}

/// Native ownership returned by `start_*_stream` and copied onto every event.
/// The runtime identity is the coordinator's existing attestation; `stream_id`
/// distinguishes stop/restart within that same runtime generation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) struct StreamBinding {
    pub(super) stream: String,
    pub(super) stream_id: u64,
    pub(super) runtime: RuntimeIdentity,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct StreamEvent<T> {
    pub(super) provenance: StreamBinding,
    pub(super) payload: T,
}

#[derive(Default)]
pub(super) struct StreamSlot {
    next_id: u64,
    task: Option<StreamTask>,
}

pub(super) enum StreamTask {
    Starting {
        binding: StreamBinding,
    },
    Running {
        binding: StreamBinding,
        handle: tauri::async_runtime::JoinHandle<()>,
    },
}

pub(super) struct StreamReservation {
    pub(super) binding: StreamBinding,
    pub(super) start_new: bool,
}

impl LiveStreams {
    pub(super) fn slot(&self, kind: StreamKind) -> &Mutex<StreamSlot> {
        match kind {
            StreamKind::Connections => &self.connections,
            StreamKind::Logs => &self.logs,
        }
    }

    pub(crate) fn stop_all(&self) {
        stop_stream_silently(&self.connections);
        stop_stream_silently(&self.logs);
    }
}

impl Drop for LiveStreams {
    fn drop(&mut self) {
        self.stop_all();
    }
}

pub(super) fn lock_stream_slot(
    slot: &Mutex<StreamSlot>,
) -> Result<std::sync::MutexGuard<'_, StreamSlot>, String> {
    slot.lock()
        .map_err(|error| ControllerCommandError::ClientUnavailable(error.to_string()).to_ipc())
}

pub(super) fn task_binding(task: &StreamTask) -> &StreamBinding {
    match task {
        StreamTask::Starting { binding } | StreamTask::Running { binding, .. } => binding,
    }
}

/// Atomically retains an existing supervisor for the same runtime identity or
/// aborts/replaces it for a new identity. Ownership is changed under one slot
/// lock, so Active A -> Active B cannot leave A registered as B's stream.
pub(super) fn reserve_stream(
    slot: &Mutex<StreamSlot>,
    kind: StreamKind,
    runtime: RuntimeIdentity,
) -> Result<StreamReservation, String> {
    let mut slot = lock_stream_slot(slot)?;
    if let Some(task) = slot.task.as_ref()
        && task_binding(task).runtime == runtime
    {
        return Ok(StreamReservation {
            binding: task_binding(task).clone(),
            start_new: false,
        });
    }
    let next_id = slot.next_id.checked_add(1).ok_or_else(|| {
        ControllerCommandError::ClientUnavailable(
            "controller stream identifier space is exhausted".into(),
        )
        .to_ipc()
    })?;
    if let Some(StreamTask::Running { handle, .. }) = slot.task.take() {
        handle.abort();
    }
    slot.next_id = next_id;
    let binding = StreamBinding {
        stream: kind.name().to_owned(),
        stream_id: slot.next_id,
        runtime,
    };
    slot.task = Some(StreamTask::Starting {
        binding: binding.clone(),
    });
    Ok(StreamReservation {
        binding,
        start_new: true,
    })
}

pub(super) fn attach_stream(
    slot: &Mutex<StreamSlot>,
    stream_id: u64,
    handle: tauri::async_runtime::JoinHandle<()>,
) -> Result<(), String> {
    let mut slot = match lock_stream_slot(slot) {
        Ok(slot) => slot,
        Err(error) => {
            handle.abort();
            return Err(error);
        }
    };
    let binding = match slot.task.as_ref() {
        Some(StreamTask::Starting { binding }) if binding.stream_id == stream_id => {
            Some(binding.clone())
        }
        _ => None,
    };
    if let Some(binding) = binding {
        slot.task = Some(StreamTask::Running { binding, handle });
    } else {
        // Stop or task completion won the race while spawn was being attached.
        handle.abort();
    }
    Ok(())
}

pub(super) fn release_stream(slot: &Mutex<StreamSlot>, stream_id: u64) {
    let mut slot = match slot.lock() {
        Ok(slot) => slot,
        Err(error) => {
            eprintln!("controller stream ownership release failed: {error}");
            return;
        }
    };
    let owned = match slot.task.as_ref() {
        Some(task) => task_binding(task).stream_id == stream_id,
        None => false,
    };
    if owned {
        slot.task = None;
    }
}

pub(super) fn stop_stream(
    slot: &Mutex<StreamSlot>,
    expected: &StreamBinding,
) -> Result<(), String> {
    let mut slot = lock_stream_slot(slot)?;
    if !slot
        .task
        .as_ref()
        .is_some_and(|task| task_binding(task) == expected)
    {
        return Ok(());
    }
    let task = slot.task.take();
    if let Some(StreamTask::Running { handle, .. }) = task {
        handle.abort();
    }
    Ok(())
}

pub(super) fn stop_stream_silently(slot: &Mutex<StreamSlot>) {
    let mut slot = match slot.lock() {
        Ok(slot) => slot,
        Err(error) => {
            eprintln!("controller stream shutdown failed: {error}");
            return;
        }
    };
    if let Some(StreamTask::Running { handle, .. }) = slot.task.take() {
        handle.abort();
    }
}

pub(super) fn start_stream(
    app: AppHandle,
    streams: &LiveStreams,
    kind: StreamKind,
) -> Result<StreamBinding, String> {
    let engine = app.state::<ManagedEngine>();
    let snapshot = engine.coordinator.snapshot();
    let runtime = running_runtime_identity(engine.coordinator.runtime_platform(), &snapshot)
        .map_err(|error| error.to_ipc())?
        .clone();
    let reservation = reserve_stream(streams.slot(kind), kind, runtime)?;
    if !reservation.start_new {
        return Ok(reservation.binding);
    }
    let binding = reservation.binding;
    let stream_id = binding.stream_id;
    let task_app = app.clone();
    let task_binding = binding.clone();
    let handle = tauri::async_runtime::spawn(async move {
        supervise_stream(&task_app, kind, &task_binding).await;
        release_stream(
            task_app.state::<LiveStreams>().slot(kind),
            task_binding.stream_id,
        );
    });
    attach_stream(streams.slot(kind), stream_id, handle)?;
    Ok(binding)
}

pub(super) async fn supervise_stream(app: &AppHandle, kind: StreamKind, binding: &StreamBinding) {
    let mut last_error: Option<String> = None;
    loop {
        if !stream_binding_is_current(app, binding) {
            return;
        }
        let result = match kind {
            StreamKind::Connections => run_connections_stream(app, binding).await,
            StreamKind::Logs => run_log_stream(app, binding).await,
        };
        if !stream_binding_is_current(app, binding) {
            return;
        }
        match result {
            // A clean close while the engine remains active is reconnectable.
            Ok(()) => last_error = None,
            Err(error) => emit_unique_stream_error(app, binding, &mut last_error, error),
        }
        tokio::time::sleep(STREAM_RETRY_INTERVAL).await;
    }
}

pub(super) fn stream_binding_is_current(app: &AppHandle, binding: &StreamBinding) -> bool {
    let engine = app.state::<ManagedEngine>();
    let snapshot = engine.coordinator.snapshot();
    running_runtime_identity(engine.coordinator.runtime_platform(), &snapshot)
        .is_ok_and(|runtime| runtime == &binding.runtime)
}

pub(super) fn client_for_stream(
    app: &AppHandle,
    binding: &StreamBinding,
) -> Result<ControllerClient, String> {
    if !stream_binding_is_current(app, binding) {
        return Err(ControllerCommandError::EngineNotRunning.to_ipc());
    }
    client_from_app(app)
}

pub(super) async fn run_connections_stream(
    app: &AppHandle,
    binding: &StreamBinding,
) -> Result<(), String> {
    let client = client_for_stream(app, binding)?;
    let url = client.connections_stream_url().map_err(ipc_error)?;
    let (socket, _response) =
        connect_async_with_config(url, Some(controller_websocket_config()), false)
            .await
            .map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    let mut engine_check = tokio::time::interval(Duration::from_millis(250));
    engine_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            message = read.next() => {
                let Some(message) = message else {
                    return Ok(());
                };
                let message = message.map_err(transport_error)?;
                if let Some(snapshot) = decode_connections_message(&message)? {
                    if !stream_binding_is_current(app, binding) {
                        return Ok(());
                    }
                    app.emit(
                        CONNECTIONS_SNAPSHOT_EVENT,
                        StreamEvent {
                            provenance: binding.clone(),
                            payload: snapshot,
                        },
                    )
                        .map_err(|error| format!("failed to publish connections snapshot: {error}"))?;
                }
            }
            _ = engine_check.tick() => {
                if !stream_binding_is_current(app, binding) {
                    return Ok(());
                }
            }
        }
    }
}

pub(super) async fn run_log_stream(app: &AppHandle, binding: &StreamBinding) -> Result<(), String> {
    let client = client_for_stream(app, binding)?;
    let url = client
        .logs_stream_url(LOG_STREAM_LEVEL)
        .map_err(ipc_error)?;
    let (socket, _response) =
        connect_async_with_config(url, Some(controller_websocket_config()), false)
            .await
            .map_err(transport_error)?;
    let (_write, mut read) = socket.split();
    let mut engine_check = tokio::time::interval(Duration::from_millis(250));
    engine_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            message = read.next() => {
                let Some(message) = message else {
                    return Ok(());
                };
                let message = message.map_err(transport_error)?;
                if let Some(entry) = decode_log_message(&message)? {
                    if !stream_binding_is_current(app, binding) {
                        return Ok(());
                    }
                    let line = log_line_from_structured(entry);
                    if matches!(line.level.as_str(), "warning" | "error") {
                        crate::diagnostics::record(app,
                            if line.level == "error" { cfw_core::DiagnosticTopic::Network } else { cfw_core::DiagnosticTopic::NetworkWarnings },
                            if line.level == "error" { "request_error" } else { "request_warning" }, &line.message);
                    }
                    app.emit(
                        LOG_LINES_EVENT,
                        StreamEvent {
                            provenance: binding.clone(),
                            payload: vec![line],
                        },
                    )
                        .map_err(|error| format!("failed to publish log line: {error}"))?;
                }
            }
            _ = engine_check.tick() => {
                if !stream_binding_is_current(app, binding) {
                    return Ok(());
                }
            }
        }
    }
}
