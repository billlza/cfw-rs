//! Native SwiftUI adapter to the existing coordinator and shared control use cases.
//! The view owns no networking; accepted work outlives its observation window.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use cfw_engine_api::{EngineMode, EngineSnapshot, EngineState};
use serde::Serialize;
use tauri::{AppHandle, Listener, Manager};
use tokio::sync::{Notify, oneshot};

mod control;
use crate::engine_controls::EngineControl;
use control::{
    Completion, ControlGate, Controls, Displayed, Switch, control_from_wire,
    needs_approval_settings, retry_target,
};

struct Session {
    id: u64,
    app: AppHandle,
    closed: Notify,
    changed: Notify,
    gate: Mutex<ControlGate>,
}

const MAX_FRAME_BYTES: usize = 32_768;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
static OPEN_PENDING: AtomicBool = AtomicBool::new(false);

struct OpenPermit;
impl Drop for OpenPermit {
    fn drop(&mut self) {
        OPEN_PENDING.store(false, Ordering::Release);
    }
}

struct LocaleSubscription {
    app: AppHandle,
    id: tauri::EventId,
}
impl Drop for LocaleSubscription {
    fn drop(&mut self) {
        self.app.unlisten(self.id);
    }
}

unsafe extern "C" {
    fn cfm_dashboard_present_v2(
        bytes: *const u8,
        count: usize,
        closed: extern "C" fn(usize),
        control: extern "C" fn(usize, u64, u64, u64, u32, u8) -> i32,
        context: usize,
    ) -> i32;
    fn cfm_dashboard_publish_v2(bytes: *const u8, count: usize) -> i32;
    fn cfm_dashboard_invalidate_v2(session: u64) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Active,
    Inactive,
    Pending,
    Unknown,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Frame<'a> {
    version: u32,
    sequence: u64,
    session: u64,
    locale: &'a str,
    phase: &'a str,
    core: Status,
    system_proxy: Status,
    tunnel: Status,
    failure: Option<&'a str>,
    controls: Controls,
    command: Option<Completion>,
}

impl<'a> Frame<'a> {
    fn from_snapshot(snapshot: &'a EngineSnapshot, locale: &'a str, sequence: u64) -> Self {
        use Status::*;
        let (phase, core, system_proxy, tunnel, failure) = match &snapshot.state {
            EngineState::Off => ("off", Inactive, Inactive, Inactive, None),
            EngineState::LocalProxyActive { runtime }
            | EngineState::ProxyActive { runtime }
            | EngineState::TunnelActive { runtime }
            | EngineState::TunnelSystemProxyActive { runtime }
                if !runtime.ready =>
            {
                ("changing", Pending, Pending, Pending, None)
            }
            EngineState::LocalProxyActive { .. } => ("active", Active, Inactive, Inactive, None),
            EngineState::ProxyActive { .. } => ("active", Active, Active, Inactive, None),
            EngineState::TunnelActive { .. } => ("active", Active, Inactive, Active, None),
            EngineState::TunnelSystemProxyActive { .. } => ("active", Active, Active, Active, None),
            EngineState::Failed { error, .. } => {
                ("failed", Unknown, Unknown, Unknown, Some(error.as_str()))
            }
            EngineState::AwaitingApproval { .. } => ("approval", Pending, Pending, Pending, None),
            EngineState::LocalProxyStarting { .. }
            | EngineState::ProxyStarting { .. }
            | EngineState::LocalProxyStopping { .. }
            | EngineState::ProxyStopping { .. }
            | EngineState::TunnelInstalling { .. }
            | EngineState::TunnelStarting { .. }
            | EngineState::TunnelStopping { .. } => ("changing", Pending, Pending, Pending, None),
        };
        Self {
            version: 2,
            sequence,
            session: sequence,
            locale,
            phase,
            core,
            system_proxy,
            tunnel,
            failure,
            controls: Controls::unavailable(),
            command: None,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("native overview frame exceeds the delivery limit".into());
        }
        Ok(bytes)
    }
}

extern "C" fn window_closed(context: usize) {
    // SAFETY: Swift owns one raw Arc until close/replacement and clears both
    // callbacks before consuming it. Main-thread callbacks cannot interleave.
    let session = unsafe { Arc::<Session>::from_raw(context as *const Session) };
    match session.gate.lock() {
        Ok(mut gate) => gate.closed = true,
        Err(_) => crate::emit_startup_error(
            &session.app,
            "native_control_state_failed",
            "native control state lock failed".into(),
        ),
    }
    session.closed.notify_one();
}

extern "C" fn request_control(
    context: usize,
    session_id: u64,
    revision: u64,
    request_id: u64,
    control: u32,
    enabled: u8,
) -> i32 {
    // SAFETY: this callback is borrowed only while Swift retains the context;
    // it is cleared before the close callback releases that strong reference.
    let session = unsafe { &*(context as *const Session) };
    if session.id != session_id || enabled > 1 {
        return 0;
    }
    let Some(control) = control_from_wire(control) else {
        return 0;
    };
    let observed = match session.gate.lock() {
        Ok(mut gate) => match gate.reserve(revision, request_id, control, enabled == 1) {
            Ok(snapshot) => snapshot,
            Err(status) => return status,
        },
        Err(_) => return 0,
    };
    // SAFETY: the borrowed raw Arc is still live throughout this synchronous
    // callback. The new strong reference belongs to accepted work, independent
    // of window close/cancellation.
    let owned = unsafe {
        Arc::increment_strong_count(context as *const Session);
        Arc::from_raw(context as *const Session)
    };
    owned.changed.notify_one();
    tauri::async_runtime::spawn(async move {
        let result = execute_control(&owned.app, control, enabled == 1, observed).await;
        if let Err(error) = &result {
            crate::emit_startup_error(&owned.app, "native_control_failed", error.clone());
        }
        let completion = owned
            .gate
            .lock()
            .map_err(|_| "native control state lock failed")
            .and_then(|mut gate| gate.finish(request_id, result.err()));
        if let Err(error) = completion {
            crate::emit_startup_error(&owned.app, "native_control_completion_failed", error.into());
        }
        owned.changed.notify_one();
    });
    1
}

async fn execute_control(
    app: &AppHandle,
    control: EngineControl,
    enabled: bool,
    observed: EngineSnapshot,
) -> Result<(), String> {
    app.state::<crate::startup_state::NativeStartup>()
        .require_ready()?;
    if app.state::<crate::LaunchContext>().is_migration_handoff()
        || !app
            .state::<crate::lifecycle::AppLifecycle>()
            .startup_work_allowed()
    {
        return Err(
            "network changes are unavailable while the application is exiting or migrating".into(),
        );
    }
    let requested_retry = enabled && retry_target(&observed, control).is_some();
    let result = crate::engine_controls::apply_observed_control(
        &app.state::<crate::engine::ManagedEngine>(),
        &app.state::<crate::legacy::LegacyRetirementGate>(),
        &app.state::<crate::commands::ManagedProfiles>(),
        control,
        enabled,
        observed,
    )
    .await?;
    if needs_approval_settings(requested_retry, &result.snapshot) {
        // Match the existing explicit TUN retry flow. This is navigation to
        // Apple's approval UI, never approval on the user's behalf.
        let (sender, receiver) = oneshot::channel();
        app.run_on_main_thread(move || {
            let _receiver_closed = sender.send(crate::commands::open_login_items_settings());
        })
        .map_err(|error| format!("could not dispatch approval settings: {error}"))?;
        receiver
            .await
            .map_err(|_| "approval settings dispatch ended without a response".to_owned())??;
    }
    Ok(())
}

fn controls_for(app: &AppHandle, snapshot: &EngineSnapshot) -> Controls {
    let engine = app.state::<crate::engine::ManagedEngine>();
    let retirement = app.state::<crate::legacy::LegacyRetirementGate>();
    let lifecycle_ok = app
        .state::<crate::lifecycle::AppLifecycle>()
        .startup_work_allowed()
        && !app.state::<crate::LaunchContext>().is_migration_handoff();
    // The process/journal observation can perform I/O. Sample it once per
    // projected frame on this worker; execution still rechecks under its lease.
    let start_admission = if lifecycle_ok {
        crate::legacy::require_network_start_allowed(&retirement)
    } else {
        Err("network changes are unavailable while the application is exiting or migrating".into())
    };
    let can_start = |mode| {
        start_admission
            .clone()
            .and_then(|()| engine.require_capability(mode))
    };
    let project = |control, enabled: bool, mode: EngineMode| {
        let admission = if enabled && lifecycle_ok {
            Ok(()) // Stopping must remain available when start admission is denied.
        } else {
            can_start(mode)
        };
        Switch {
            enabled,
            available: admission.is_ok(),
            retry: enabled
                && retry_target(snapshot, control).is_some_and(|mode| can_start(mode).is_ok()),
            reason: admission.err(),
        }
    };
    Controls {
        core: project(
            EngineControl::Core,
            snapshot.desired_mode != EngineMode::Off,
            EngineMode::LocalProxy,
        ),
        system_proxy: project(
            EngineControl::SystemProxy,
            snapshot.desired_mode.system_proxy_enabled(),
            EngineMode::SystemProxy,
        ),
        tunnel: project(
            EngineControl::Tunnel,
            snapshot.desired_mode.tunnel_enabled(),
            EngineMode::Tunnel,
        ),
    }
}

async fn deliver(
    app: &AppHandle,
    bytes: Vec<u8>,
    session: Arc<Session>,
    displayed: Displayed,
    present: bool,
) -> Result<bool, String> {
    let (sender, receiver) = oneshot::channel();
    app.run_on_main_thread(move || {
        let status = if present {
            let pointer = Arc::into_raw(session.clone()) as usize;
            // SAFETY: main-thread, synchronous borrowed buffer; callbacks share
            // one retained session context until its exactly-once close.
            let status = unsafe {
                cfm_dashboard_present_v2(
                    bytes.as_ptr(),
                    bytes.len(),
                    window_closed,
                    request_control,
                    pointer,
                )
            };
            if status != 1 {
                // SAFETY: rejected presentations do not retain the context.
                unsafe {
                    drop(Arc::<Session>::from_raw(pointer as *const Session));
                }
            }
            status
        } else {
            // SAFETY: main-thread, synchronous borrowed buffer.
            unsafe { cfm_dashboard_publish_v2(bytes.as_ptr(), bytes.len()) }
        };
        let result = match status {
            1 => session
                .gate
                .lock()
                .map(|mut gate| {
                    gate.display(displayed);
                    true
                })
                .map_err(|_| "native control state lock failed".to_owned()),
            2 => Ok(false),
            other => Err(format!("native overview rejected frame (status {other})")),
        };
        let _receiver_closed = sender.send(result);
    })
    .map_err(|error| error.to_string())?;
    receiver
        .await
        .map_err(|_| "native overview delivery was cancelled".to_owned())?
}

pub(crate) fn open(app: AppHandle) {
    if OPEN_PENDING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let permit = OpenPermit;
    tauri::async_runtime::spawn(async move {
        let session = match next_sequence() {
            Ok(value) => value,
            Err(error) => {
                crate::emit_startup_error(&app, "native_overview_failed", error);
                return;
            }
        };
        if let Err(error) = observe(&app, session, permit).await {
            if let Err(dispatch_error) = app.run_on_main_thread(move || {
                // SAFETY: main-thread, scalar-only ABI; stale sessions cannot
                // invalidate a newly opened window's observation.
                let status = unsafe { cfm_dashboard_invalidate_v2(session) };
                if status != 1 && status != 2 {
                    eprintln!("native overview invalidation failed: {status}");
                }
            }) {
                eprintln!("native overview invalidation dispatch failed: {dispatch_error}");
            }
            crate::emit_startup_error(&app, "native_overview_failed", error);
        }
    });
}

async fn observe(app: &AppHandle, session: u64, permit: OpenPermit) -> Result<(), String> {
    app.state::<crate::startup_state::NativeStartup>()
        .require_ready()?;
    if app.state::<crate::LaunchContext>().is_migration_handoff() {
        return Err("native overview is unavailable during migration handoff".into());
    }
    let coordinator = app
        .state::<crate::engine::ManagedEngine>()
        .coordinator
        .clone();
    let mut snapshots = coordinator.subscribe();
    let session_state = Arc::new(Session {
        id: session,
        app: app.clone(),
        closed: Notify::new(),
        changed: Notify::new(),
        gate: Mutex::new(ControlGate::default()),
    });
    let locale_changed = Arc::new(Notify::new());
    let notify_locale = locale_changed.clone();
    let _locale_subscription = LocaleSubscription {
        app: app.clone(),
        id: app.listen("cfm://native-overview-locale", move |_| {
            notify_locale.notify_one()
        }),
    };
    // Do not present the coordinator's pre-observation default as a proven Off.
    // Startup errors are preserved in its published failed snapshot.
    if let Err(error) = coordinator.wait_for_reconciliation().await
        && !matches!(coordinator.snapshot().state, EngineState::Failed { .. })
    {
        return Err(format!(
            "startup observation ended without a failure snapshot: {error}"
        ));
    }
    let snapshot = snapshots.borrow_and_update().clone();
    let locale = crate::i18n::locale_identifier(app);
    let mut frame = Frame::from_snapshot(&snapshot, locale, session);
    frame.controls = controls_for(app, &snapshot);
    let displayed = Displayed {
        revision: frame.sequence,
        snapshot: snapshot.clone(),
        controls: frame.controls.clone(),
    };
    deliver(app, frame.encode()?, session_state.clone(), displayed, true).await?;
    drop(permit);
    loop {
        tokio::select! {
            biased;
            _ = session_state.closed.notified() => return Ok(()),
            changed = snapshots.changed() => {
                changed.map_err(|_| "engine observation stream closed")?;
            }
            _ = locale_changed.notified() => {}
            _ = session_state.changed.notified() => {}
        }
        let snapshot = snapshots.borrow_and_update().clone();
        let mut frame = Frame::from_snapshot(
            &snapshot,
            crate::i18n::locale_identifier(app),
            next_sequence()?,
        );
        frame.session = session;
        frame.controls = controls_for(app, &snapshot);
        frame.command = session_state
            .gate
            .lock()
            .map_err(|_| "native control state lock failed")?
            .completion();
        let displayed = Displayed {
            revision: frame.sequence,
            snapshot: snapshot.clone(),
            controls: frame.controls.clone(),
        };
        let bytes = frame.encode()?;
        // Only one main-thread delivery is outstanding. The coordinator's
        // watch channel coalesces later snapshots instead of growing a queue.
        if !deliver(app, bytes, session_state.clone(), displayed, false).await? {
            return Ok(());
        }
    }
}

fn next_sequence() -> Result<u64, String> {
    SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "native overview sequence exhausted".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::{EngineCommandContext, EngineMode, EngineOwner, RuntimeIdentity};

    #[test]
    fn swift_fixture_matches_actual_rust_serialization() {
        let snapshot = EngineSnapshot::default();
        let actual: serde_json::Value =
            serde_json::from_slice(&Frame::from_snapshot(&snapshot, "en", 1).encode().unwrap())
                .unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../native/dashboard/Tests/CFMNativeDashboardTests/Fixtures/off.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn failed_observation_is_unknown_and_preserves_the_failure() {
        let snapshot = EngineSnapshot {
            state: EngineState::Failed {
                generation: 1,
                target: EngineMode::Off,
                error: "Unavailable".into(),
            },
            ..EngineSnapshot::default()
        };
        let frame = Frame::from_snapshot(&snapshot, "en", 1);
        assert_eq!(frame.core, Status::Unknown);
        assert_eq!(frame.system_proxy, Status::Unknown);
        assert_eq!(frame.tunnel, Status::Unknown);
        assert_eq!(frame.failure, Some("Unavailable"));
    }

    #[test]
    fn active_modes_project_each_integration_separately() {
        let runtime = RuntimeIdentity {
            owner: EngineOwner::ProxyAgent,
            context: EngineCommandContext {
                installation_id: "test".into(),
                config_epoch: 1,
                generation: 1,
            },
            config_digest: "ab".repeat(32),
            ready: true,
        };
        for (state, proxy, tunnel) in [
            (
                EngineState::LocalProxyActive {
                    runtime: runtime.clone(),
                },
                Status::Inactive,
                Status::Inactive,
            ),
            (
                EngineState::ProxyActive {
                    runtime: runtime.clone(),
                },
                Status::Active,
                Status::Inactive,
            ),
            (
                EngineState::TunnelActive {
                    runtime: runtime.clone(),
                },
                Status::Inactive,
                Status::Active,
            ),
            (
                EngineState::TunnelSystemProxyActive { runtime },
                Status::Active,
                Status::Active,
            ),
        ] {
            let snapshot = EngineSnapshot {
                state,
                ..EngineSnapshot::default()
            };
            let frame = Frame::from_snapshot(&snapshot, "en", 1);
            assert_eq!(frame.core, Status::Active);
            assert_eq!((frame.system_proxy, frame.tunnel), (proxy, tunnel));
        }
    }

    #[test]
    fn a_nonready_runtime_never_projects_a_connected_state() {
        let runtime = RuntimeIdentity {
            owner: EngineOwner::PacketTunnelSystemExtension,
            context: EngineCommandContext {
                installation_id: "test".into(),
                config_epoch: 1,
                generation: 1,
            },
            config_digest: "ab".repeat(32),
            ready: false,
        };
        for state in [
            EngineState::LocalProxyActive {
                runtime: runtime.clone(),
            },
            EngineState::ProxyActive {
                runtime: runtime.clone(),
            },
            EngineState::TunnelActive {
                runtime: runtime.clone(),
            },
            EngineState::TunnelSystemProxyActive { runtime },
        ] {
            let snapshot = EngineSnapshot {
                state,
                desired_mode: EngineMode::TunnelSystemProxy,
                ..EngineSnapshot::default()
            };
            let frame = Frame::from_snapshot(&snapshot, "en", 1);
            assert_eq!(frame.phase, "changing");
            assert_eq!(
                (frame.core, frame.system_proxy, frame.tunnel),
                (Status::Pending, Status::Pending, Status::Pending)
            );
            assert_eq!(
                retry_target(&snapshot, EngineControl::Core),
                Some(EngineMode::TunnelSystemProxy)
            );
        }
    }

    #[test]
    fn oversized_error_is_rejected_without_a_truncated_success() {
        let snapshot = EngineSnapshot {
            state: EngineState::Failed {
                generation: 1,
                target: EngineMode::Off,
                error: "x".repeat(MAX_FRAME_BYTES),
            },
            ..EngineSnapshot::default()
        };
        assert!(Frame::from_snapshot(&snapshot, "en", 1).encode().is_err());
    }
}
