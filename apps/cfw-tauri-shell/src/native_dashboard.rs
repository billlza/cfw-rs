//! Development SwiftUI observation surface, attached to the existing coordinator.
//! No service registration, owner creation, controller access or mode command.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use cfw_engine_api::{EngineSnapshot, EngineState};
use serde::Serialize;
use tauri::{AppHandle, Listener, Manager};
use tokio::sync::{Notify, oneshot};

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
    fn cfm_dashboard_present_v1(
        bytes: *const u8,
        count: usize,
        closed: extern "C" fn(usize),
        context: usize,
    ) -> i32;
    fn cfm_dashboard_publish_v1(bytes: *const u8, count: usize) -> i32;
    fn cfm_dashboard_invalidate_v1(session: u64) -> i32;
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
}

impl<'a> Frame<'a> {
    fn from_snapshot(snapshot: &'a EngineSnapshot, locale: &'a str, sequence: u64) -> Self {
        use Status::*;
        let (phase, core, system_proxy, tunnel, failure) = match &snapshot.state {
            EngineState::Off => ("off", Inactive, Inactive, Inactive, None),
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
            version: 1,
            sequence,
            session: sequence,
            locale,
            phase,
            core,
            system_proxy,
            tunnel,
            failure,
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
    // SAFETY: each successful present transfers one Arc strong reference;
    // Swift consumes this callback once on close or replacement and clears it.
    let cancellation = unsafe { Arc::<Notify>::from_raw(context as *const Notify) };
    cancellation.notify_one();
}

async fn deliver(
    app: &AppHandle,
    bytes: Vec<u8>,
    present: Option<Arc<Notify>>,
) -> Result<bool, String> {
    let (sender, receiver) = oneshot::channel();
    app.run_on_main_thread(move || {
        let status = if let Some(cancellation) = present {
            let pointer = Arc::into_raw(cancellation) as usize;
            // SAFETY: main-thread call; bytes are borrowed synchronously; the
            // callback context stays alive until Swift consumes it exactly once.
            let status = unsafe {
                cfm_dashboard_present_v1(bytes.as_ptr(), bytes.len(), window_closed, pointer)
            };
            if status != 1 {
                // SAFETY: a rejected present does not retain callback/context.
                unsafe {
                    drop(Arc::<Notify>::from_raw(pointer as *const Notify));
                }
            }
            status
        } else {
            // SAFETY: dispatch guarantees the main thread; Swift copies bytes
            // synchronously, and cannot retain the borrowed Rust allocation.
            unsafe { cfm_dashboard_publish_v1(bytes.as_ptr(), bytes.len()) }
        };
        let _receiver_closed = sender.send(status);
    })
    .map_err(|error| error.to_string())?;
    match receiver
        .await
        .map_err(|_| "native overview delivery was cancelled")?
    {
        1 => Ok(true),
        2 => Ok(false),
        status => Err(format!("native overview rejected frame (status {status})")),
    }
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
                let status = unsafe { cfm_dashboard_invalidate_v1(session) };
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
    let cancellation = Arc::new(Notify::new());
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
    let bytes = Frame::from_snapshot(&snapshot, locale, session).encode()?;
    deliver(app, bytes, Some(cancellation.clone())).await?;
    drop(permit);
    loop {
        tokio::select! {
            biased;
            _ = cancellation.notified() => return Ok(()),
            changed = snapshots.changed() => {
                changed.map_err(|_| "engine observation stream closed")?;
            }
            _ = locale_changed.notified() => {}
        }
        let snapshot = snapshots.borrow_and_update().clone();
        let mut frame = Frame::from_snapshot(
            &snapshot,
            crate::i18n::locale_identifier(app),
            next_sequence()?,
        );
        frame.session = session;
        let bytes = frame.encode()?;
        // Only one main-thread delivery is outstanding. The coordinator's
        // watch channel coalesces later snapshots instead of growing a queue.
        if !deliver(app, bytes, None).await? {
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
