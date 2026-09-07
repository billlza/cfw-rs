use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use cfw_engine_api::EngineEvent;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};

use crate::legacy::{
    ConsumedHandoffTicket, MigrationHandoffLease, ProcessIdentity, RendererReadyChallenge,
};
use crate::lifecycle::{AppLifecycle, MigrationHandoffStatus};

const MAIN_WINDOW_LABEL: &str = "main";
const PARENT_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const PARENT_EXIT_MAX_CHECKS: usize = 1_001;

pub(crate) struct LaunchContext {
    migration_handoff: bool,
    handoff_ticket: Option<ConsumedHandoffTicket>,
    _handoff_lease: Option<MigrationHandoffLease>,
    renderer_ready: RendererReadyGate,
}

impl LaunchContext {
    pub(crate) fn dashboard() -> Self {
        Self {
            migration_handoff: false,
            handoff_ticket: None,
            _handoff_lease: None,
            renderer_ready: RendererReadyGate::default(),
        }
    }

    pub(crate) fn handoff(ticket: ConsumedHandoffTicket, lease: MigrationHandoffLease) -> Self {
        Self {
            migration_handoff: true,
            handoff_ticket: Some(ticket),
            _handoff_lease: Some(lease),
            renderer_ready: RendererReadyGate::default(),
        }
    }

    pub(crate) const fn is_migration_handoff(&self) -> bool {
        self.migration_handoff
    }

    fn require_handoff_ticket(&self) -> Result<&ConsumedHandoffTicket, String> {
        if !self.migration_handoff {
            return Err("dashboard launch cannot acknowledge migration renderer readiness".into());
        }
        self.handoff_ticket
            .as_ref()
            .ok_or_else(|| "migration handoff has no admitted startup ticket".to_owned())
    }

    pub(crate) fn mark_renderer_native_ready(&self) -> Result<(), String> {
        self.require_handoff_ticket()?.require_child_identity()?;
        self.renderer_ready.mark_native_ready()
    }

    fn migration_handoff_renderer_ready(
        &self,
    ) -> Result<Option<MigrationHandoffRendererReady>, String> {
        if !self.migration_handoff {
            return Ok(None);
        }
        let ticket = self.require_handoff_ticket()?;
        ticket.require_child_identity()?;
        self.renderer_ready
            .boot_state(ticket.renderer_challenges())
            .map(Some)
    }

    fn acknowledge_renderer_ready(
        &self,
        window_label: &str,
        renderer: RendererReadyChallenge,
    ) -> Result<(), String> {
        let ticket = self.require_handoff_ticket()?;
        self.renderer_ready.acknowledge_with(
            window_label,
            renderer,
            || ticket.require_child_identity().map(|_| ()),
            |proof| ticket.publish_ready(proof),
        )
    }

    pub(crate) fn require_renderer_ready_published(&self) -> Result<(), String> {
        self.require_handoff_ticket()?;
        self.renderer_ready.require_post_parent_window_ready()
    }

    fn handoff_parent_absent(&self) -> Result<bool, String> {
        self.require_handoff_ticket()?.parent_absent()
    }

    fn mark_post_parent_window_ready(&self) -> Result<(), String> {
        self.require_handoff_ticket()?.require_child_identity()?;
        self.renderer_ready.mark_post_parent_window_ready()
    }

    fn post_parent_window_ready(&self) -> Result<bool, String> {
        self.require_handoff_ticket()?;
        self.renderer_ready.post_parent_window_ready()
    }

    pub(crate) fn require_handoff_parent_absent(&self) -> Result<(), String> {
        self.require_handoff_ticket()?.require_parent_absent()
    }

    pub(crate) fn handoff_parent_identity(&self) -> Option<&ProcessIdentity> {
        self.handoff_ticket
            .as_ref()
            .map(ConsumedHandoffTicket::parent_identity)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum MigrationHandoffRendererReady {
    Challenge { generation: u32, challenge: String },
    Published,
}

impl From<RendererReadyChallenge> for MigrationHandoffRendererReady {
    fn from(value: RendererReadyChallenge) -> Self {
        Self::Challenge {
            generation: value.generation,
            challenge: value.challenge,
        }
    }
}

#[derive(Default)]
struct RendererReadyGate {
    inner: Mutex<RendererReadyGateInner>,
}

#[derive(Default)]
struct RendererReadyGateInner {
    phase: RendererReadyPhase,
    next_challenge: usize,
}

#[derive(Default)]
enum RendererReadyPhase {
    #[default]
    NativePending,
    NativeReady,
    Challenged(RendererReadyChallenge),
    Publishing,
    Published,
    PostParentWindowReady,
    Failed,
}

impl RendererReadyGate {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RendererReadyGateInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "migration renderer-ready gate lock failed".to_owned())
    }

    fn mark_native_ready(&self) -> Result<(), String> {
        let mut inner = self.lock()?;
        if !matches!(inner.phase, RendererReadyPhase::NativePending) {
            return Err("migration renderer native readiness was already resolved".into());
        }
        inner.phase = RendererReadyPhase::NativeReady;
        Ok(())
    }

    fn boot_state(
        &self,
        challenges: &[RendererReadyChallenge],
    ) -> Result<MigrationHandoffRendererReady, String> {
        let mut inner = self.lock()?;
        match inner.phase {
            RendererReadyPhase::NativePending => {
                Err("migration renderer cannot bootstrap before native setup completes".into())
            }
            RendererReadyPhase::NativeReady | RendererReadyPhase::Challenged(_) => {
                let Some(challenge) = challenges.get(inner.next_challenge).cloned() else {
                    inner.phase = RendererReadyPhase::Failed;
                    return Err(
                        "migration renderer exhausted its ticket-bound bootstrap generations"
                            .into(),
                    );
                };
                let Some(next_challenge) = inner.next_challenge.checked_add(1) else {
                    inner.phase = RendererReadyPhase::Failed;
                    return Err("migration renderer generation counter overflowed".into());
                };
                inner.next_challenge = next_challenge;
                inner.phase = RendererReadyPhase::Challenged(challenge.clone());
                Ok(challenge.into())
            }
            RendererReadyPhase::Publishing => {
                Err("migration renderer readiness publication is in progress".into())
            }
            RendererReadyPhase::Published | RendererReadyPhase::PostParentWindowReady => {
                Ok(MigrationHandoffRendererReady::Published)
            }
            RendererReadyPhase::Failed => {
                Err("migration renderer readiness previously failed and remains closed".into())
            }
        }
    }

    fn acknowledge_with<Verify, Publish>(
        &self,
        window_label: &str,
        renderer: RendererReadyChallenge,
        verify_child: Verify,
        publish: Publish,
    ) -> Result<(), String>
    where
        Verify: FnOnce() -> Result<(), String>,
        Publish: FnOnce(&RendererReadyChallenge) -> Result<(), String>,
    {
        if window_label != MAIN_WINDOW_LABEL {
            return Err(
                "migration renderer readiness is accepted only from the main window".into(),
            );
        }
        let mut inner = self.lock()?;
        match &inner.phase {
            RendererReadyPhase::Challenged(expected) if expected == &renderer => {}
            RendererReadyPhase::Challenged(_) => {
                return Err("migration renderer readiness challenge is stale or invalid".into());
            }
            RendererReadyPhase::NativePending | RendererReadyPhase::NativeReady => {
                return Err("migration renderer has no active readiness challenge".into());
            }
            RendererReadyPhase::Publishing => {
                return Err(
                    "migration renderer readiness publication is already in progress".into(),
                );
            }
            RendererReadyPhase::Published | RendererReadyPhase::PostParentWindowReady => {
                return Err(
                    "migration renderer readiness acknowledgement was already consumed".into(),
                );
            }
            RendererReadyPhase::Failed => {
                return Err(
                    "migration renderer readiness previously failed and remains closed".into(),
                );
            }
        }

        inner.phase = RendererReadyPhase::Publishing;
        if let Err(error) = verify_child() {
            inner.phase = RendererReadyPhase::Failed;
            return Err(format!(
                "migration renderer child identity verification failed: {error}"
            ));
        }
        if let Err(error) = publish(&renderer) {
            inner.phase = RendererReadyPhase::Failed;
            return Err(format!(
                "migration renderer readiness publication failed: {error}"
            ));
        }
        inner.phase = RendererReadyPhase::Published;
        Ok(())
    }

    fn mark_post_parent_window_ready(&self) -> Result<(), String> {
        let mut inner = self.lock()?;
        if matches!(inner.phase, RendererReadyPhase::Published) {
            inner.phase = RendererReadyPhase::PostParentWindowReady;
            Ok(())
        } else {
            Err(
                "migration window cannot complete post-parent activation in its current state"
                    .into(),
            )
        }
    }

    fn require_post_parent_window_ready(&self) -> Result<(), String> {
        if self.post_parent_window_ready()? {
            Ok(())
        } else {
            Err("migration window is not ready after the dashboard parent exited".into())
        }
    }

    fn post_parent_window_ready(&self) -> Result<bool, String> {
        Ok(matches!(
            self.lock()?.phase,
            RendererReadyPhase::PostParentWindowReady
        ))
    }
}

async fn wait_for_parent_absence_with<Check, Sleep, SleepFuture>(
    mut check: Check,
    mut sleep: Sleep,
    max_checks: usize,
) -> Result<(), String>
where
    Check: FnMut() -> Result<bool, String>,
    Sleep: FnMut() -> SleepFuture,
    SleepFuture: Future<Output = ()>,
{
    if max_checks == 0 {
        return Err("migration parent-exit wait has no observation budget".into());
    }
    for index in 0..max_checks {
        if check()? {
            return Ok(());
        }
        if index + 1 < max_checks {
            sleep().await;
        }
    }
    Err("migration dashboard parent did not exit within 20 seconds".into())
}

async fn reactivate_window_after_parent_exit(app: AppHandle) -> Result<(), String> {
    wait_for_parent_absence_with(
        || app.state::<LaunchContext>().handoff_parent_absent(),
        || tokio::time::sleep(PARENT_EXIT_POLL_INTERVAL),
        PARENT_EXIT_MAX_CHECKS,
    )
    .await?;
    activate_main_window(&app)?;
    app.state::<LaunchContext>().mark_post_parent_window_ready()
}

fn activate_main_window(app: &AppHandle) -> Result<(), String> {
    crate::shell::prepare_migration_handoff_window(app)
}

pub(crate) fn reopen_main_window(app: &AppHandle) -> Result<(), String> {
    let launch = app.state::<LaunchContext>();
    if launch.is_migration_handoff() && !launch.post_parent_window_ready()? {
        return Ok(());
    }
    activate_main_window(app)
}

fn schedule_post_parent_window_activation(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        if let Err(error) = reactivate_window_after_parent_exit(app.clone()).await {
            eprintln!("migration post-parent window activation failed: {error}");
            if let Err(emit_error) = app.emit(
                "cfw://engine-event",
                EngineEvent::boundary_failure(
                    "migration_post_parent_window_failed",
                    "The migration window could not be restored after the dashboard exited. No cutover was authorized. Relaunch Clash for Mac and retry.",
                ),
            ) {
                eprintln!("failed to publish migration window activation error: {emit_error}");
            }
            if let Err(shutdown_error) = crate::lifecycle::request_shutdown(
                app.clone(),
                crate::launch::STARTUP_ADMISSION_EXIT_CODE,
            ) {
                eprintln!("failed to close unusable migration handoff: {shutdown_error}");
            }
        }
    });
}

#[derive(Debug, Clone, Serialize)]
struct ProductInfo {
    name: &'static str,
    version: &'static str,
    license: &'static str,
    minimum_macos: &'static str,
    architecture: &'static str,
}

#[derive(Clone, Serialize)]
pub(crate) struct BootPayload {
    product: ProductInfo,
    migration_handoff: bool,
    migration_handoff_status: MigrationHandoffStatus,
    migration_handoff_renderer_ready: Option<MigrationHandoffRendererReady>,
}

#[tauri::command]
pub(crate) fn boot_payload(
    launch: State<'_, LaunchContext>,
    lifecycle: State<'_, AppLifecycle>,
) -> Result<BootPayload, String> {
    Ok(BootPayload {
        product: ProductInfo {
            name: "Clash for Mac",
            version: env!("CARGO_PKG_VERSION"),
            license: "GPL-3.0-or-later",
            minimum_macos: "15.0",
            architecture: "arm64",
        },
        migration_handoff: launch.is_migration_handoff(),
        migration_handoff_status: lifecycle.migration_handoff_status()?,
        migration_handoff_renderer_ready: launch.migration_handoff_renderer_ready()?,
    })
}

#[tauri::command]
pub(crate) fn acknowledge_migration_handoff_renderer_ready(
    window: WebviewWindow,
    launch: State<'_, LaunchContext>,
    generation: u32,
    challenge: String,
) -> Result<(), String> {
    let renderer = RendererReadyChallenge::from_renderer_input(generation, challenge)?;
    launch.acknowledge_renderer_ready(window.label(), renderer)?;
    schedule_post_parent_window_activation(window.app_handle().clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    fn challenges() -> Vec<RendererReadyChallenge> {
        (1..=3)
            .map(|generation| RendererReadyChallenge {
                generation,
                challenge: format!("00000000-0000-4000-8000-{generation:012x}"),
            })
            .collect()
    }

    fn active_challenge(gate: &RendererReadyGate) -> RendererReadyChallenge {
        let MigrationHandoffRendererReady::Challenge {
            generation,
            challenge,
        } = gate.boot_state(&challenges()).expect("issue challenge")
        else {
            panic!("expected challenge");
        };
        RendererReadyChallenge {
            generation,
            challenge,
        }
    }

    #[test]
    fn native_setup_does_not_publish_or_issue_a_renderer_challenge() {
        let gate = RendererReadyGate::default();
        assert!(gate.boot_state(&challenges()).is_err());
        assert!(gate.require_post_parent_window_ready().is_err());
        let publications = AtomicUsize::new(0);
        assert!(
            gate.acknowledge_with(
                MAIN_WINDOW_LABEL,
                challenges()[0].clone(),
                || Ok(()),
                |_| {
                    publications.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(publications.load(Ordering::Acquire), 0);
        gate.mark_native_ready().expect("native ready");
        assert!(gate.require_post_parent_window_ready().is_err());
    }

    #[test]
    fn exhausting_parent_bound_generations_is_terminal() {
        let gate = RendererReadyGate::default();
        gate.mark_native_ready().expect("native ready");
        let only = vec![challenges()[0].clone()];
        assert!(gate.boot_state(&only).is_ok());
        assert!(gate.boot_state(&only).is_err());
        assert!(gate.boot_state(&only).is_err());
        assert!(gate.require_post_parent_window_ready().is_err());
    }

    #[test]
    fn stale_and_wrong_window_acknowledgements_do_not_poison_the_current_generation() {
        let gate = RendererReadyGate::default();
        gate.mark_native_ready().expect("native ready");
        let stale = active_challenge(&gate);
        let current = active_challenge(&gate);
        assert!(
            gate.acknowledge_with(MAIN_WINDOW_LABEL, stale, || Ok(()), |_| Ok(()))
                .is_err()
        );
        assert!(
            gate.acknowledge_with("other", current.clone(), || Ok(()), |_| Ok(()))
                .is_err()
        );
        gate.acknowledge_with(MAIN_WINDOW_LABEL, current, || Ok(()), |_| Ok(()))
            .expect("current main-window acknowledgement");
        assert!(gate.require_post_parent_window_ready().is_err());
        gate.mark_post_parent_window_ready()
            .expect("post-parent window ready");
        gate.require_post_parent_window_ready()
            .expect("final migration window readiness");
        assert!(gate.mark_post_parent_window_ready().is_err());
    }

    #[test]
    fn replay_and_publish_failure_are_terminal_and_never_republish() {
        let gate = RendererReadyGate::default();
        gate.mark_native_ready().expect("native ready");
        let proof = active_challenge(&gate);
        let calls = AtomicUsize::new(0);
        gate.acknowledge_with(
            MAIN_WINDOW_LABEL,
            proof.clone(),
            || Ok(()),
            |_| {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            },
        )
        .expect("publish");
        assert!(
            gate.acknowledge_with(
                MAIN_WINDOW_LABEL,
                proof,
                || Ok(()),
                |_| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                }
            )
            .is_err()
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);

        let failed = RendererReadyGate::default();
        failed.mark_native_ready().expect("native ready");
        let proof = active_challenge(&failed);
        assert!(
            failed
                .acknowledge_with(
                    MAIN_WINDOW_LABEL,
                    proof.clone(),
                    || Ok(()),
                    |_| { Err("injected persistence failure".into()) }
                )
                .is_err()
        );
        assert!(
            failed
                .acknowledge_with(MAIN_WINDOW_LABEL, proof, || Ok(()), |_| Ok(()))
                .is_err()
        );
        assert!(failed.require_post_parent_window_ready().is_err());
    }

    #[test]
    fn concurrent_acknowledgements_have_exactly_one_publication_side_effect() {
        let gate = Arc::new(RendererReadyGate::default());
        gate.mark_native_ready().expect("native ready");
        let proof = active_challenge(&gate);
        let publications = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let gate = gate.clone();
            let proof = proof.clone();
            let publications = publications.clone();
            workers.push(std::thread::spawn(move || {
                gate.acknowledge_with(
                    MAIN_WINDOW_LABEL,
                    proof,
                    || Ok(()),
                    |_| {
                        publications.fetch_add(1, Ordering::AcqRel);
                        std::thread::sleep(Duration::from_millis(20));
                        Ok(())
                    },
                )
            }));
        }
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(publications.load(Ordering::Acquire), 1);
    }

    #[test]
    fn dashboard_and_inconsistent_handoff_roles_have_no_acknowledgement_path() {
        let dashboard = LaunchContext::dashboard();
        assert!(dashboard.require_handoff_ticket().is_err());

        let inconsistent = LaunchContext {
            migration_handoff: true,
            handoff_ticket: None,
            _handoff_lease: None,
            renderer_ready: RendererReadyGate::default(),
        };
        assert!(inconsistent.require_handoff_ticket().is_err());
    }

    #[tokio::test]
    async fn parent_exit_wait_is_bounded_and_preserves_observation_errors() {
        let checks = AtomicUsize::new(0);
        let sleeps = AtomicUsize::new(0);
        wait_for_parent_absence_with(
            || Ok(checks.fetch_add(1, Ordering::AcqRel) >= 2),
            || {
                sleeps.fetch_add(1, Ordering::AcqRel);
                std::future::ready(())
            },
            4,
        )
        .await
        .expect("third observation sees parent exit");
        assert_eq!(checks.load(Ordering::Acquire), 3);
        assert_eq!(sleeps.load(Ordering::Acquire), 2);

        let error = wait_for_parent_absence_with(
            || Err("kernel observation failed".into()),
            || std::future::ready(()),
            4,
        )
        .await
        .expect_err("observation failure remains terminal");
        assert_eq!(error, "kernel observation failed");

        let error = wait_for_parent_absence_with(|| Ok(false), || std::future::ready(()), 2)
            .await
            .expect_err("bounded wait times out");
        assert_eq!(
            error,
            "migration dashboard parent did not exit within 20 seconds"
        );
        assert!(
            wait_for_parent_absence_with(|| Ok(true), || std::future::ready(()), 0,)
                .await
                .is_err()
        );
    }
}
