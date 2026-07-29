use std::sync::Mutex;

use serde::Serialize;
use tauri::{State, WebviewWindow};

use crate::legacy::{
    ConsumedHandoffTicket, MigrationHandoffLease, ProcessIdentity, RendererReadyChallenge,
};
use crate::lifecycle::{AppLifecycle, MigrationHandoffStatus};

const MAIN_WINDOW_LABEL: &str = "main";

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
        self.renderer_ready.require_published()
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
            RendererReadyPhase::Published => Ok(MigrationHandoffRendererReady::Published),
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
            RendererReadyPhase::Published => {
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

    fn require_published(&self) -> Result<(), String> {
        if matches!(self.lock()?.phase, RendererReadyPhase::Published) {
            Ok(())
        } else {
            Err("migration renderer readiness has not been published".into())
        }
    }
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
    launch.acknowledge_renderer_ready(window.label(), renderer)
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
        assert!(gate.require_published().is_err());
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
        assert!(gate.require_published().is_err());
    }

    #[test]
    fn exhausting_parent_bound_generations_is_terminal() {
        let gate = RendererReadyGate::default();
        gate.mark_native_ready().expect("native ready");
        let only = vec![challenges()[0].clone()];
        assert!(gate.boot_state(&only).is_ok());
        assert!(gate.boot_state(&only).is_err());
        assert!(gate.boot_state(&only).is_err());
        assert!(gate.require_published().is_err());
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
        assert!(failed.require_published().is_err());
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
}
