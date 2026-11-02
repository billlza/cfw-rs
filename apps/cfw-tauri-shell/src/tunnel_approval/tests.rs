use std::collections::VecDeque;
use std::sync::Arc;

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext, EngineMode,
    EngineRuntimePlatform, EngineSessionIdentity, EngineStartRequest, NativeEngineStatus,
    RuntimeIdentity, TunnelApprovalFuture, TunnelInstallOutcome,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

use super::*;

/// A platform whose Tunnel installation always awaits the person's approval.
struct AwaitingInstallation;

fn not_part_of_the_wait<T: Send + 'static>(operation: &'static str) -> BackendFuture<'static, T> {
    Box::pin(async move {
        Err(BackendError::new(
            BackendErrorKind::Unavailable,
            format!("{operation} is not part of an approval wait"),
        ))
    })
}

impl EngineBackend for AwaitingInstallation {
    fn runtime_platform(&self) -> EngineRuntimePlatform {
        EngineRuntimePlatform::MacOs
    }
    fn query_status(&self) -> BackendFuture<'_, NativeEngineStatus> {
        Box::pin(async { Ok(NativeEngineStatus::Off) })
    }
    fn check_configuration(&self, _request: EngineStartRequest) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn start_local_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        not_part_of_the_wait("start_local_proxy")
    }
    fn stop_local_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        not_part_of_the_wait("stop_local_proxy")
    }
    fn start_system_proxy(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, RuntimeIdentity> {
        not_part_of_the_wait("start_system_proxy")
    }
    fn stop_system_proxy(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        not_part_of_the_wait("stop_system_proxy")
    }
    fn install_tunnel(
        &self,
        _context: EngineCommandContext,
    ) -> BackendFuture<'_, TunnelInstallOutcome> {
        Box::pin(async { Ok(TunnelInstallOutcome::AwaitingApproval) })
    }
    fn cancel_tunnel_install(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn authorize_tunnel_configuration(
        &self,
        _request: EngineStartRequest,
    ) -> BackendFuture<'_, ()> {
        not_part_of_the_wait("authorize_tunnel_configuration")
    }
    fn start_tunnel(&self, _request: EngineStartRequest) -> BackendFuture<'_, RuntimeIdentity> {
        not_part_of_the_wait("start_tunnel")
    }
    fn stop_tunnel(&self, _context: EngineCommandContext) -> BackendFuture<'_, ()> {
        not_part_of_the_wait("stop_tunnel")
    }
}

/// Answers each approval wait from a script and records its context.
struct ScriptedApproval {
    answers: Mutex<VecDeque<Result<TunnelApprovalWait, BackendError>>>,
    contexts: Mutex<Vec<EngineCommandContext>>,
}

impl ScriptedApproval {
    fn answering(
        answers: impl IntoIterator<Item = Result<TunnelApprovalWait, BackendError>>,
    ) -> Self {
        Self {
            answers: Mutex::new(answers.into_iter().collect()),
            contexts: Mutex::new(Vec::new()),
        }
    }

    fn contexts(&self) -> Vec<EngineCommandContext> {
        self.contexts.lock().expect("contexts lock").clone()
    }
}

impl TunnelApprovalBackend for ScriptedApproval {
    fn await_tunnel_approval(&self, context: EngineCommandContext) -> TunnelApprovalFuture<'_> {
        Box::pin(async move {
            self.contexts.lock().expect("contexts lock").push(context);
            self.answers
                .lock()
                .expect("answers lock")
                .pop_front()
                .expect("every approval wait is scripted")
        })
    }
}

async fn set_mode(coordinator: &EngineModeCoordinator, mode: EngineMode) -> EngineSnapshot {
    coordinator
        .set_mode(
            mode,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            ValidatedSingBoxProfile::direct(),
            EngineSettings::default(),
        )
        .await
        .expect("mode change")
}

async fn awaiting_coordinator() -> (EngineModeCoordinator, EngineSnapshot) {
    let coordinator = EngineModeCoordinator::spawn(
        Arc::new(AwaitingInstallation),
        EngineSessionIdentity {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
        },
    );
    let awaiting = set_mode(&coordinator, EngineMode::Tunnel).await;
    assert!(matches!(
        awaiting.state,
        EngineState::AwaitingApproval { .. }
    ));
    (coordinator, awaiting)
}

#[tokio::test]
async fn the_answer_is_waited_for_with_the_exact_installation_context() {
    let (coordinator, awaiting) = awaiting_coordinator().await;
    let approval = ScriptedApproval::answering([
        Ok(TunnelApprovalWait::StillAwaiting),
        Ok(TunnelApprovalWait::StillAwaiting),
        Ok(TunnelApprovalWait::Resolved),
    ]);
    assert_eq!(
        awaited_approval(&coordinator, &approval, &awaiting).await,
        Ok(ApprovalAnswer::Answered)
    );
    let context = coordinator
        .pending_tunnel_approval(awaiting)
        .await
        .expect("query")
        .expect("the installation still awaits approval");
    assert_eq!(approval.contexts(), vec![context; 3]);
}

#[tokio::test]
async fn a_withdrawn_request_or_a_stale_observation_supersedes_the_watch() {
    let (coordinator, awaiting) = awaiting_coordinator().await;
    let withdrawn = ScriptedApproval::answering([Ok(TunnelApprovalWait::NoPendingRequest)]);
    assert_eq!(
        awaited_approval(&coordinator, &withdrawn, &awaiting).await,
        Ok(ApprovalAnswer::Superseded)
    );

    let off = set_mode(&coordinator, EngineMode::Off).await;
    assert_eq!(off.state, EngineState::Off);
    let never = ScriptedApproval::answering([]);
    assert_eq!(
        awaited_approval(&coordinator, &never, &awaiting).await,
        Ok(ApprovalAnswer::Superseded)
    );
    assert!(
        never.contexts().is_empty(),
        "a stale observation waits for nothing"
    );
}

#[tokio::test]
async fn an_approval_that_never_comes_ends_the_watch_after_its_bounded_waits() {
    let (coordinator, awaiting) = awaiting_coordinator().await;
    let approval = ScriptedApproval::answering(std::iter::repeat_n(
        Ok(TunnelApprovalWait::StillAwaiting),
        MAXIMUM_APPROVAL_WAITS,
    ));
    assert_eq!(
        awaited_approval(&coordinator, &approval, &awaiting).await,
        Ok(ApprovalAnswer::Unanswered)
    );
    assert_eq!(approval.contexts().len(), MAXIMUM_APPROVAL_WAITS);
}

#[tokio::test]
async fn a_failed_wait_is_reported() {
    let (coordinator, awaiting) = awaiting_coordinator().await;
    let approval = ScriptedApproval::answering([Err(BackendError::new(
        BackendErrorKind::Unavailable,
        "native bridge closed",
    ))]);
    let error = awaited_approval(&coordinator, &approval, &awaiting)
        .await
        .expect_err("a failed wait is an error");
    assert!(error.contains("native bridge closed"), "{error}");
}

#[test]
fn one_watcher_waits_per_generation_and_a_newer_generation_replaces_it() {
    let watch = ApprovalWatch::default();
    assert_eq!(watch.claim(4), Ok(true));
    assert_eq!(watch.claim(4), Ok(false));
    assert_eq!(watch.claim(5), Ok(true));
    watch.release(4).expect("release");
    assert_eq!(
        watch.claim(5),
        Ok(false),
        "an ending older watcher keeps the newer claim"
    );
    watch.release(5).expect("release");
    assert_eq!(watch.claim(5), Ok(true));
}
