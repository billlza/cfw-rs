//! Native peer + actual journal publication checks. Cleanup observations are
//! explicitly injected for policy testing; no engine or TUN runtime is started.
use super::*;
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext};
use cfw_windows_engine::ServicePeerAuthorization;
use cfw_windows_engine::authority::{
    AuthorityError, CleanupEvidence, PrepareRequest, WindowsAuthority,
};
use cfw_windows_engine::authority_journal::{JournalFaultPoint, JournalStoreError};
use std::io::Write;

pub(super) fn request(name: &str, image: &Path, digest: [u8; 32]) -> Result<()> {
    let mut channel =
        ServiceChannel::connect(name, ServiceClientRole::Desktop, verified(image, digest)?)
            .map_err(|e| e.to_string())?;
    if channel
        .request(b"authority-state", Instant::now() + Duration::from_secs(45))
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"state-ok"
    {
        return Err("authority state fixture reply mismatch".into());
    }
    Ok(())
}

pub(super) struct Validation {
    controller: Option<WindowsAuthority>,
    path: PathBuf,
    scope: String,
    next: PrepareRequest,
    cleanup_attempted: bool,
}
fn input(installation: uuid::Uuid, revision: u64, generation: u64) -> PrepareRequest {
    PrepareRequest {
        root: RootContext {
            installation_id: installation,
            epoch: 1,
            generation,
        },
        operation_id: uuid::Uuid::new_v4(),
        mode: AuthorityMode::SystemProxy,
        config_sha256: [3; 32],
        identity_sha256: [4; 32],
        expected_revision: revision,
    }
}
fn isolated_off(controller: &mut WindowsAuthority) -> Result<()> {
    let revision = controller
        .snapshot()
        .revision
        .ok_or("unknown fixture revision before cleanup")?;
    let lease = controller
        .recovery_target()
        .and_then(|state| state.operation().map(|op| op.lease_id()));
    controller
        .reconcile_off(CleanupEvidence::for_validation(revision, lease, true))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn allocate(controller: &mut WindowsAuthority, peer: &ServicePeerAuthorization) -> Result<()> {
    let current = controller.lineage(peer).map_err(|e| e.to_string())?;
    let next = controller
        .reserve_generation(peer, &current)
        .map_err(|e| e.to_string())?;
    assert_eq!(next.installation_id, current.installation_id);
    assert_eq!(next.config_epoch, current.config_epoch);
    assert_eq!(next.generation, current.generation + 1);
    Ok(())
}

pub(super) fn begin(peer: &ServicePeerAuthorization) -> Result<Validation> {
    let scope = format!("CFW-authority-{}", uuid::Uuid::new_v4());
    let path = authority_journal::root()?.join(&scope);
    let client_installation = uuid::Uuid::new_v4();
    let mut case = Validation {
        controller: None,
        path,
        scope,
        next: input(client_installation, 1, 1),
        cleanup_attempted: false,
    };
    case.controller =
        Some(WindowsAuthority::open(&case.path, &case.scope).map_err(|e| e.to_string())?);
    let controller = case.controller.as_mut().ok_or("missing native authority")?;
    assert_eq!(controller.snapshot().state, AuthorityState::Recovering);
    let initial = controller.lineage(peer).map_err(|e| e.to_string())?;
    let installation = initial.installation_id;
    assert_ne!(installation, client_installation);
    assert_eq!(initial.generation, 0);
    assert!(matches!(
        controller.reserve_generation(peer, &initial),
        Err(AuthorityError::Recovering)
    ));
    assert!(matches!(
        controller.prepare(peer, input(installation, 1, 1)),
        Err(AuthorityError::Recovering)
    ));
    isolated_off(controller)?;
    let genesis = controller.recovery_target().cloned();
    assert!(matches!(
        controller.prepare(peer, input(client_installation, 2, 1)),
        Err(AuthorityError::Stale)
    ));
    assert_eq!(controller.recovery_target().cloned(), genesis);
    allocate(controller, peer)?;
    assert!(matches!(
        controller.prepare(peer, input(client_installation, 2, 1)),
        Err(AuthorityError::Replay)
    ));
    assert_eq!(controller.snapshot().revision, Some(2));
    let first = controller
        .prepare(peer, input(installation, 2, 1))
        .map_err(|e| e.to_string())?;
    assert_eq!(
        first.context().operation.owner.sid_bytes(),
        peer.owner().user_sid_bytes()
    );
    assert_eq!(controller.snapshot().revision, Some(3));
    assert_eq!(
        controller.owned_lease(peer).map_err(|e| e.to_string())?,
        *first.context()
    );
    assert!(matches!(
        first.with_ticket(|ticket| controller.bind_user_agent(
            peer,
            first.context().clone(),
            ticket
        )),
        Err(AuthorityError::Identity)
    ));
    let mut foreign_context = first.context().clone();
    foreign_context.operation.operation_id = uuid::Uuid::new_v4();
    assert!(matches!(
        controller.abort_prepared(peer, &foreign_context, 3),
        Err(AuthorityError::Stale)
    ));
    assert_eq!(controller.snapshot().revision, Some(3));
    let aborted = controller
        .abort_prepared(peer, first.context(), 3)
        .map_err(|e| e.to_string())?;
    assert_eq!(aborted.state, AuthorityState::Off);
    assert_eq!(aborted.revision, Some(5));
    allocate(controller, peer)?;
    let second = controller
        .prepare(peer, input(installation, 6, 2))
        .map_err(|e| e.to_string())?;
    assert!(
        first.with_ticket(|a| second.with_ticket(|b| a.len() == 32 && b.len() == 32 && a != b))
    );
    let journal = std::fs::read(case.path.join("journal-1.bin")).map_err(|e| e.to_string())?;
    for grant in [&first, &second] {
        assert!(
            !grant.with_ticket(|ticket| journal.windows(ticket.len()).any(|part| part == ticket))
        );
    }
    // A fresh directory/anchor handle retains the SYSTEM counter but no lease.
    case.controller = None;
    let mut reopened =
        WindowsAuthority::open(&case.path, &case.scope).map_err(|e| e.to_string())?;
    assert_eq!(reopened.snapshot().state, AuthorityState::Recovering);
    assert_eq!(reopened.snapshot().revision, Some(7));
    let retained = reopened.lineage(peer).map_err(|e| e.to_string())?;
    assert_eq!(retained.installation_id, installation);
    assert_eq!(retained.generation, 2);
    let scope = reopened
        .recorded_runtime_scope(peer)
        .map_err(|e| e.to_string())?;
    assert_eq!(scope.snapshot().state, AuthorityState::Recovering);
    assert_eq!(scope.operation().unwrap().config_sha256(), &[3; 32]);
    assert_eq!(scope.operation().unwrap().identity_sha256(), &[4; 32]);
    assert!(reopened.owned_lease(peer).is_err());
    assert!(matches!(
        reopened.prepare(peer, input(installation, 7, 3)),
        Err(AuthorityError::Recovering)
    ));
    isolated_off(&mut reopened)?;
    assert_eq!(reopened.snapshot().revision, Some(8));
    drop((first, second));
    allocate(&mut reopened, peer)?;
    reopened
        .interrupt_next_publication_for_validation(JournalFaultPoint::CommittedAnchorPublished)
        .map_err(|e| e.to_string())?;
    match reopened.prepare(peer, input(installation, 9, 3)) {
        Err(AuthorityError::Journal(JournalStoreError::InjectedFault)) => {}
        Err(error) => return Err(format!("unexpected native publication failure: {error}")),
        Ok(_) => return Err("authority returned a ticket despite uncertain publication".into()),
    }
    assert_eq!(reopened.snapshot().state, AuthorityState::Recovering);
    assert_eq!(reopened.snapshot().revision, None);
    assert!(reopened.owned_lease(peer).is_err());
    assert!(matches!(
        reopened.lineage(peer),
        Err(AuthorityError::Recovering)
    ));
    reopened.reload_for_recovery().map_err(|e| e.to_string())?;
    assert_eq!(reopened.snapshot().revision, Some(10));
    assert_eq!(reopened.snapshot().state, AuthorityState::Recovering);
    isolated_off(&mut reopened)?;
    assert_eq!(reopened.snapshot().revision, Some(11));
    allocate(&mut reopened, peer)?;
    let third = reopened
        .prepare(peer, input(installation, 12, 4))
        .map_err(|e| e.to_string())?;
    assert_eq!(reopened.snapshot().revision, Some(13));
    let mut foreign_context = third.context().clone();
    foreign_context.operation.operation_id = uuid::Uuid::new_v4();
    assert!(matches!(
        reopened.begin_stop(peer, &foreign_context, 13),
        Err(AuthorityError::Stale)
    ));
    assert_eq!(reopened.snapshot().revision, Some(13));
    let stopped = reopened
        .begin_stop(peer, third.context(), 13)
        .map_err(|e| e.to_string())?;
    assert_eq!(stopped.state, AuthorityState::Off);
    assert_eq!(stopped.revision, Some(15));
    let journal = std::fs::read(case.path.join("journal-1.bin")).map_err(|e| e.to_string())?;
    assert!(!third.with_ticket(|ticket| journal.windows(ticket.len()).any(|part| part == ticket)));
    drop(third);
    let current = reopened.lineage(peer).map_err(|e| e.to_string())?;
    reopened
        .interrupt_next_publication_for_validation(JournalFaultPoint::CommittedAnchorPublished)
        .map_err(|e| e.to_string())?;
    assert!(matches!(
        reopened.reserve_generation(peer, &current),
        Err(AuthorityError::Journal(JournalStoreError::InjectedFault))
    ));
    assert_eq!(reopened.snapshot().revision, None);
    assert!(matches!(
        reopened.lineage(peer),
        Err(AuthorityError::Recovering)
    ));
    reopened.reload_for_recovery().map_err(|e| e.to_string())?;
    let advanced = reopened.lineage(peer).map_err(|e| e.to_string())?;
    assert_eq!(advanced.installation_id, installation);
    assert_eq!(advanced.generation, 5);
    assert_eq!(reopened.snapshot().revision, Some(16));
    isolated_off(&mut reopened)?;
    assert_eq!(reopened.snapshot().revision, Some(17));
    case.next = input(installation, 17, 6);
    case.controller = Some(reopened);
    Ok(case)
}

impl Validation {
    fn cleanup(&mut self) -> Result<()> {
        self.cleanup_attempted = true;
        self.controller = None;
        authority_journal::cleanup(&self.path, &self.scope)
    }
    pub(super) fn finish_after_reply(mut self, peer: &ServicePeerAuthorization) -> Result<()> {
        let checked = (|| {
            let controller = self
                .controller
                .as_mut()
                .ok_or("missing post-reply controller")?;
            let before = controller.snapshot();
            match controller.prepare(peer, self.next.clone()) {
                Err(AuthorityError::Peer(ServiceAuthorizationError::Transport(
                    ServiceTransportError::RequestOrder,
                ))) => {}
                Err(error) => {
                    return Err(format!(
                        "post-reply request returned wrong rejection: {error}"
                    ));
                }
                Ok(_) => return Err("a replied request authorized another preparation".into()),
            }
            assert_eq!(controller.snapshot(), before);
            Ok(())
        })();
        let cleanup = self.cleanup();
        match (checked, cleanup) {
            (Ok(()), Ok(())) => write_report(),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => {
                Err(format!("{error}; native authority cleanup: {cleanup}"))
            }
        }
    }
}
impl Drop for Validation {
    fn drop(&mut self) {
        if !self.cleanup_attempted
            && let Err(error) = self.cleanup()
        {
            SERVICE_EXIT.store(1, Ordering::SeqCst);
            if let Err(record_error) =
                record_service_failure(&format!("native authority fixture cleanup: {error}"))
            {
                eprintln!("authority cleanup failed ({error}); recording failed ({record_error})");
            }
        }
    }
}
fn expected() -> serde_json::Value {
    serde_json::json!({"success":true,"preparation_api_returns":3,"system_rng_used":true,"ticket_material_absent_from_journal":true,"wrong_runtime_role_rejected":true,"stale_request_did_not_publish":true,"client_installation_claim_rejected":true,"lineage_survives_reopen":true,"recovered_configuration_identity_preserved":true,"allocated_generations":5,"uncertain_allocation_did_not_return_generation":true,"foreign_operation_abort_rejected":true,"unbound_begin_stop_releases_without_runtime":true,"reopen_does_not_restore_ticket":true,"post_commit_failure_returns_no_ticket":true,"uncertain_revision_not_reported_as_current":true,"replied_request_cannot_issue_another_ticket":true,"cleanup_observations_injected_for_policy_test":true,"native_runtime_owner_bound":false,"actual_runtime_started":false,"full_service_backend_proven":false})
}
fn write_report() -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(authority_journal::root()?.join("lifecycle.authority-validation.json"))
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec(&expected()).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}
pub(super) fn require_report(root: &Path) -> Result<()> {
    let bytes = std::fs::read(root.join("lifecycle.authority-validation.json"))
        .map_err(|e| e.to_string())?;
    if bytes.len() > 8192 {
        return Err("authority fixture report exceeded its bound".into());
    }
    let report: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if report != expected() {
        return Err("authority fixture report differs from its checks".into());
    }
    Ok(())
}
