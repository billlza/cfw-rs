use super::*;
// State-machine unit tests use an inert resource value; product Windows
// instantiations retain the real staging lease and inspected MSI.
type UpdaterSecurityState = super::UpdaterSecurityState<()>;
type StagedUpdate = super::StagedUpdate<()>;

fn authorization(version: &str) -> UpdateAuthorization {
    UpdateAuthorization {
        version: version.into(),
        archive_name: format!("archive-{version}.tar.gz"),
        download_url: format!("https://github.com/release/{version}"),
        signature: format!("signature-{version}"),
    }
}

#[test]
fn renderer_must_request_the_exact_presented_version() {
    let state = UpdaterSecurityState::default();
    state
        .authorize(authorization("1.2.3"))
        .expect("presented check");
    assert!(state.authorization("1.2.3").is_ok());
    assert!(matches!(
        state.authorization("1.2.4"),
        Err(UpdateError::AuthorizationChanged)
    ));
    assert!(matches!(
        state.authorization("1.2.3"),
        Err(UpdateError::MissingAuthorization)
    ));
}

#[test]
fn recheck_must_match_the_exact_presented_authorization() {
    let state = UpdaterSecurityState::default();
    let first = authorization("1.2.3");
    state.authorize(first.clone()).expect("presented check");
    let checked = state.authorization("1.2.3").expect("authorization");
    state
        .consume_if_current(&checked, &first)
        .expect("matching recheck");
    assert!(matches!(
        state.authorization("1.2.3"),
        Err(UpdateError::MissingAuthorization)
    ));

    state.authorize(first.clone()).expect("second check");
    let checked = state.authorization("1.2.3").expect("authorization");
    assert!(matches!(
        state.consume_if_current(&checked, &authorization("1.2.4")),
        Err(UpdateError::AuthorizationChanged)
    ));
    assert!(matches!(
        state.authorization("1.2.3"),
        Err(UpdateError::MissingAuthorization)
    ));
}

#[test]
fn any_intervening_check_invalidates_the_presented_snapshot() {
    let state = UpdaterSecurityState::default();
    let first = authorization("1.2.3");
    state.authorize(first.clone()).expect("first check");
    let checked = state.authorization("1.2.3").expect("authorization");
    state
        .authorize(authorization("1.2.4"))
        .expect("intervening check");
    assert!(matches!(
        state.consume_if_current(&checked, &first),
        Err(UpdateError::AuthorizationChanged)
    ));
}

#[test]
fn consumed_authorization_cannot_be_replayed() {
    let state = UpdaterSecurityState::default();
    state
        .authorize(authorization("1.2.3"))
        .expect("presented check");
    state.clear_authorization().expect("consume authorization");
    assert!(matches!(
        state.authorization("1.2.3"),
        Err(UpdateError::MissingAuthorization)
    ));
}

fn staged(version: &str) -> StagedUpdate {
    StagedUpdate {
        transaction: Uuid::from_u128(11),
        offer_version: version.into(),
        resources: (),
        installed: BundleIdentity {
            version: "0.4.0".into(),
            build: 40074,
        },
        staged: BundleIdentity {
            version: version.into(),
            build: 50021,
        },
    }
}

struct TrackedResource {
    allocation: Box<u64>,
    drops: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for TrackedResource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn tracked_stage(
    drops: &Arc<std::sync::atomic::AtomicUsize>,
) -> super::StagedUpdate<TrackedResource> {
    let stage = staged("0.5.0");
    super::StagedUpdate {
        transaction: stage.transaction,
        offer_version: stage.offer_version,
        installed: stage.installed,
        staged: stage.staged,
        resources: TrackedResource {
            allocation: Box::new(91),
            drops: drops.clone(),
        },
    }
}

fn reviewed_resources() -> super::UpdaterSecurityState<TrackedResource> {
    let state = super::UpdaterSecurityState::default();
    state
        .begin_review()
        .unwrap()
        .unwrap()
        .complete(InstallOutcome::None)
        .unwrap();
    state
}

#[test]
fn commit_rollback_and_cancel_move_the_same_nonclone_resource() {
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = reviewed_resources();
    let stage = tracked_stage(&drops);
    let address = std::ptr::from_ref(stage.resources.allocation.as_ref());
    state
        .begin_preparation("0.5.0")
        .unwrap()
        .stage(stage)
        .unwrap();
    let commit = state.begin_commit("0.5.0").unwrap();
    assert_eq!(
        std::ptr::from_ref(commit.staged().unwrap().resources.allocation.as_ref()),
        address
    );
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(commit);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let Cancelled::Staged(stage) = state.cancel_install().unwrap() else {
        panic!("cancel must transfer the retained resources");
    };
    assert_eq!(
        std::ptr::from_ref(stage.resources.allocation.as_ref()),
        address
    );
    assert!(state.pending().unwrap().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(stage);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_handoff_releases_resources_once_without_restaging() {
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let state = reviewed_resources();
    state
        .begin_preparation("0.5.0")
        .unwrap()
        .stage(tracked_stage(&drops))
        .unwrap();
    state.begin_commit("0.5.0").unwrap().handed_off();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(matches!(
        state.cancel_install(),
        Err(UpdateError::CancellationTooLate)
    ));
    assert!(matches!(
        state.begin_commit("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
    drop(state);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_or_wrong_version_cannot_publish_owned_resources() {
    for cancelled in [true, false] {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let state = reviewed_resources();
        let lease = state
            .begin_preparation(if cancelled { "0.5.0" } else { "0.6.0" })
            .unwrap();
        if cancelled {
            assert!(matches!(state.cancel_install(), Ok(Cancelled::Preparation)));
        }
        let result = lease.stage(tracked_stage(&drops));
        assert!(matches!(
            (cancelled, result),
            (true, Err(UpdateError::DownloadCancelled))
                | (false, Err(UpdateError::AuthorizationChanged))
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(state.pending().unwrap().is_none());
        drop(state);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

/// A state whose previous attempt has been reviewed with nothing to report.
fn reviewed() -> UpdaterSecurityState {
    let state = UpdaterSecurityState::default();
    state
        .begin_review()
        .expect("review slot")
        .expect("first review")
        .complete(InstallOutcome::None)
        .expect("reviewed");
    state
}

#[test]
fn build_qualified_offer_survives_staging_and_commit() {
    let state = reviewed();
    let version = "1.2.3-build.60124";
    let mut update = staged("1.2.3");
    update.offer_version = version.into();
    update.installed = BundleIdentity {
        version: "1.2.3".into(),
        build: 60123,
    };
    update.staged.build = 60124;
    state
        .begin_preparation(version)
        .unwrap()
        .stage(update)
        .unwrap();
    assert_eq!(state.pending().unwrap().unwrap().version, version);
    assert!(matches!(
        state.begin_commit("1.2.3"),
        Err(UpdateError::AuthorizationChanged)
    ));
    let commit = state.begin_commit(version).unwrap();
    assert_eq!(commit.staged().unwrap().staged.version, "1.2.3");
    assert_eq!(commit.staged().unwrap().staged.build, 60124);
    drop(commit);
    assert_eq!(state.pending().unwrap().unwrap().version, version);
    state.begin_commit(version).unwrap().handed_off();
}

fn pending(phase: PendingPhase) -> Option<PendingInstall> {
    Some(PendingInstall {
        phase,
        version: "0.5.0".into(),
    })
}

#[test]
fn nothing_is_prepared_before_the_previous_attempt_was_reviewed() {
    let state = UpdaterSecurityState::default();
    assert!(matches!(
        state.begin_preparation("0.5.0"),
        Err(UpdateError::PreviousAttemptUnreviewed)
    ));

    let review = state.begin_review().expect("slot").expect("first review");
    assert!(
        matches!(state.begin_review(), Err(UpdateError::InstallAlreadyActive)),
        "one review at a time"
    );
    assert_eq!(state.pending().expect("pending"), None);
    assert_eq!(
        state.cancel_install().expect("nothing to cancel"),
        Cancelled::Nothing
    );
    drop(review);
    assert!(
        matches!(
            state.begin_preparation("0.5.0"),
            Err(UpdateError::PreviousAttemptUnreviewed)
        ),
        "an abandoned review leaves the attempt unreviewed"
    );

    let outcome = InstallOutcome::Failed {
        version: "0.5.0".into(),
        code: "exchange_failed".into(),
    };
    state
        .begin_review()
        .expect("slot")
        .expect("second review")
        .complete(outcome.clone())
        .expect("reviewed");
    assert!(
        state.begin_review().expect("slot").is_none(),
        "the previous attempt is reviewed once per process"
    );
    assert_eq!(state.take_unreported_outcome().expect("outcome"), outcome);
    assert_eq!(
        state.take_unreported_outcome().expect("outcome"),
        InstallOutcome::None,
        "the outcome is reported once"
    );
    drop(state.begin_preparation("0.5.0").expect("preparation"));
}

#[test]
fn a_release_that_failed_authentication_stays_rejected_until_it_changes() {
    let state = UpdaterSecurityState::default();
    let release = authorization("1.2.3");
    assert!(!state.is_rejected(&release).expect("query"));
    state.reject_release(&release).expect("reject");
    assert!(state.is_rejected(&release).expect("query"));
    state.authorize(release.clone()).expect("fresh check");
    assert!(
        state.is_rejected(&release).expect("query"),
        "a fresh check of the same release does not clear the verdict"
    );
    let mut republished = release.clone();
    republished.signature = "another-signature".into();
    assert!(!state.is_rejected(&republished).expect("query"));
    assert!(!state.is_rejected(&authorization("1.2.4")).expect("query"));
}

#[test]
fn one_installation_occupies_the_slot_until_its_preparation_ends() {
    let state = reviewed();
    let lease = state.begin_preparation("0.5.0").expect("first preparation");
    assert_eq!(
        state.pending().expect("pending"),
        pending(PendingPhase::Preparing)
    );
    assert!(matches!(
        state.begin_preparation("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
    assert!(matches!(
        state.begin_commit("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
    drop(lease);
    assert!(matches!(
        state.begin_commit("0.5.0"),
        Err(UpdateError::NoStagedUpdate)
    ));
    assert_eq!(state.pending().expect("pending"), None);
    drop(
        state
            .begin_preparation("0.5.0")
            .expect("slot is free after an abandoned preparation"),
    );
}

#[test]
fn cancelling_a_preparation_signals_it_and_refuses_a_late_stage() {
    let state = reviewed();
    assert_eq!(state.cancel_install().expect("idle"), Cancelled::Nothing);
    let lease = state.begin_preparation("0.5.0").expect("preparation");
    assert!(!lease.cancellation.is_cancelled());
    assert_eq!(
        state.cancel_install().expect("cancel"),
        Cancelled::Preparation
    );
    assert!(lease.cancellation.is_cancelled());
    assert!(
        matches!(
            state.begin_preparation("0.5.0"),
            Err(UpdateError::InstallAlreadyActive)
        ),
        "the cancelled task still owns the slot until it stops"
    );
    assert!(matches!(
        lease.stage(staged("0.5.0")),
        Err(UpdateError::DownloadCancelled)
    ));
    drop(
        state
            .begin_preparation("0.5.0")
            .expect("slot is free after the cancelled task ended"),
    );
}

#[test]
fn a_staged_update_is_committed_only_for_its_exact_version() {
    let state = reviewed();
    state
        .begin_preparation("0.5.0")
        .expect("preparation")
        .stage(staged("0.5.0"))
        .expect("staged");
    assert_eq!(
        state.pending().expect("pending"),
        pending(PendingPhase::Staged)
    );
    assert!(matches!(
        state.begin_preparation("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
    assert!(matches!(
        state.begin_commit("0.5.1"),
        Err(UpdateError::AuthorizationChanged)
    ));
    let committing = state.begin_commit("0.5.0").expect("commit");
    assert_eq!(committing.staged().expect("owned stage"), &staged("0.5.0"));
    assert_eq!(
        state.pending().expect("pending"),
        pending(PendingPhase::Committing)
    );
    assert!(matches!(
        state.begin_commit("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
    assert!(matches!(
        state.cancel_install(),
        Err(UpdateError::CancellationTooLate)
    ));

    drop(committing);
    assert_eq!(
        state.pending().expect("pending"),
        pending(PendingPhase::Staged),
        "a hand-off that ended without the installer keeps the update staged"
    );
    assert_eq!(
        state.cancel_install().expect("discard"),
        Cancelled::Staged(staged("0.5.0"))
    );
    assert_eq!(state.cancel_install().expect("idle"), Cancelled::Nothing);
    assert_eq!(state.pending().expect("pending"), None);
}

#[test]
fn a_completed_hand_off_never_returns_the_update_to_the_waiting_state() {
    let state = reviewed();
    state
        .begin_preparation("0.5.0")
        .expect("preparation")
        .stage(staged("0.5.0"))
        .expect("staged");
    state.begin_commit("0.5.0").expect("commit").handed_off();
    assert_eq!(
        state.pending().expect("pending"),
        pending(PendingPhase::Committing)
    );
    assert!(matches!(
        state.cancel_install(),
        Err(UpdateError::CancellationTooLate)
    ));
    assert!(matches!(
        state.begin_commit("0.5.0"),
        Err(UpdateError::InstallAlreadyActive)
    ));
}

#[test]
fn pending_installations_serialize_as_phase_and_version() {
    assert_eq!(
        serde_json::to_value(pending(PendingPhase::Staged)).expect("serialize"),
        serde_json::json!({ "phase": "staged", "version": "0.5.0" })
    );
    assert_eq!(
        serde_json::to_value(None::<PendingInstall>).expect("serialize"),
        serde_json::Value::Null
    );
    for (phase, name) in [
        (PendingPhase::Preparing, "preparing"),
        (PendingPhase::Committing, "committing"),
    ] {
        assert_eq!(
            serde_json::to_value(phase).expect("serialize"),
            serde_json::json!(name)
        );
    }
}

#[tokio::test]
async fn cancellation_wakes_a_registered_waiter_and_stays_set() {
    let cancellation = Arc::new(DownloadCancellation::new());
    let waiter = {
        let cancellation = cancellation.clone();
        tokio::spawn(async move { cancellation.cancelled().await })
    };
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    cancellation.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("the waiter is woken")
        .expect("waiter task");
    tokio::time::timeout(std::time::Duration::from_secs(5), cancellation.cancelled())
        .await
        .expect("a later waiter returns immediately");
}

#[test]
fn concurrent_checks_are_rejected_instead_of_queued() {
    let state = UpdaterSecurityState::default();
    let first = state.try_serialize_checks().expect("first check");
    assert!(matches!(
        state.try_serialize_checks(),
        Err(UpdateError::Busy)
    ));
    drop(first);
    let second = state
        .try_serialize_checks()
        .expect("capacity returns after the active check");
    assert!(matches!(
        state.try_serialize_checks(),
        Err(UpdateError::Busy)
    ));
    drop(second);
}
