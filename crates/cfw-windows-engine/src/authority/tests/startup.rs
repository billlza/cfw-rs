use super::*;

fn prior_off_proof(state: &AuthorityCommittedState) -> CleanupEvidence {
    let mut proof = CleanupEvidence::for_validation(state.revision(), None, true);
    proof.binding = CleanupBinding::RecordedOff(state.clone());
    proof
}

#[test]
fn startup_admission_preserves_enrollment_and_unused_allocations_without_a_lease() {
    let initial = AuthorityCommittedState::enrollment(Uuid::from_u128(1));
    let reserved = initial.reserve_next_generation().unwrap();
    for prior in [initial, reserved.clone(), reserved.checkpoint().unwrap()] {
        let mut machine = recovered(Some(prior.clone()));
        assert_eq!(machine.recorded_off_target().unwrap(), prior);
        machine.reconcile(&prior_off_proof(&prior)).unwrap();
        assert_eq!(machine.phase(), AuthorityState::Off);
        assert_eq!(machine.metadata(), Some(&prior));
        assert_eq!(machine.revision(), prior.revision());
        assert!(machine.context().is_none());
        assert!(machine.lease_for_owner(&peer(Role::Desktop)).is_err());
        assert!(matches!(
            machine.recorded_off_target(),
            Err(AuthorityError::Recovering)
        ));
    }
}

#[test]
fn startup_readmission_of_retired_runtime_keeps_lineage_and_commits_a_new_revision() {
    let now = Instant::now();
    let (mut original, host, _, context, _) = prepared(now);
    original
        .abort_prepared(Some(&host), original.revision(), now)
        .unwrap();
    original.finish_unbound_abort().unwrap();
    let retired = original.metadata().unwrap().clone();
    let unused = retired.reserve_next_generation().unwrap();
    for prior in [retired, unused] {
        let mut machine = recovered(Some(prior.clone()));
        assert_eq!(machine.recorded_off_target().unwrap(), prior);
        machine.reconcile(&prior_off_proof(&prior)).unwrap();
        let current = machine.metadata().unwrap();
        assert_eq!(current.root(), &context.operation.root);
        assert_eq!(current.allocated_generation(), prior.allocated_generation());
        assert_eq!(current.revision(), prior.revision() + 1);
        assert_eq!(current.transition(), JournalTransition::ReconcileOff);
        assert_eq!(machine.phase(), AuthorityState::Off);
        assert!(current.operation().is_none());
        assert!(machine.context().is_none());
        current.validate_successor(&prior).unwrap();
    }
}

#[test]
fn startup_requires_known_off_and_never_restores_execution_from_other_records() {
    assert!(matches!(
        recovered(None).recorded_off_target(),
        Err(AuthorityError::Recovering)
    ));
    let (value, _, _, _, _) = prepared(Instant::now());
    let operation = value.metadata().unwrap().operation().unwrap().clone();
    let root = value.metadata().unwrap().root().clone();
    for (state, transition) in [
        (AuthorityState::Preparing, JournalTransition::Prepare),
        (AuthorityState::Starting, JournalTransition::BindOwner),
        (AuthorityState::Active, JournalTransition::Ready),
        (AuthorityState::Stopping, JournalTransition::OwnerStopped),
        (AuthorityState::Quarantined, JournalTransition::ReconcileOff),
    ] {
        let prior = AuthorityCommittedState::new(
            root.clone(),
            7,
            transition,
            state,
            Some(operation.clone()),
        )
        .unwrap();
        let machine = recovered(Some(prior.clone()));
        assert!(matches!(
            machine.recorded_off_target(),
            Err(AuthorityError::CleanupUnproven)
        ));
        assert_eq!(machine.phase(), AuthorityState::Recovering);
        assert_eq!(machine.metadata(), Some(&prior));
        assert!(machine.context().is_none());
    }
    let mut uncertain = recovered(Some(AuthorityCommittedState::enrollment(Uuid::from_u128(
        1,
    ))));
    uncertain.enter_recovery(true);
    assert!(matches!(
        uncertain.recorded_off_target(),
        Err(AuthorityError::Recovering)
    ));
    assert_eq!(uncertain.snapshot().revision, None);
}

#[test]
fn startup_evidence_binds_full_record_and_cannot_hide_allocations_or_a_lease() {
    let prior = AuthorityCommittedState::enrollment(Uuid::from_u128(1))
        .reserve_next_generation()
        .unwrap();
    let mut altered = serde_json::to_value(&prior).unwrap();
    altered["allocated_generation"] = serde_json::json!(2);
    let different: AuthorityCommittedState = serde_json::from_value(altered).unwrap();
    let proof = prior_off_proof(&prior);
    assert!(matches!(
        proof.validate_scope(Some(&different)),
        Err(AuthorityError::Stale)
    ));
    assert!(matches!(
        proof.validate_scope(None),
        Err(AuthorityError::Stale)
    ));
    let mut wrong_revision = prior_off_proof(&prior);
    wrong_revision.revision += 1;
    assert!(matches!(
        wrong_revision.validate_scope(Some(&prior)),
        Err(AuthorityError::Stale)
    ));
    let mut with_lease = prior_off_proof(&prior);
    with_lease.lease_id = Some(Uuid::from_u128(8));
    assert!(matches!(
        with_lease.validate_scope(Some(&prior)),
        Err(AuthorityError::Stale)
    ));
    let (active, _, _, _) = active(Instant::now());
    assert!(matches!(
        prior_off_proof(active.metadata().unwrap()).validate_scope(active.metadata()),
        Err(AuthorityError::Stale)
    ));
}
