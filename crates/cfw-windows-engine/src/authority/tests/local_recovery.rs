use super::*;

#[test]
fn local_recovery_retires_known_runtime_records_without_restoring_a_stop_ack_or_lease() {
    let (stopped, host, context) = local_stop::local(true);
    let operation = stopped.metadata().unwrap().operation().unwrap().clone();
    for (state, transition, revision) in [
        (AuthorityState::Preparing, JournalTransition::Prepare, 3),
        (AuthorityState::Starting, JournalTransition::BindOwner, 4),
        (AuthorityState::Active, JournalTransition::Ready, 5),
        (AuthorityState::Stopping, JournalTransition::OwnerStopped, 7),
        (
            AuthorityState::Quarantined,
            JournalTransition::ReconcileOff,
            8,
        ),
    ] {
        let prior = AuthorityCommittedState::new(
            context.operation.root.clone(),
            revision,
            transition,
            state,
            Some(operation.clone()),
        )
        .unwrap();
        let mut recovered = recovered(Some(prior.clone()));
        assert!(recovered.context().is_none());
        assert!(recovered.lease_for_owner(&host).is_err());
        assert!(recovered.local_stopped_cleanup_target().is_err());
        assert_eq!(recovered.local_recovery_target().unwrap(), prior);
        // Only the native adapter can supply the actual process retirement;
        // this test supplies policy evidence explicitly, not an OS observation.
        let mut proof = CleanupEvidence::for_validation(revision, Some(context.lease_id), true);
        proof.binding = CleanupBinding::LocalRuntime(prior);
        recovered.reconcile(&proof).unwrap();
        assert_eq!(recovered.phase(), AuthorityState::Off);
        assert_eq!(recovered.revision(), revision + 1);
        assert_eq!(
            recovered.metadata().unwrap().transition(),
            JournalTransition::ReconcileOff
        );
        assert_eq!(
            recovered.metadata().unwrap().root(),
            &context.operation.root
        );
        assert!(recovered.metadata().unwrap().operation().is_none());
        assert!(recovered.lease_for_owner(&host).is_err());
        assert!(recovered.local_recovery_target().is_err());
        assert!(recovered.reconcile(&proof).is_err());
    }
}

#[test]
fn local_recovery_cannot_relabel_other_modes_unknown_journals_or_prior_off() {
    assert!(recovered(None).local_recovery_target().is_err());
    assert!(
        recovered(Some(AuthorityCommittedState::enrollment(Uuid::from_u128(
            1
        ))))
        .local_recovery_target()
        .is_err()
    );
    let (mut local, _, _) = local_stop::local(true);
    assert!(matches!(
        local.local_recovery_target(),
        Err(AuthorityError::Recovering)
    ));
    local.enter_recovery(true);
    assert!(matches!(
        local.local_recovery_target(),
        Err(AuthorityError::Recovering)
    ));
    let (system, _, _, _) = active(Instant::now());
    let record = serde_json::to_value(system.metadata().unwrap()).unwrap();
    for mode in [AuthorityMode::SystemProxy, AuthorityMode::Tunnel] {
        let mut record = record.clone();
        record["operation"]["mode"] = serde_json::to_value(mode).unwrap();
        let machine = recovered(Some(serde_json::from_value(record).unwrap()));
        assert!(matches!(
            machine.local_recovery_target(),
            Err(AuthorityError::CleanupUnproven)
        ));
    }
}
