use super::*;

pub(super) fn local(acknowledged: bool) -> (Machine, Peer, LeaseContext) {
    let now = Instant::now();
    let mut machine = off();
    let host = peer(Role::Desktop);
    let runtime = peer(Role::UserAgent);
    let revision = allocate(&mut machine, &host);
    let mut request = input(revision, 1);
    request.mode = AuthorityMode::LocalProxy;
    let ticket = Ticket::for_test([7; 32]);
    let context = machine
        .prepare(&request, &host, Uuid::from_u128(8), ticket.digest(), now)
        .unwrap();
    ticket
        .expose(|bytes| machine.bind(&runtime, &context, bytes, now))
        .unwrap();
    let mut ready = report(&context);
    ready.ready_flags = 3;
    machine.ready(&runtime, &ready, now).unwrap();
    assert!(matches!(
        machine.local_stopped_cleanup_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
    machine
        .begin_stop(&host, &context, machine.revision(), now)
        .unwrap();
    if acknowledged {
        machine
            .stopped(&runtime, &stopped_report(&context), now)
            .unwrap();
    }
    (machine, host, context)
}

#[test]
fn local_stop_requires_live_stop_acknowledgement_and_never_reconstructs_it_from_disk() {
    let (unacknowledged, _, _) = local(false);
    assert!(matches!(
        unacknowledged.local_stopped_cleanup_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
    let (mut stopped, _, _) = local(true);
    let target = stopped.local_stopped_cleanup_target().unwrap();
    let restarted = recovered(Some(target));
    assert!(matches!(
        restarted.local_stopped_cleanup_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
    stopped.enter_recovery(true);
    assert!(matches!(
        stopped.local_stopped_cleanup_target(),
        Err(AuthorityError::Recovering)
    ));
}

#[test]
fn local_cleanup_scope_cannot_release_a_proxy_mode_or_different_operation() {
    let now = Instant::now();
    let (mut system, host, runtime, context) = active(now);
    system
        .begin_stop(&host, &context, system.revision(), now)
        .unwrap();
    system
        .stopped(&runtime, &stopped_report(&context), now)
        .unwrap();
    assert!(matches!(
        system.local_stopped_cleanup_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
    let (mut local, _, context) = local(true);
    let target = local.local_stopped_cleanup_target().unwrap();
    let mut proof =
        CleanupEvidence::for_validation(target.revision(), Some(context.lease_id), true);
    proof.binding = CleanupBinding::LocalRuntime(system.metadata().unwrap().clone());
    assert!(matches!(
        proof.validate_scope(system.metadata()),
        Err(AuthorityError::Stale)
    ));
    proof.binding = CleanupBinding::LocalRuntime(target.clone());
    proof.lease_id = Some(Uuid::from_u128(99));
    assert!(matches!(
        local.reconcile(&proof),
        Err(AuthorityError::Stale)
    ));
    proof.lease_id = Some(context.lease_id);
    let mut altered = serde_json::to_value(&target).unwrap();
    altered["operation"]["identity_sha256"][0] = serde_json::json!(99);
    proof.binding = CleanupBinding::LocalRuntime(serde_json::from_value(altered).unwrap());
    assert!(matches!(
        local.reconcile(&proof),
        Err(AuthorityError::Stale)
    ));
    assert_eq!(local.metadata(), Some(&target));
}

#[test]
fn local_global_off_commits_only_after_complete_scoped_cleanup_evidence() {
    let (mut machine, host, context) = local(true);
    let target = machine.local_stopped_cleanup_target().unwrap();
    let mut proof =
        CleanupEvidence::for_validation(target.revision(), Some(context.lease_id), true);
    proof.binding = CleanupBinding::LocalRuntime(target.clone());
    machine.reconcile(&proof).unwrap();
    assert_eq!(machine.phase(), AuthorityState::Off);
    assert_eq!(machine.revision(), target.revision() + 1);
    assert_eq!(
        machine.metadata().unwrap().transition(),
        JournalTransition::GlobalOff
    );
    assert_eq!(machine.metadata().unwrap().root(), target.root());
    assert!(machine.metadata().unwrap().operation().is_none());
    assert!(machine.lease_for_owner(&host).is_err());
    assert!(machine.reconcile(&proof).is_err());
    let (mut incomplete, _, _) = local(true);
    proof.endpoints_closed = false;
    incomplete.reconcile(&proof).unwrap();
    assert_eq!(incomplete.phase(), AuthorityState::Quarantined);
    assert!(incomplete.metadata().unwrap().operation().is_some());
}
