use super::{
    machine::{Machine, TimerAction},
    secret::Ticket,
    types::*,
    *,
};
use crate::{
    authority_journal::{
        AuthorityCommittedState, JournalCursor, JournalRecovery, JournalTransition, RecordedOwner,
        RecoveryAction,
    },
    connection_binding::ConnectionBinding,
};
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, PacketPumpLimits, RootContext};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn owner() -> RecordedOwner {
    serde_json::from_value(
        serde_json::json!({"sid":[1,1,0,0,0,0,0,5,21,0,0,0],"authentication_id":99,"session_id":2}),
    )
    .unwrap()
}
fn peer(role: Role) -> Peer {
    Peer {
        owner: owner(),
        connection: ConnectionBinding::new(),
        role,
    }
}
pub(super) fn recovered(state: Option<AuthorityCommittedState>) -> Machine {
    let action = state.as_ref().map_or(RecoveryAction::VerifyOff, |value| {
        value.restart_action().unwrap()
    });
    let cursor = state
        .as_ref()
        .map(|value| JournalCursor::new(1, 1, 1000, [1; 32], value.revision()).unwrap());
    Machine::recovering(JournalRecovery {
        committed: state,
        cursor,
        action,
    })
    .unwrap()
}
fn off() -> Machine {
    let mut value = recovered(None);
    value
        .reconcile(&CleanupEvidence::for_validation(1, None, true))
        .unwrap();
    value.enroll(Uuid::from_u128(1)).unwrap();
    value
}
fn input(revision: u64, generation: u64) -> PrepareRequest {
    PrepareRequest {
        root: RootContext {
            installation_id: Uuid::from_u128(1),
            epoch: 1,
            generation,
        },
        operation_id: Uuid::from_u128(2),
        mode: AuthorityMode::SystemProxy,
        config_sha256: [3; 32],
        identity_sha256: [4; 32],
        expected_revision: revision,
    }
}
fn allocate(value: &mut Machine, host: &Peer) -> u64 {
    let expected = value.lineage().unwrap();
    value.reserve_generation(host, &expected).unwrap();
    value.revision()
}
fn prepared(now: Instant) -> (Machine, Peer, Peer, LeaseContext, Ticket) {
    let mut value = off();
    let host = peer(Role::Desktop);
    let runtime = peer(Role::UserAgent);
    let revision = allocate(&mut value, &host);
    let ticket = Ticket::for_test([7; 32]);
    let context = value
        .prepare(
            &input(revision, 1),
            &host,
            Uuid::from_u128(8),
            ticket.digest(),
            now,
        )
        .unwrap();
    (value, host, runtime, context, ticket)
}
fn report(context: &LeaseContext) -> ReadyReport {
    ReadyReport {
        context: context.clone(),
        runtime_digest: context.operation.identity_sha256,
        ready_flags: 0b111,
        packet_pump_limits: None,
        observed_millis: 1,
    }
}
pub(super) fn active(now: Instant) -> (Machine, Peer, Peer, LeaseContext) {
    let (mut value, host, runtime, context, ticket) = prepared(now);
    ticket
        .expose(|bytes| value.bind(&runtime, &context, bytes, now))
        .unwrap();
    value.ready(&runtime, &report(&context), now).unwrap();
    (value, host, runtime, context)
}
fn stopped_report(context: &LeaseContext) -> StoppedReport {
    StoppedReport {
        context: context.clone(),
        engine_stopped: true,
        transport_closed: true,
        os_restored: true,
        observed_millis: 1,
    }
}

#[test]
fn recovery_and_incomplete_cleanup_never_bootstrap_permission() {
    let mut value = recovered(None);
    let host = peer(Role::Desktop);
    let token = Ticket::for_test([1; 32]);
    assert!(matches!(
        value.prepare(
            &input(1, 1),
            &host,
            Uuid::from_u128(8),
            token.digest(),
            Instant::now()
        ),
        Err(AuthorityError::Recovering)
    ));
    value
        .reconcile(&CleanupEvidence::for_validation(1, None, false))
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Quarantined);
    assert!(matches!(
        value.prepare(
            &input(1, 1),
            &host,
            Uuid::from_u128(8),
            token.digest(),
            Instant::now()
        ),
        Err(AuthorityError::Quarantined)
    ));
    value
        .reconcile(&CleanupEvidence::for_validation(1, None, true))
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Off);
    assert_eq!(value.revision(), 1);
    assert!(value.metadata().is_none());
    let genesis = AuthorityCommittedState::enrollment(Uuid::from_u128(1));
    let mut restarted = recovered(Some(genesis));
    assert_eq!(restarted.phase(), AuthorityState::Recovering);
    restarted
        .reconcile(&CleanupEvidence::for_validation(1, None, true))
        .unwrap();
    assert_eq!(restarted.phase(), AuthorityState::Off);
}

#[test]
fn preparation_has_a_closed_revision_installation_and_generation_domain() {
    let mut value = off();
    let host = peer(Role::Desktop);
    let revision = allocate(&mut value, &host);
    let token = Ticket::for_test([1; 32]);
    let now = Instant::now();
    for request in [
        PrepareRequest {
            expected_revision: revision + 1,
            ..input(revision, 1)
        },
        PrepareRequest {
            root: RootContext {
                installation_id: Uuid::from_u128(9),
                ..input(revision, 1).root
            },
            ..input(revision, 1)
        },
        PrepareRequest {
            operation_id: Uuid::nil(),
            ..input(revision, 1)
        },
        input(revision, 0),
    ] {
        let mut candidate = value.clone();
        assert!(
            candidate
                .prepare(&request, &host, Uuid::from_u128(8), token.digest(), now)
                .is_err()
        );
        assert_eq!(candidate.snapshot(), value.snapshot());
        assert_eq!(candidate.metadata(), value.metadata());
    }
    let mut candidate = value.clone();
    assert!(matches!(
        candidate.prepare(
            &input(revision, 1),
            &peer(Role::UserAgent),
            Uuid::from_u128(8),
            token.digest(),
            now
        ),
        Err(AuthorityError::Identity)
    ));
    let context = candidate
        .prepare(
            &input(revision, 1),
            &host,
            Uuid::from_u128(8),
            token.digest(),
            now,
        )
        .unwrap();
    assert_eq!(context.operation.owner, host.owner);
    assert_eq!(context.operation.prepared_revision, revision + 1);
    assert!(matches!(
        candidate.prepare(
            &input(revision + 1, 2),
            &host,
            Uuid::from_u128(10),
            token.digest(),
            now
        ),
        Err(AuthorityError::LeaseConflict)
    ));
}

#[test]
fn ticket_is_single_use_and_cannot_change_account_logon_session_or_runtime_role() {
    let now = Instant::now();
    let (mut value, host, runtime, context, ticket) = prepared(now);
    assert!(matches!(
        value.bind(&host, &context, &[7; 32], now),
        Err(AuthorityError::Identity)
    ));
    for key in ["authentication_id", "session_id"] {
        let mut foreign = runtime.clone();
        let mut claim = serde_json::to_value(&foreign.owner).unwrap();
        claim[key] = serde_json::json!(333);
        foreign.owner = serde_json::from_value(claim).unwrap();
        assert!(matches!(
            value.bind(&foreign, &context, &[7; 32], now),
            Err(AuthorityError::Identity)
        ));
    }
    let mut foreign = runtime.clone();
    let mut claim = serde_json::to_value(&foreign.owner).unwrap();
    claim["sid"][8] = serde_json::json!(22);
    foreign.owner = serde_json::from_value(claim).unwrap();
    assert!(matches!(
        value.bind(&foreign, &context, &[7; 32], now),
        Err(AuthorityError::Identity)
    ));
    assert!(matches!(
        value.bind(&runtime, &context, &[7; 31], now),
        Err(AuthorityError::Ticket)
    ));
    for index in 0..32 {
        let mut bad = [7; 32];
        bad[index] ^= 1;
        assert!(matches!(
            value.bind(&runtime, &context, &bad, now),
            Err(AuthorityError::Ticket)
        ));
    }
    ticket
        .expose(|bytes| value.bind(&runtime, &context, bytes, now))
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Starting);
    assert!(matches!(
        ticket.expose(|bytes| value.bind(&runtime, &context, bytes, now)),
        Err(AuthorityError::Ticket)
    ));
}

#[test]
fn new_connections_of_the_same_user_cannot_inherit_views_or_commands() {
    let now = Instant::now();
    let (mut value, host, runtime, context) = active(now);
    let new_host = peer(Role::Desktop);
    let new_runtime = peer(Role::UserAgent);
    assert!(value.lease_for_owner(&new_host).is_err());
    assert!(value.lease_for_owner(&new_runtime).is_err());
    assert!(value.begin_stop(&new_host, &context, 5, now).is_err());
    assert!(value.heartbeat(&new_runtime, &context, now).is_err());
    assert_eq!(value.lease_for_owner(&host).unwrap(), context);
    assert_eq!(value.lease_for_owner(&runtime).unwrap(), context);
    host.connection.close();
    assert!(value.lease_for_owner(&host).is_err());
    assert!(value.timer_action(now).unwrap() == TimerAction::Revoke);
}

#[test]
fn readiness_is_exact_and_only_identical_replay_is_idempotent() {
    let now = Instant::now();
    let (mut value, _, runtime, context, ticket) = prepared(now);
    ticket
        .expose(|bytes| value.bind(&runtime, &context, bytes, now))
        .unwrap();
    let good = report(&context);
    let mut bad = good.clone();
    bad.runtime_digest[0] ^= 1;
    assert!(value.ready(&runtime, &bad, now).is_err());
    bad = good.clone();
    bad.ready_flags |= 0x80;
    assert!(value.ready(&runtime, &bad, now).is_err());
    bad = good.clone();
    bad.observed_millis = 0;
    assert!(value.ready(&runtime, &bad, now).is_err());
    value.ready(&runtime, &good, now).unwrap();
    assert_eq!(value.revision(), 5);
    value.ready(&runtime, &good, now).unwrap();
    assert_eq!(value.revision(), 5);
    bad = good.clone();
    bad.observed_millis = 2;
    assert!(value.ready(&runtime, &bad, now).is_err());
    assert_eq!(value.revision(), 5);
}

#[test]
fn tunnel_policy_needs_a_distinct_worker_and_bounded_packet_evidence() {
    let now = Instant::now();
    let mut value = off();
    let host = peer(Role::Desktop);
    let revision = allocate(&mut value, &host);
    let worker = peer(Role::TunnelWorker);
    let token = Ticket::for_test([7; 32]);
    let context = value
        .prepare(
            &PrepareRequest {
                mode: AuthorityMode::Tunnel,
                ..input(revision, 1)
            },
            &host,
            Uuid::from_u128(8),
            token.digest(),
            now,
        )
        .unwrap();
    assert!(
        value
            .bind(&peer(Role::UserAgent), &context, &[7; 32], now)
            .is_err()
    );
    value.bind(&worker, &context, &[7; 32], now).unwrap();
    let mut ready = report(&context);
    assert!(value.ready(&worker, &ready, now).is_err());
    ready.packet_pump_limits = Some(PacketPumpLimits {
        maximum_packet_bytes: 1500,
        maximum_queued_bytes: 1024 * 1024,
        maximum_queued_packets: 1024,
        maximum_read_batch: 64,
    });
    value.ready(&worker, &ready, now).unwrap();
    assert_eq!(value.phase(), AuthorityState::Active);
}

#[test]
fn stop_replays_do_not_reactivate_or_extend_its_independent_deadline() {
    let now = Instant::now();
    let (mut value, host, runtime, context) = active(now);
    value.begin_stop(&host, &context, 5, now).unwrap();
    assert_eq!(value.revision(), 6);
    value.begin_stop(&host, &context, 5, now).unwrap();
    value.begin_stop(&host, &context, 6, now).unwrap();
    assert_eq!(value.revision(), 6);
    assert!(value.begin_stop(&host, &context, 4, now).is_err());
    assert!(value.ready(&runtime, &report(&context), now).is_err());
    value
        .heartbeat(&runtime, &context, now + Duration::from_secs(4))
        .unwrap();
    assert!(value.timer_action(now + Duration::from_secs(5)).unwrap() == TimerAction::Quarantine);
    value.quarantine_expired_stop().unwrap();
    let before = value.snapshot();
    value.revoke(false, now + Duration::from_secs(6)).unwrap();
    assert_eq!(value.snapshot(), before);
    assert_eq!(value.phase(), AuthorityState::Quarantined);
}

#[test]
fn spontaneous_owner_stop_still_requires_independent_scope_bound_cleanup() {
    let now = Instant::now();
    let (mut value, _, runtime, context) = active(now);
    let mut bad = stopped_report(&context);
    bad.os_restored = false;
    assert!(value.stopped(&runtime, &bad, now).is_err());
    value
        .stopped(&runtime, &stopped_report(&context), now)
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Stopping);
    assert_eq!(value.revision(), 6);
    value
        .stopped(&runtime, &stopped_report(&context), now)
        .unwrap();
    assert_eq!(value.revision(), 6);
    assert!(
        value
            .reconcile(&CleanupEvidence::for_validation(
                6,
                Some(Uuid::from_u128(999)),
                true
            ))
            .is_err()
    );
    value
        .reconcile(&CleanupEvidence::for_validation(
            6,
            Some(context.lease_id),
            false,
        ))
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Quarantined);
    assert_eq!(value.revision(), 7);
    assert!(
        value
            .reconcile(&CleanupEvidence::for_validation(
                6,
                Some(context.lease_id),
                true
            ))
            .is_err()
    );
    value
        .reconcile(&CleanupEvidence::for_validation(
            7,
            Some(context.lease_id),
            true,
        ))
        .unwrap();
    assert_eq!(value.phase(), AuthorityState::Off);
    assert_eq!(value.revision(), 8);
    assert!(value.context().is_none());
    let host = peer(Role::Desktop);
    let token = Ticket::for_test([1; 32]);
    assert!(
        value
            .prepare(
                &input(8, 1),
                &host,
                Uuid::from_u128(18),
                token.digest(),
                now
            )
            .is_err()
    );
    allocate(&mut value, &host);
    value
        .prepare(
            &input(9, 2),
            &host,
            Uuid::from_u128(18),
            token.digest(),
            now,
        )
        .unwrap();
}

#[test]
fn unclaimed_preparation_can_finish_but_its_disk_record_restores_no_proof() {
    let now = Instant::now();
    let (mut value, _, runtime, context, ticket) = prepared(now);
    let expires = now + Duration::from_secs(10);
    assert!(value.timer_action(expires).unwrap() == TimerAction::AbortUnbound);
    assert!(matches!(
        ticket.expose(|bytes| value.bind(&runtime, &context, bytes, expires)),
        Err(AuthorityError::Expired)
    ));
    value.abort_prepared(None, 3, expires).unwrap();
    let abort = value.metadata().unwrap().clone();
    assert_eq!(abort.transition(), JournalTransition::AbortPrepared);
    let mut restarted = recovered(Some(abort));
    assert_eq!(restarted.phase(), AuthorityState::Recovering);
    assert!(restarted.finish_unbound_abort().is_err());
    value.finish_unbound_abort().unwrap();
    assert_eq!(value.phase(), AuthorityState::Off);
    assert_eq!(value.revision(), 5);
    assert!(value.context().is_none());
}

#[test]
fn uncertainty_erases_live_authorization_and_never_relabels_an_old_revision_current() {
    let now = Instant::now();
    let (mut value, host, runtime, context, ticket) = prepared(now);
    let metadata = value.metadata().unwrap().clone();
    assert!(value.durable_known());
    value.enter_recovery(true);
    assert!(!value.durable_known());
    assert_eq!(value.snapshot().revision, None);
    assert!(value.snapshot().root.is_none());
    assert!(value.lease_for_owner(&host).is_err());
    assert!(
        ticket
            .expose(|bytes| value.bind(&runtime, &context, bytes, now))
            .is_err()
    );
    value.enter_recovery(false);
    assert_eq!(value.snapshot().revision, None);
    let restarted = recovered(Some(metadata));
    assert!(restarted.durable_known());
    assert_eq!(restarted.snapshot().revision, Some(3));
    assert_eq!(restarted.phase(), AuthorityState::Recovering);
    assert!(restarted.context().is_none());
}

#[test]
fn only_the_bound_runtime_can_renew_liveness_and_a_clock_regression_is_an_error() {
    let now = Instant::now();
    let (mut value, host, runtime, context) = active(now);
    assert!(value.heartbeat(&host, &context, now).is_err());
    assert!(
        value
            .heartbeat(&runtime, &context, now - Duration::from_secs(1))
            .is_err()
    );
    value
        .heartbeat(&runtime, &context, now + Duration::from_secs(1))
        .unwrap();
    assert!(value.timer_action(now + Duration::from_secs(5)).unwrap() == TimerAction::None);
    assert!(value.timer_action(now + Duration::from_secs(6)).unwrap() == TimerAction::Revoke);
    value.revoke(true, now + Duration::from_secs(6)).unwrap();
    assert_eq!(value.phase(), AuthorityState::Stopping);
    assert_eq!(
        value.metadata().unwrap().transition(),
        JournalTransition::RevokeForConsoleChange
    );
    assert!(
        value
            .ready(&runtime, &report(&context), now + Duration::from_secs(6))
            .is_err()
    );
}

#[test]
fn system_lineage_enrollment_and_global_cas_do_not_bootstrap_runtime_permission() {
    let mut value = recovered(None);
    value.enroll(Uuid::from_u128(1)).unwrap();
    let first = value.lineage().unwrap();
    assert_eq!(first.generation, 0);
    assert_eq!(first.config_epoch, 1);
    assert_eq!(value.phase(), AuthorityState::Recovering);
    let host = peer(Role::Desktop);
    assert!(matches!(
        value.reserve_generation(&host, &first),
        Err(AuthorityError::Recovering)
    ));
    value
        .reconcile(&CleanupEvidence::for_validation(1, None, true))
        .unwrap();
    let next = value.reserve_generation(&host, &first).unwrap();
    assert_eq!(next.generation, 1);
    assert_eq!(value.phase(), AuthorityState::Off);
    assert!(value.context().is_none());
    let before = value.snapshot();
    assert!(matches!(
        value.reserve_generation(&host, &first),
        Err(AuthorityError::Stale)
    ));
    assert!(matches!(
        value.reserve_generation(&peer(Role::UserAgent), &next),
        Err(AuthorityError::Identity)
    ));
    assert_eq!(value.snapshot(), before);
    // Different recorded accounts share the allocator. Native admission still
    // separately decides which actual console principal may call this policy.
    let mut another = peer(Role::Desktop);
    let mut claim = serde_json::to_value(&another.owner).unwrap();
    claim["sid"][8] = serde_json::json!(22);
    claim["authentication_id"] = serde_json::json!(100);
    another.owner = serde_json::from_value(claim).unwrap();
    let second = value.reserve_generation(&another, &next).unwrap();
    assert_eq!(second.installation_id, first.installation_id);
    assert_eq!(second.generation, 2);
    assert!(value.context().is_none());
}

#[test]
fn unallocated_consumed_or_superseded_generations_cannot_prepare() {
    let mut value = off();
    let host = peer(Role::Desktop);
    let token = Ticket::for_test([7; 32]);
    let now = Instant::now();
    assert!(matches!(
        value.prepare(&input(1, 1), &host, Uuid::from_u128(8), token.digest(), now),
        Err(AuthorityError::Replay)
    ));
    allocate(&mut value, &host);
    let revision = allocate(&mut value, &host);
    for generation in [1, 3] {
        assert!(matches!(
            value.prepare(
                &input(revision, generation),
                &host,
                Uuid::from_u128(8),
                token.digest(),
                now
            ),
            Err(AuthorityError::Replay)
        ));
    }
    let context = value
        .prepare(
            &input(revision, 2),
            &host,
            Uuid::from_u128(8),
            token.digest(),
            now,
        )
        .unwrap();
    value
        .abort_prepared(Some(&host), context.operation.prepared_revision, now)
        .unwrap();
    value.finish_unbound_abort().unwrap();
    assert!(matches!(
        value.prepare(
            &input(value.revision(), 2),
            &host,
            Uuid::from_u128(9),
            token.digest(),
            now
        ),
        Err(AuthorityError::Replay)
    ));
    allocate(&mut value, &host);
    let checkpoint = value.metadata().unwrap().checkpoint().unwrap();
    let mut restarted = recovered(Some(checkpoint));
    assert_eq!(restarted.lineage().unwrap().generation, 3);
    let revision = restarted.revision();
    restarted
        .reconcile(&CleanupEvidence::for_validation(revision, None, false))
        .unwrap();
    assert_eq!(restarted.phase(), AuthorityState::Quarantined);
    assert_eq!(restarted.metadata().unwrap().allocated_generation(), 3);
    let revision = restarted.revision();
    restarted
        .reconcile(&CleanupEvidence::for_validation(revision, None, true))
        .unwrap();
    assert_eq!(restarted.lineage().unwrap().generation, 3);
    assert_eq!(
        restarted
            .reserve_generation(&host, &restarted.lineage().unwrap())
            .unwrap()
            .generation,
        4
    );
}

#[test]
fn generation_allocation_cannot_change_an_active_lease_or_recover_unknown_publication() {
    let (mut value, host, _, context) = active(Instant::now());
    let before = value.snapshot();
    let lineage = value.lineage().unwrap();
    assert!(matches!(
        value.reserve_generation(&host, &lineage),
        Err(AuthorityError::LeaseConflict)
    ));
    assert_eq!(value.snapshot(), before);
    assert_eq!(value.context(), Some(&context));
    value.enter_recovery(true);
    assert!(matches!(value.lineage(), Err(AuthorityError::Recovering)));
    assert!(matches!(
        value.reserve_generation(&host, &lineage),
        Err(AuthorityError::Recovering)
    ));
    assert_eq!(value.snapshot().revision, None);
}

#[test]
fn generation_exhaustion_preserves_the_committed_installation_and_counter() {
    let mut document =
        serde_json::to_value(AuthorityCommittedState::enrollment(Uuid::from_u128(1))).unwrap();
    document["revision"] = serde_json::json!(2);
    document["transition"] = serde_json::json!("reserve_generation");
    document["allocated_generation"] = serde_json::json!(u64::MAX);
    let state: AuthorityCommittedState = serde_json::from_value(document).unwrap();
    let mut value = recovered(Some(state));
    value
        .reconcile(&CleanupEvidence::for_validation(2, None, true))
        .unwrap();
    let before = value.metadata().cloned();
    assert!(matches!(
        value.reserve_generation(&peer(Role::Desktop), &value.lineage().unwrap()),
        Err(AuthorityError::GenerationExhausted)
    ));
    assert_eq!(value.metadata().cloned(), before);
}

#[test]
fn recorded_scope_preserves_complete_configuration_identity_without_restoring_a_lease() {
    let (mut value, host, _, context) = active(Instant::now());
    let scope = value.recorded_runtime_scope().unwrap();
    assert_eq!(scope.snapshot().state, AuthorityState::Active);
    let operation = scope.operation().unwrap();
    assert_eq!(operation.config_sha256(), &context.operation.config_sha256);
    assert_eq!(
        operation.identity_sha256(),
        &context.operation.identity_sha256
    );
    assert_ne!(operation.config_sha256(), operation.identity_sha256());
    assert_eq!(operation.lease_id(), context.lease_id);
    let checkpoint = value.metadata().unwrap().checkpoint().unwrap();
    let restarted = recovered(Some(checkpoint));
    let recovered_scope = restarted.recorded_runtime_scope().unwrap();
    assert_eq!(recovered_scope.snapshot().state, AuthorityState::Recovering);
    assert_eq!(recovered_scope.operation(), scope.operation());
    assert!(restarted.lease_for_owner(&host).is_err());
    assert!(restarted.lease_for_owner(&peer(Role::Desktop)).is_err());
    value.enter_recovery(true);
    assert!(matches!(
        value.recorded_runtime_scope(),
        Err(AuthorityError::Recovering)
    ));
}

#[test]
fn an_empty_recorded_scope_keeps_recovery_distinct_from_off() {
    let fresh = recovered(Some(AuthorityCommittedState::enrollment(Uuid::from_u128(
        1,
    ))));
    let recovering = fresh.recorded_runtime_scope().unwrap();
    assert!(recovering.operation().is_none());
    assert_eq!(recovering.snapshot().state, AuthorityState::Recovering);
    let stopped = off().recorded_runtime_scope().unwrap();
    assert!(stopped.operation().is_none());
    assert_eq!(stopped.snapshot().state, AuthorityState::Off);
    assert!(matches!(
        recovered(None).recorded_runtime_scope(),
        Err(AuthorityError::Recovering)
    ));
}
