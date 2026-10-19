use super::*;
use crate::{
    authority::{
        secret::Ticket,
        tests::{active, recovered},
    },
    connection_binding::ConnectionBinding,
};
use uuid::Uuid;

fn stopping(
    acknowledged: bool,
) -> (
    Machine,
    Peer,
    Peer,
    LeaseContext,
    ProxyRecoveryTarget,
    Instant,
) {
    let now = Instant::now();
    let (mut machine, host, runtime, context) = active(now);
    machine
        .begin_stop(&host, &context, machine.revision(), now)
        .unwrap();
    if acknowledged {
        machine
            .stopped(
                &runtime,
                &StoppedReport {
                    context: context.clone(),
                    engine_stopped: true,
                    transport_closed: true,
                    os_restored: true,
                    observed_millis: 1,
                },
                now,
            )
            .unwrap();
    }
    let target =
        ProxyRecoveryTarget::from_stopped(&machine.recorded_runtime_scope().unwrap(), &context)
            .unwrap();
    (machine, host, runtime, context, target, now)
}

#[test]
fn normal_proxy_cleanup_requires_acknowledgement_and_the_original_desktop_connection() {
    let (machine, host, _, _, target, now) = stopping(false);
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &machine,
            &host,
            target,
            ProxyRecoveryPurpose::ReconcileOff,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::CleanupUnproven)
    ));
    let (machine, host, runtime, _, target, now) = stopping(true);
    let mut other = host.clone();
    other.connection = ConnectionBinding::new();
    for peer in [other, runtime] {
        assert!(matches!(
            ProxyRecoveryAdmission::new(
                &machine,
                &peer,
                target.clone(),
                ProxyRecoveryPurpose::ReconcileOff,
                Ticket::for_test([9; 32]).recovery_digest(),
                now
            ),
            Err(AuthorityError::Identity)
        ));
    }
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &machine,
            &host,
            target,
            ProxyRecoveryPurpose::Observe,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Recovering)
    ));
}

#[test]
fn acknowledged_stop_expects_owner_exit_but_keeps_cleanup_and_lease_pending() {
    let (live, _, _, _) = active(Instant::now());
    assert!(live.runtime_liveness_required());
    let (unacknowledged, _, _, _, _, _) = stopping(false);
    assert!(unacknowledged.runtime_liveness_required());
    let (acknowledged, host, _, context, _, _) = stopping(true);
    assert!(!acknowledged.runtime_liveness_required());
    assert_eq!(acknowledged.phase(), AuthorityState::Stopping);
    assert_eq!(acknowledged.lease_for_owner(&host).unwrap(), context);
    assert!(acknowledged.metadata().unwrap().operation().is_some());
}

#[test]
fn normal_proxy_cleanup_keeps_the_stopped_binding_until_global_off_commits() {
    let (mut machine, host, _, context, target, now) = stopping(true);
    let pending = ProxyRecoveryAdmission::new(
        &machine,
        &host,
        target.clone(),
        ProxyRecoveryPurpose::ReconcileOff,
        Ticket::for_test([9; 32]).recovery_digest(),
        now,
    )
    .unwrap();
    let challenge = pending.context().clone();
    pending
        .consume(&machine, &host, &challenge, &[9; 32], now)
        .unwrap();
    assert_eq!(machine.lease_for_owner(&host).unwrap(), context);
    assert_eq!(machine.phase(), AuthorityState::Stopping);
    let mut proof = CleanupEvidence::for_validation(target.revision, Some(context.lease_id), true);
    proof.binding = CleanupBinding::Runtime(target.clone());
    machine.reconcile(&proof).unwrap();
    assert_eq!(machine.phase(), AuthorityState::Off);
    assert_eq!(machine.revision(), target.revision + 1);
    assert_eq!(
        machine.metadata().unwrap().transition(),
        crate::authority_journal::JournalTransition::GlobalOff
    );
    assert!(machine.metadata().unwrap().operation().is_none());
    assert!(machine.context().is_none());
    assert!(matches!(
        machine.lease_for_owner(&host),
        Err(AuthorityError::Identity)
    ));
    assert!(matches!(
        machine.reconcile(&proof),
        Err(AuthorityError::Stale)
    ));
}

#[test]
fn normal_stop_selector_cannot_substitute_an_operation_or_crash_recovery() {
    let (machine, _, _, context, _, _) = stopping(true);
    let scope = machine.recorded_runtime_scope().unwrap();
    assert!(matches!(
        ProxyRecoveryTarget::from_recorded(&scope),
        Err(AuthorityError::Recovering)
    ));
    for pointer in [
        "/lease_id",
        "/operation/operation_id",
        "/operation/root/installation_id",
    ] {
        let mut changed = serde_json::to_value(&context).unwrap();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!(Uuid::from_u128(99));
        assert!(matches!(
            ProxyRecoveryTarget::from_stopped(&scope, &serde_json::from_value(changed).unwrap()),
            Err(AuthorityError::Stale)
        ));
    }
    let restarted = recovered(machine.metadata().cloned());
    assert!(matches!(
        ProxyRecoveryTarget::from_stopped(&restarted.recorded_runtime_scope().unwrap(), &context),
        Err(AuthorityError::CleanupUnproven)
    ));
}

#[test]
fn normal_cleanup_revalidates_uncertainty_and_closed_owner_before_consumption() {
    for unknown in [false, true] {
        let (mut machine, host, _, _, target, now) = stopping(true);
        let pending = ProxyRecoveryAdmission::new(
            &machine,
            &host,
            target,
            ProxyRecoveryPurpose::ReconcileOff,
            Ticket::for_test([9; 32]).recovery_digest(),
            now,
        )
        .unwrap();
        let context = pending.context().clone();
        if unknown {
            machine.enter_recovery(true);
        } else {
            host.connection.close();
        }
        let result = pending.consume(&machine, &host, &context, &[9; 32], now);
        if unknown {
            assert!(matches!(result, Err(AuthorityError::Recovering)));
        } else {
            assert!(matches!(result, Err(AuthorityError::Identity)));
        }
    }
}

fn fixture() -> (Machine, Peer, ProxyRecoveryTarget, Instant) {
    let now = Instant::now();
    let (live, mut peer, _, _) = active(now);
    let machine = recovered(live.metadata().cloned());
    // A later interactive logon of the same account, with a new connection.
    let mut value = serde_json::to_value(&peer.owner).unwrap();
    value["authentication_id"] = serde_json::json!(100);
    value["session_id"] = serde_json::json!(3);
    peer.owner = serde_json::from_value(value).unwrap();
    peer.connection = ConnectionBinding::new();
    let target =
        ProxyRecoveryTarget::from_recorded(&machine.recorded_runtime_scope().unwrap()).unwrap();
    (machine, peer, target, now)
}
fn admission(
    machine: &Machine,
    peer: &Peer,
    target: ProxyRecoveryTarget,
    now: Instant,
) -> ProxyRecoveryAdmission {
    ProxyRecoveryAdmission::new(
        machine,
        peer,
        target,
        ProxyRecoveryPurpose::Observe,
        Ticket::for_test([9; 32]).recovery_digest(),
        now,
    )
    .unwrap()
}

#[test]
fn later_logon_can_observe_recovery_without_inheriting_execution() {
    let (mut machine, peer, target, now) = fixture();
    assert_ne!(target.operation.owner(), &peer.owner);
    let pending = admission(&machine, &peer, target.clone(), now);
    let context = pending.context().clone();
    assert_eq!(&context.observer, &peer.owner);
    assert_eq!(&context.target.operation.owner(), &target.operation.owner());
    pending
        .consume(&machine, &peer, &context, &[9; 32], now)
        .unwrap();
    assert!(machine.context().is_none());
    assert_eq!(machine.phase(), AuthorityState::Recovering);
    assert!(matches!(
        machine.reserve_generation(&peer, &machine.lineage().unwrap()),
        Err(AuthorityError::Recovering)
    ));
    assert!(matches!(
        machine.lease_for_owner(&peer),
        Err(AuthorityError::Identity)
    ));
}

#[test]
fn recovery_rejects_other_accounts_roles_and_every_changed_durable_identity() {
    let (machine, peer, target, now) = fixture();
    let mut foreign = peer.clone();
    let mut value = serde_json::to_value(&foreign.owner).unwrap();
    value["sid"][8] = serde_json::json!(22);
    foreign.owner = serde_json::from_value(value).unwrap();
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &machine,
            &foreign,
            target.clone(),
            ProxyRecoveryPurpose::Observe,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Identity)
    ));
    foreign = peer.clone();
    foreign.role = Role::UserAgent;
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &machine,
            &foreign,
            target.clone(),
            ProxyRecoveryPurpose::Observe,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Identity)
    ));
    let original = serde_json::to_value(&target).unwrap();
    for (pointer, replacement) in [
        (
            "/root/installation_id",
            serde_json::json!(Uuid::from_u128(99)),
        ),
        ("/root/epoch", serde_json::json!(2)),
        ("/root/generation", serde_json::json!(2)),
        ("/revision", serde_json::json!(99)),
        (
            "/operation/operation_id",
            serde_json::json!(Uuid::from_u128(99)),
        ),
        (
            "/operation/lease_id",
            serde_json::json!(Uuid::from_u128(99)),
        ),
        ("/operation/config_sha256/0", serde_json::json!(99)),
        ("/operation/identity_sha256/0", serde_json::json!(99)),
        ("/operation/owner/authentication_id", serde_json::json!(101)),
        ("/operation/owner/session_id", serde_json::json!(4)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(
            matches!(
                ProxyRecoveryAdmission::new(
                    &machine,
                    &peer,
                    changed,
                    ProxyRecoveryPurpose::Observe,
                    Ticket::for_test([9; 32]).recovery_digest(),
                    now
                ),
                Err(AuthorityError::Stale)
            ),
            "{pointer}"
        );
    }
    for mode in [AuthorityMode::LocalProxy, AuthorityMode::Tunnel] {
        let mut changed = original.clone();
        changed["operation"]["mode"] = serde_json::to_value(mode).unwrap();
        let target: ProxyRecoveryTarget = serde_json::from_value(changed).unwrap();
        assert!(matches!(target.validate(), Err(AuthorityError::Invalid)));
    }
}

#[test]
fn recovery_challenge_expires_and_cannot_move_to_another_connection() {
    let (machine, peer, target, now) = fixture();
    let pending = admission(&machine, &peer, target.clone(), now);
    let context = pending.context().clone();
    let mut other = peer.clone();
    other.connection = ConnectionBinding::new();
    assert!(!pending.belongs_to(&other));
    assert!(matches!(
        pending.consume(&machine, &other, &context, &[9; 32], now),
        Err(AuthorityError::Identity)
    ));
    let pending = admission(&machine, &peer, target.clone(), now);
    assert!(!pending.available(now + LIFETIME));
    assert!(matches!(
        pending.consume(&machine, &peer, &context, &[9; 32], now + LIFETIME),
        Err(AuthorityError::Expired)
    ));
    let pending = admission(&machine, &peer, target.clone(), now);
    assert!(matches!(
        pending.consume(&machine, &peer, &context, &[8; 32], now),
        Err(AuthorityError::Ticket)
    ));
    let pending = admission(&machine, &peer, target, now);
    peer.connection.close();
    assert!(!pending.available(now));
    assert!(matches!(
        pending.consume(&machine, &peer, &context, &[9; 32], now),
        Err(AuthorityError::Identity)
    ));
}

#[test]
fn active_or_uncertain_journal_cannot_admit_recovery_observation() {
    let (mut machine, peer, target, now) = fixture();
    let (active, _, _, _) = active(now);
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &active,
            &peer,
            target.clone(),
            ProxyRecoveryPurpose::Observe,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Recovering)
    ));
    let pending = admission(&machine, &peer, target.clone(), now);
    let context = pending.context().clone();
    machine.enter_recovery(true);
    assert!(matches!(
        pending.consume(&machine, &peer, &context, &[9; 32], now),
        Err(AuthorityError::Recovering)
    ));
    assert!(matches!(
        ProxyRecoveryAdmission::new(
            &machine,
            &peer,
            target,
            ProxyRecoveryPurpose::Observe,
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Recovering)
    ));
}

#[test]
fn production_cleanup_scope_cannot_be_substituted_or_replayed() {
    let (mut machine, _, target, _) = fixture();
    let mut proof =
        CleanupEvidence::for_validation(target.revision, Some(target.operation.lease_id()), true);
    proof.binding = CleanupBinding::Runtime(target.clone());
    for pointer in ["/root/installation_id", "/operation/operation_id"] {
        let mut changed = serde_json::to_value(&target).unwrap();
        *changed.pointer_mut(pointer).unwrap() = serde_json::json!(Uuid::from_u128(99));
        proof.binding = CleanupBinding::Runtime(serde_json::from_value(changed).unwrap());
        assert!(matches!(
            machine.reconcile(&proof),
            Err(AuthorityError::Stale)
        ));
        assert_eq!(machine.phase(), AuthorityState::Recovering);
    }
    proof.binding = CleanupBinding::Runtime(target);
    machine.reconcile(&proof).unwrap();
    assert_eq!(machine.phase(), AuthorityState::Off);
    assert!(matches!(
        machine.reconcile(&proof),
        Err(AuthorityError::Stale)
    ));
}

#[test]
fn observation_challenge_cannot_be_upgraded_to_cleanup() {
    let (machine, peer, target, now) = fixture();
    let pending = admission(&machine, &peer, target, now);
    let mut context = pending.context().clone();
    context.purpose = ProxyRecoveryPurpose::ReconcileOff;
    assert!(matches!(
        pending.consume(&machine, &peer, &context, &[9; 32], now),
        Err(AuthorityError::Stale)
    ));
}

#[test]
fn every_cleanup_obligation_is_required_before_releasing_the_old_operation() {
    for missing in 0..7 {
        let (mut machine, _, target, _) = fixture();
        let mut proof = CleanupEvidence::for_validation(
            target.revision,
            Some(target.operation.lease_id()),
            true,
        );
        proof.binding = CleanupBinding::Runtime(target.clone());
        match missing {
            0 => proof.proxy_listener_closed = false,
            1 => proof.system_proxy_restored = false,
            2 => proof.tunnel_engine_stopped = false,
            3 => proof.packet_pump_closed = false,
            4 => proof.managed_tunnel_off = false,
            5 => proof.endpoints_closed = false,
            6 => proof.secret_buffers_cleared = false,
            _ => unreachable!(),
        }
        machine.reconcile(&proof).unwrap();
        assert_eq!(
            machine.phase(),
            AuthorityState::Quarantined,
            "missing obligation {missing}"
        );
        assert_eq!(
            machine.metadata().unwrap().operation(),
            Some(&target.operation)
        );
    }
}
