use super::*;
use crate::{
    authority::{
        secret::Ticket,
        tests::{active, recovered},
    },
    connection_binding::ConnectionBinding,
};
use uuid::Uuid;

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
            Ticket::for_test([9; 32]).recovery_digest(),
            now
        ),
        Err(AuthorityError::Recovering)
    ));
}
