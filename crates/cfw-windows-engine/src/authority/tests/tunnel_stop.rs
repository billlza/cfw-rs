use super::*;

const MTU: u16 = 1500;

fn tunnel_lease(now: Instant) -> (Machine, Peer, Peer, LeaseContext) {
    let mut machine = off();
    let host = peer(Role::Desktop);
    let runtime = peer(Role::UserAgent);
    let revision = allocate(&mut machine, &host);
    let mut request = input(revision, 1);
    request.mode = AuthorityMode::Tunnel;
    let ticket = Ticket::for_test([7; 32]);
    let context = machine
        .prepare(&request, &host, Uuid::from_u128(8), ticket.digest(), now)
        .unwrap();
    ticket
        .expose(|bytes| machine.bind(&runtime, &context, bytes, now))
        .unwrap();
    (machine, host, runtime, context)
}

fn tunnel_ready(context: &LeaseContext) -> ReadyReport {
    let mut ready = report(context);
    ready.packet_pump_limits = Some(crate::tunnel::packet_pump_limits(MTU));
    ready
}

pub(super) fn tunnel(acknowledged: bool) -> (Machine, LeaseContext) {
    let now = Instant::now();
    let (mut machine, host, runtime, context) = tunnel_lease(now);
    machine
        .ready(&runtime, &tunnel_ready(&context), now)
        .unwrap();
    machine
        .begin_stop(&host, &context, machine.revision(), now)
        .unwrap();
    if acknowledged {
        machine
            .stopped(&runtime, &stopped_report(&context), now)
            .unwrap();
    }
    (machine, context)
}

fn evidence(target: &AuthorityCommittedState, lease: Uuid, network: bool) -> CleanupEvidence {
    let mut proof = CleanupEvidence::for_validation(target.revision(), Some(lease), true);
    proof.binding = CleanupBinding::TunnelRuntime(target.clone());
    proof.packet_pump_closed = network;
    proof.managed_tunnel_off = network;
    proof
}

#[test]
fn tunnel_endpoint_commands_admit_only_the_bound_user_agent_before_ready() {
    let now = Instant::now();
    let (mut machine, host, runtime, context) = tunnel_lease(now);
    machine
        .require_starting_runtime(&runtime, &context)
        .unwrap();
    assert!(matches!(
        machine.require_starting_runtime(&host, &context),
        Err(AuthorityError::Identity)
    ));
    // Same account and role on another connection is not the bound runtime.
    assert!(matches!(
        machine.require_starting_runtime(&peer(Role::UserAgent), &context),
        Err(AuthorityError::Identity)
    ));
    let mut other = context.clone();
    other.lease_id = Uuid::from_u128(99);
    assert!(matches!(
        machine.require_starting_runtime(&runtime, &other),
        Err(AuthorityError::Stale)
    ));
    machine
        .ready(&runtime, &tunnel_ready(&context), now)
        .unwrap();
    assert!(matches!(
        machine.require_starting_runtime(&runtime, &context),
        Err(AuthorityError::Stale)
    ));
}

#[test]
fn tunnel_ready_attests_the_windows_pump_bounds_within_the_wire_limits() {
    use cfw_engine_api::authority_v1::WireValidate;
    for mtu in [
        *crate::tunnel::HANDOFF_MTU.start(),
        MTU,
        *crate::tunnel::HANDOFF_MTU.end(),
    ] {
        let limits = crate::tunnel::packet_pump_limits(mtu);
        limits.validate().unwrap();
        assert_eq!(limits.maximum_packet_bytes, mtu);
        assert_eq!(limits.maximum_queued_packets, 2);
        assert_eq!(limits.maximum_queued_bytes, 2 * u32::from(mtu));
        assert_eq!(limits.maximum_read_batch, 1);
    }
}

#[test]
fn tunnel_stop_reconciles_only_with_retired_network_and_its_own_scope() {
    let (unacknowledged, _) = tunnel(false);
    assert!(matches!(
        unacknowledged.stopped_cleanup_target(AuthorityMode::Tunnel),
        Err(AuthorityError::CleanupUnproven)
    ));
    let (mut machine, context) = tunnel(true);
    assert!(matches!(
        machine.local_stopped_cleanup_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
    let target = machine
        .stopped_cleanup_target(AuthorityMode::Tunnel)
        .unwrap();
    // A LocalProxy proof cannot release a Tunnel record.
    let mut local = evidence(&target, context.lease_id, true);
    local.binding = CleanupBinding::LocalRuntime(target.clone());
    assert!(matches!(
        local.validate_scope(machine.metadata()),
        Err(AuthorityError::Stale)
    ));
    // Neither can a Tunnel proof for another record.
    let (local_machine, _, _) = super::local_stop::local(true);
    let local_target = local_machine.local_stopped_cleanup_target().unwrap();
    assert!(matches!(
        evidence(&local_target, context.lease_id, true).validate_scope(local_machine.metadata()),
        Err(AuthorityError::Stale)
    ));
    // An adapter still present keeps the run quarantined, never Off.
    let mut incomplete = machine.clone();
    let retained = evidence(&target, context.lease_id, false);
    retained.validate_scope(incomplete.metadata()).unwrap();
    incomplete.reconcile(&retained).unwrap();
    assert_eq!(incomplete.phase(), AuthorityState::Quarantined);
    let proof = evidence(&target, context.lease_id, true);
    proof.validate_scope(machine.metadata()).unwrap();
    machine.reconcile(&proof).unwrap();
    assert_eq!(machine.phase(), AuthorityState::Off);
    assert!(machine.context().is_none());
}

#[test]
fn tunnel_recovery_uses_the_recorded_run_and_never_another_mode() {
    let (machine, _) = tunnel(true);
    let target = machine
        .stopped_cleanup_target(AuthorityMode::Tunnel)
        .unwrap();
    let restarted = recovered(Some(target.clone()));
    assert_eq!(
        restarted.recovery_target(AuthorityMode::Tunnel).unwrap(),
        target
    );
    assert!(matches!(
        restarted.recovery_target(AuthorityMode::LocalProxy),
        Err(AuthorityError::CleanupUnproven)
    ));
    assert!(matches!(
        restarted.local_recovery_target(),
        Err(AuthorityError::CleanupUnproven)
    ));
}
