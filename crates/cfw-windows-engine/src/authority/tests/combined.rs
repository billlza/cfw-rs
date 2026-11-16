//! A run that owns a tunnel and this user's proxy settings. SYSTEM retires
//! the tunnel by itself; the record is released only by the proxy proof of
//! the same account, whose evidence also carries SYSTEM's own observation
//! that the tunnel is gone.
use super::tunnel_stop::{lease, stopping, tunnel, tunnel_ready};
use super::*;
use crate::authority::ProxyRecoveryTarget;

const MODE: RunMode = RunMode::TunnelSystemProxy;
const OTHERS: [RunMode; 3] = [RunMode::LocalProxy, RunMode::SystemProxy, RunMode::Tunnel];

fn proxy_proof(target: &AuthorityCommittedState, lease: Uuid, network: bool) -> CleanupEvidence {
    let mut proof = CleanupEvidence::for_validation(target.revision(), Some(lease), true);
    proof.binding = CleanupBinding::Runtime(ProxyRecoveryTarget {
        root: target.root().clone(),
        revision: target.revision(),
        operation: target.operation().unwrap().clone(),
    });
    proof.tunnel_engine_stopped = network;
    proof.packet_pump_closed = network;
    proof.managed_tunnel_off = network;
    proof
}

#[test]
fn a_combined_run_is_ready_only_with_its_proxy_and_its_pump_bounds() {
    let now = Instant::now();
    let (mut machine, host, runtime, context) = lease(MODE, now);
    // Its routes are asked for before Ready, and by the bound runtime alone.
    machine
        .require_starting_runtime(&runtime, &context)
        .unwrap();
    assert!(matches!(
        machine.require_starting_runtime(&host, &context),
        Err(AuthorityError::Identity)
    ));
    // The report of a proxy run has no pump bounds, and the report of a run
    // without a proxy has two flags: a combined run needs both.
    assert!(machine.ready(&runtime, &report(&context), now).is_err());
    let mut unproxied = tunnel_ready(&context);
    unproxied.ready_flags = 0b011;
    assert!(machine.ready(&runtime, &unproxied, now).is_err());
    assert_eq!(machine.phase(), AuthorityState::Starting);
    machine
        .ready(&runtime, &tunnel_ready(&context), now)
        .unwrap();
    assert_eq!(machine.phase(), AuthorityState::Active);
    assert!(matches!(
        machine.require_starting_runtime(&runtime, &context),
        Err(AuthorityError::Stale)
    ));
}

#[test]
fn a_combined_stop_is_released_by_the_proxy_proof_and_by_no_other_scope() {
    let (unacknowledged, _) = stopping(MODE, false);
    assert!(matches!(
        unacknowledged.stopped_cleanup_target(MODE),
        Err(AuthorityError::CleanupUnproven)
    ));
    let (mut machine, context) = stopping(MODE, true);
    for other in OTHERS {
        assert!(
            matches!(
                machine.stopped_cleanup_target(other),
                Err(AuthorityError::CleanupUnproven)
            ),
            "{other:?}"
        );
    }
    let target = machine.stopped_cleanup_target(MODE).unwrap();
    // SYSTEM's own observations release a Tunnel or a LocalProxy record. A
    // combined record also owns proxy settings that SYSTEM cannot read:
    // neither of those scopes names it.
    for binding in [
        CleanupBinding::TunnelRuntime(target.clone()),
        CleanupBinding::LocalRuntime(target.clone()),
    ] {
        let mut proof =
            CleanupEvidence::for_validation(target.revision(), Some(context.lease_id), true);
        proof.binding = binding;
        assert!(matches!(
            proof.validate_scope(machine.metadata()),
            Err(AuthorityError::Stale)
        ));
    }
    // The proxy proof names it. Without SYSTEM's observation that the tunnel
    // is gone the machine never records Off.
    let mut incomplete = machine.clone();
    let retained = proxy_proof(&target, context.lease_id, false);
    retained.validate_scope(incomplete.metadata()).unwrap();
    assert!(!retained.exact());
    incomplete.reconcile(&retained).unwrap();
    assert_eq!(incomplete.phase(), AuthorityState::Quarantined);
    let proof = proxy_proof(&target, context.lease_id, true);
    proof.validate_scope(machine.metadata()).unwrap();
    machine.reconcile(&proof).unwrap();
    assert_eq!(machine.phase(), AuthorityState::Off);
    assert!(machine.context().is_none());
}

#[test]
fn a_combined_recovery_names_its_own_mode_and_its_proxy_target() {
    let (machine, _) = stopping(MODE, true);
    let target = machine.stopped_cleanup_target(MODE).unwrap();
    let restarted = recovered(Some(target.clone()));
    assert_eq!(restarted.recovery_target(MODE).unwrap(), target);
    for other in OTHERS {
        assert!(
            matches!(
                restarted.recovery_target(other),
                Err(AuthorityError::CleanupUnproven)
            ),
            "{other:?}"
        );
    }
    // A Desktop of the account selects the recorded run for its proxy proof,
    // as it does for a SystemProxy run, and never a run that owns no proxy.
    let selected =
        ProxyRecoveryTarget::from_recorded(&restarted.recorded_runtime_scope().unwrap()).unwrap();
    assert_eq!(selected.operation.mode(), MODE);
    assert_eq!(selected.revision, target.revision());
    let (plain, _) = tunnel(true);
    let plain = recovered(Some(plain.stopped_cleanup_target(RunMode::Tunnel).unwrap()));
    assert!(matches!(
        ProxyRecoveryTarget::from_recorded(&plain.recorded_runtime_scope().unwrap()),
        Err(AuthorityError::Invalid)
    ));
}
