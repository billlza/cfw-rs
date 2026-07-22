use std::time::Duration;

use cfw_engine_api::{
    EngineBackend, EngineMode, EngineOwner, EngineSessionIdentity, EngineSnapshot,
    NativeEngineStatus, RuntimeIdentity,
};
use tokio::sync::watch;

use crate::{
    EngineCoordinatorError, EngineOperation,
    coordinator_actor::StartupReconciliation,
    runtime::{
        CoordinatorState, NativeLease, NativeLeaseKind, backend_error, call_backend, publish,
        set_failed, set_off, validate_cleanup_runtime, validate_recovered_runtime,
    },
    transition::stop_owned_runtime,
};

#[derive(Clone)]
pub(crate) struct ReconciliationFailure {
    pub(crate) error: EngineCoordinatorError,
    pub(crate) safely_off: bool,
}

pub(crate) async fn reconcile_initial_state(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    session: &EngineSessionIdentity,
    operation_timeout: Duration,
    startup_reconciliation: StartupReconciliation,
) -> Result<(), ReconciliationFailure> {
    let expected_generation = state.snapshot.generation;
    let status = match call_backend(
        operation_timeout,
        EngineOperation::QueryStatus,
        backend.query_status(),
    )
    .await
    {
        Ok(status) => status,
        Err(source) => {
            let error = backend_error(EngineOperation::QueryStatus, source);
            set_failed(
                state,
                snapshots,
                EngineMode::Off,
                expected_generation,
                &error,
            );
            return Err(ReconciliationFailure {
                error,
                safely_off: false,
            });
        }
    };

    match status {
        NativeEngineStatus::Off => {
            state.snapshot.desired_mode = EngineMode::Off;
            set_off(state, snapshots);
            Ok(())
        }
        NativeEngineStatus::SystemProxy { runtime } => {
            let context = ReconciliationContext {
                backend,
                state,
                snapshots,
                session,
                expected_generation,
                operation_timeout,
            };
            let kind = RecoveredRuntimeKind {
                mode: EngineMode::SystemProxy,
                owner: EngineOwner::ProxyAgent,
                lease_kind: NativeLeaseKind::SystemProxy,
            };
            if matches!(
                startup_reconciliation,
                StartupReconciliation::CleanupWithoutLineage
            ) {
                cleanup_runtime_without_lineage(context, kind, runtime).await
            } else {
                reconcile_runtime(context, kind, runtime).await
            }
        }
        NativeEngineStatus::Tunnel { runtime } => {
            let context = ReconciliationContext {
                backend,
                state,
                snapshots,
                session,
                expected_generation,
                operation_timeout,
            };
            let kind = RecoveredRuntimeKind {
                mode: EngineMode::Tunnel,
                owner: EngineOwner::PacketTunnelSystemExtension,
                lease_kind: NativeLeaseKind::TunnelRuntime,
            };
            if matches!(
                startup_reconciliation,
                StartupReconciliation::CleanupWithoutLineage
            ) {
                cleanup_runtime_without_lineage(context, kind, runtime).await
            } else {
                reconcile_runtime(context, kind, runtime).await
            }
        }
    }
}

async fn cleanup_runtime_without_lineage(
    context: ReconciliationContext<'_>,
    kind: RecoveredRuntimeKind,
    runtime: RuntimeIdentity,
) -> Result<(), ReconciliationFailure> {
    let ReconciliationContext {
        backend,
        state,
        snapshots,
        operation_timeout,
        ..
    } = context;
    let validation_error = validate_cleanup_runtime(&runtime, kind.mode, kind.owner).err();
    state.snapshot.desired_mode = EngineMode::Off;
    state.snapshot.generation = runtime.context.generation;
    state.snapshot.config_digest = Some(runtime.config_digest.clone());
    state.native_lease = Some(NativeLease {
        kind: kind.lease_kind,
        context: runtime.context.clone(),
    });

    let cleanup = stop_owned_runtime(backend, state, snapshots, operation_timeout).await;
    match (validation_error, cleanup) {
        (None, Ok(())) => {
            set_off(state, snapshots);
            Ok(())
        }
        (Some(error), Ok(())) => {
            set_failed(
                state,
                snapshots,
                kind.mode,
                runtime.context.generation,
                &error,
            );
            Err(ReconciliationFailure {
                error,
                safely_off: true,
            })
        }
        (None, Err(error)) => {
            set_failed(
                state,
                snapshots,
                kind.mode,
                runtime.context.generation,
                &error,
            );
            Err(ReconciliationFailure {
                error,
                safely_off: false,
            })
        }
        (Some(validation_error), Err(EngineCoordinatorError::Backend { operation, source })) => {
            let error = EngineCoordinatorError::ValidationAndCleanupFailed {
                validation_error: Box::new(validation_error),
                cleanup_operation: operation,
                cleanup_error: source,
            };
            set_failed(
                state,
                snapshots,
                kind.mode,
                runtime.context.generation,
                &error,
            );
            Err(ReconciliationFailure {
                error,
                safely_off: false,
            })
        }
        (Some(_), Err(unexpected)) => {
            set_failed(
                state,
                snapshots,
                kind.mode,
                runtime.context.generation,
                &unexpected,
            );
            Err(ReconciliationFailure {
                error: unexpected,
                safely_off: false,
            })
        }
    }
}

struct ReconciliationContext<'a> {
    backend: &'a dyn EngineBackend,
    state: &'a mut CoordinatorState,
    snapshots: &'a watch::Sender<EngineSnapshot>,
    session: &'a EngineSessionIdentity,
    expected_generation: u64,
    operation_timeout: Duration,
}

#[derive(Clone, Copy)]
struct RecoveredRuntimeKind {
    mode: EngineMode,
    owner: EngineOwner,
    lease_kind: NativeLeaseKind,
}

async fn reconcile_runtime(
    context: ReconciliationContext<'_>,
    kind: RecoveredRuntimeKind,
    runtime: RuntimeIdentity,
) -> Result<(), ReconciliationFailure> {
    let ReconciliationContext {
        backend,
        state,
        snapshots,
        session,
        expected_generation,
        operation_timeout,
    } = context;
    state.snapshot.desired_mode = kind.mode;
    state.snapshot.generation = runtime.context.generation;
    state.snapshot.config_digest = Some(runtime.config_digest.clone());
    state.native_lease = Some(NativeLease {
        kind: kind.lease_kind,
        context: runtime.context.clone(),
    });

    if let Err(validation_error) = validate_recovered_runtime(
        &runtime,
        kind.mode,
        kind.owner,
        session,
        expected_generation,
    ) {
        let error = match stop_owned_runtime(backend, state, snapshots, operation_timeout).await {
            Ok(()) => validation_error,
            Err(EngineCoordinatorError::Backend { operation, source }) => {
                EngineCoordinatorError::ValidationAndCleanupFailed {
                    validation_error: Box::new(validation_error),
                    cleanup_operation: operation,
                    cleanup_error: source,
                }
            }
            Err(unexpected) => unexpected,
        };
        let safely_off = state.native_lease.is_none();
        set_failed(
            state,
            snapshots,
            kind.mode,
            runtime.context.generation,
            &error,
        );
        return Err(ReconciliationFailure { error, safely_off });
    }

    state.snapshot.state = match kind.mode {
        EngineMode::SystemProxy => cfw_engine_api::EngineState::ProxyActive { runtime },
        EngineMode::Tunnel => cfw_engine_api::EngineState::TunnelActive { runtime },
        EngineMode::Off => unreachable!("native running status cannot be Off"),
    };
    publish(state, snapshots);
    Ok(())
}
