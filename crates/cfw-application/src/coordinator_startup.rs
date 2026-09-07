use std::time::Duration;

use cfw_engine_api::{
    EngineBackend, EngineMode, EngineOwner, EngineSessionIdentity, EngineSnapshot,
    NativeEngineStatus, RetryDirective, RuntimeIdentity,
};
use tokio::sync::watch;

use crate::{
    EngineCoordinatorError, EngineOperation,
    coordinator_actor::StartupReconciliation,
    runtime::{
        CoordinatorState, NativeLease, NativeLeaseKind, backend_error, call_backend,
        prove_global_off, set_failed, set_off, validate_cleanup_runtime,
        validate_recovered_runtime,
    },
    transition::stop_owned_runtime,
};

#[derive(Clone)]
pub(crate) struct ReconciliationFailure {
    pub(crate) error: EngineCoordinatorError,
    pub(crate) safely_off: bool,
}

impl ReconciliationFailure {
    /// A failed startup observation may be repeated only at a later explicit
    /// command boundary and only when the typed backend contract says that a
    /// fresh read or an external registration-state change can resolve it.
    /// Failures after cleanup, identity validation, or mutation remain terminal
    /// because repeating those operations could target ambiguous native state.
    pub(crate) fn allows_explicit_retry(&self) -> bool {
        let EngineCoordinatorError::Backend {
            operation: EngineOperation::QueryStatus,
            source,
        } = &self.error
        else {
            return false;
        };
        matches!(
            source.kind.retry_directive(),
            RetryDirective::IdempotentReadOnly | RetryDirective::RegistrationStatusChange
        )
    }
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
                cleanup_recovered_runtime(context, kind, runtime).await
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
                cleanup_recovered_runtime(context, kind, runtime).await
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
    let off_proof = match &cleanup {
        Ok(()) => Some(prove_global_off(backend, state, snapshots, operation_timeout).await),
        Err(_) => None,
    };
    match (validation_error, cleanup, off_proof) {
        (None, Ok(()), Some(Ok(()))) => {
            set_off(state, snapshots);
            Ok(())
        }
        (Some(error), Ok(()), Some(Ok(()))) => {
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
        (None, Ok(()), Some(Err(error))) => Err(ReconciliationFailure {
            error,
            safely_off: false,
        }),
        (Some(validation_error), Ok(()), Some(Err(proof_error))) => {
            let error = EngineCoordinatorError::ValidationAndOffProofFailed {
                validation_error: Box::new(validation_error),
                proof_error: Box::new(proof_error),
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
        (None, Err(error), None) => {
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
        (
            Some(validation_error),
            Err(EngineCoordinatorError::Backend { operation, source }),
            None,
        ) => {
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
        (Some(_), Err(unexpected), None) => {
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
        (_, Ok(()), None) | (_, Err(_), Some(_)) => {
            unreachable!("Off proof runs exactly once after a successful cleanup")
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

/// A controller capability is scoped to one Host process. Even when the native
/// runtime matches the durable generation lineage exactly, a replacement Host
/// cannot authenticate to that runtime's loopback controller. Startup therefore
/// tears the exact owner down and settles at Off; a later user request starts a
/// fresh generation with this process's capability.
async fn cleanup_recovered_runtime(
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
    state.snapshot.desired_mode = EngineMode::Off;
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
        let (error, safely_off) =
            match stop_owned_runtime(backend, state, snapshots, operation_timeout).await {
                Ok(()) => {
                    match prove_global_off(backend, state, snapshots, operation_timeout).await {
                        Ok(()) => (validation_error, true),
                        Err(proof_error) => (
                            EngineCoordinatorError::ValidationAndOffProofFailed {
                                validation_error: Box::new(validation_error),
                                proof_error: Box::new(proof_error),
                            },
                            false,
                        ),
                    }
                }
                Err(EngineCoordinatorError::Backend { operation, source }) => (
                    EngineCoordinatorError::ValidationAndCleanupFailed {
                        validation_error: Box::new(validation_error),
                        cleanup_operation: operation,
                        cleanup_error: source,
                    },
                    false,
                ),
                Err(unexpected) => (unexpected, false),
            };
        set_failed(
            state,
            snapshots,
            kind.mode,
            runtime.context.generation,
            &error,
        );
        return Err(ReconciliationFailure { error, safely_off });
    }

    match stop_owned_runtime(backend, state, snapshots, operation_timeout).await {
        Ok(()) => match prove_global_off(backend, state, snapshots, operation_timeout).await {
            Ok(()) => {
                set_off(state, snapshots);
                Ok(())
            }
            Err(error) => Err(ReconciliationFailure {
                error,
                safely_off: false,
            }),
        },
        Err(error) => {
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
    }
}
