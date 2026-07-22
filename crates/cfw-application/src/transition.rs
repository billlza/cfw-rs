use std::time::Duration;

use cfw_engine_api::{
    BackendError, EngineBackend, EngineCommandContext, EngineGenerationStore, EngineMode,
    EngineOwner, EngineSnapshot, EngineState, TunnelInstallOutcome,
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use tokio::sync::watch;

use crate::{
    EngineCoordinatorError, EngineOperation,
    cutover::start_request,
    runtime::{
        CoordinatorState, NativeLease, NativeLeaseKind, TransitionContext, backend_error,
        call_backend, publish, reconcile_active_runtime, reserve_next_generation, set_failed,
        set_off, validate_runtime,
    },
};

pub(crate) async fn transition(
    context: TransitionContext<'_>,
    state: &mut CoordinatorState,
    target: EngineMode,
    profile: &ValidatedSingBoxProfile,
    settings: &EngineSettings,
) -> Result<EngineSnapshot, EngineCoordinatorError> {
    let TransitionContext {
        backend,
        snapshots,
        session,
        generation_store,
        operation_timeout,
        status_query_timeout,
    } = context;
    if target == EngineMode::Off {
        return transition_to_off(
            backend,
            state,
            snapshots,
            operation_timeout,
            generation_store,
        )
        .await;
    }
    let projected = match target {
        EngineMode::SystemProxy => profile.project(ProjectionMode::SystemProxy, settings)?,
        EngineMode::Tunnel => profile.project(ProjectionMode::Tunnel, settings)?,
        EngineMode::Off => unreachable!("off returned before projection"),
    };

    let is_same_active_runtime = match &state.snapshot.state {
        EngineState::ProxyActive { runtime } if target == EngineMode::SystemProxy => {
            runtime.config_digest == projected.digest() && runtime.ready
        }
        EngineState::TunnelActive { runtime } if target == EngineMode::Tunnel => {
            runtime.config_digest == projected.digest() && runtime.ready
        }
        _ => false,
    };
    if is_same_active_runtime {
        reconcile_active_runtime(backend, state, snapshots, status_query_timeout).await?;
        state.snapshot.desired_mode = target;
        publish(state, snapshots);
        return Ok(state.snapshot.clone());
    }

    let generation = reserve_next_generation(state, generation_store)?;
    state.snapshot.desired_mode = target;
    state.snapshot.generation = generation;

    stop_owned_runtime(backend, state, snapshots, operation_timeout).await?;
    set_off(state, snapshots);

    let context = EngineCommandContext::new(session, generation);
    let request = start_request(&projected, settings, context.clone());

    match target {
        EngineMode::SystemProxy => {
            state.native_lease = Some(NativeLease {
                kind: NativeLeaseKind::SystemProxy,
                context: context.clone(),
            });
            state.snapshot.state = EngineState::ProxyStarting { generation };
            state.snapshot.config_digest = Some(request.config_digest.clone());
            publish(state, snapshots);

            let runtime = match call_backend(
                operation_timeout,
                EngineOperation::StartSystemProxy,
                backend.start_system_proxy(request.clone()),
            )
            .await
            {
                Ok(runtime) => runtime,
                Err(source) => {
                    return fail_backend(
                        backend,
                        state,
                        snapshots,
                        EngineOperation::StartSystemProxy,
                        source,
                        operation_timeout,
                    )
                    .await;
                }
            };
            if let Err(error) = validate_runtime(
                &runtime,
                EngineOwner::ProxyAgent,
                &context,
                &request.config_digest,
            ) {
                return fail_identity(backend, state, snapshots, error, operation_timeout).await;
            }
            state.snapshot.state = EngineState::ProxyActive { runtime };
        }
        EngineMode::Tunnel => {
            state.native_lease = Some(NativeLease {
                kind: NativeLeaseKind::TunnelInstallation,
                context: context.clone(),
            });
            state.snapshot.state = EngineState::TunnelInstalling { generation };
            state.snapshot.config_digest = Some(request.config_digest.clone());
            publish(state, snapshots);

            let install = call_backend(
                operation_timeout,
                EngineOperation::InstallTunnel,
                backend.install_tunnel(context.clone()),
            )
            .await
            .map_err(|source| backend_error(EngineOperation::InstallTunnel, source));
            let install = match install {
                Ok(outcome) => outcome,
                Err(EngineCoordinatorError::Backend { operation, source }) => {
                    return fail_backend(
                        backend,
                        state,
                        snapshots,
                        operation,
                        source,
                        operation_timeout,
                    )
                    .await;
                }
                Err(unexpected) => return Err(unexpected),
            };
            if install == TunnelInstallOutcome::AwaitingApproval {
                state.snapshot.state = EngineState::AwaitingApproval { generation };
                publish(state, snapshots);
                return Ok(state.snapshot.clone());
            }

            state.snapshot.state = EngineState::TunnelStarting { generation };
            publish(state, snapshots);
            state.native_lease = Some(NativeLease {
                kind: NativeLeaseKind::TunnelRuntime,
                context: context.clone(),
            });
            let runtime = match call_backend(
                operation_timeout,
                EngineOperation::StartTunnel,
                backend.start_tunnel(request.clone()),
            )
            .await
            {
                Ok(runtime) => runtime,
                Err(source) => {
                    return fail_backend(
                        backend,
                        state,
                        snapshots,
                        EngineOperation::StartTunnel,
                        source,
                        operation_timeout,
                    )
                    .await;
                }
            };
            if let Err(error) = validate_runtime(
                &runtime,
                EngineOwner::PacketTunnelSystemExtension,
                &context,
                &request.config_digest,
            ) {
                return fail_identity(backend, state, snapshots, error, operation_timeout).await;
            }
            state.snapshot.state = EngineState::TunnelActive { runtime };
        }
        EngineMode::Off => unreachable!("off returned before native start"),
    }

    publish(state, snapshots);
    Ok(state.snapshot.clone())
}

pub(crate) async fn stop_owned_runtime(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    operation_timeout: Duration,
) -> Result<(), EngineCoordinatorError> {
    let Some(lease) = state.native_lease.clone() else {
        return Ok(());
    };

    let (operation, result) = match lease.kind {
        NativeLeaseKind::SystemProxy => {
            state.snapshot.state = EngineState::ProxyStopping {
                generation: lease.context.generation,
            };
            publish(state, snapshots);
            (
                EngineOperation::StopSystemProxy,
                call_backend(
                    operation_timeout,
                    EngineOperation::StopSystemProxy,
                    backend.stop_system_proxy(lease.context.clone()),
                )
                .await,
            )
        }
        NativeLeaseKind::TunnelInstallation => (
            EngineOperation::CancelTunnelInstall,
            call_backend(
                operation_timeout,
                EngineOperation::CancelTunnelInstall,
                backend.cancel_tunnel_install(lease.context.clone()),
            )
            .await,
        ),
        NativeLeaseKind::TunnelRuntime => {
            state.snapshot.state = EngineState::TunnelStopping {
                generation: lease.context.generation,
            };
            publish(state, snapshots);
            (
                EngineOperation::StopTunnel,
                call_backend(
                    operation_timeout,
                    EngineOperation::StopTunnel,
                    backend.stop_tunnel(lease.context.clone()),
                )
                .await,
            )
        }
    };

    if let Err(source) = result {
        let error = backend_error(operation, source);
        let target = state.snapshot.desired_mode;
        let generation = state.snapshot.generation;
        set_failed(state, snapshots, target, generation, &error);
        return Err(error);
    }

    state.native_lease = None;
    Ok(())
}

async fn fail_backend(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    operation: EngineOperation,
    source: BackendError,
    operation_timeout: Duration,
) -> Result<EngineSnapshot, EngineCoordinatorError> {
    let target = state.snapshot.desired_mode;
    let generation = state.snapshot.generation;
    let error = match stop_owned_runtime(backend, state, snapshots, operation_timeout).await {
        Ok(()) => backend_error(operation, source),
        Err(EngineCoordinatorError::Backend {
            operation: cleanup_operation,
            source: cleanup_error,
        }) => EngineCoordinatorError::StartAndCleanupFailed {
            start_operation: operation,
            start_error: source,
            cleanup_operation,
            cleanup_error,
        },
        Err(unexpected) => unexpected,
    };
    set_failed(state, snapshots, target, generation, &error);
    Err(error)
}

async fn fail_identity(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    error: EngineCoordinatorError,
    operation_timeout: Duration,
) -> Result<EngineSnapshot, EngineCoordinatorError> {
    let target = state.snapshot.desired_mode;
    let generation = state.snapshot.generation;
    if let Err(cleanup_error) =
        stop_owned_runtime(backend, state, snapshots, operation_timeout).await
    {
        let (cleanup_operation, cleanup_error) = match cleanup_error {
            EngineCoordinatorError::Backend { operation, source } => (operation, source),
            unexpected => {
                set_failed(state, snapshots, target, generation, &unexpected);
                return Err(unexpected);
            }
        };
        let combined = EngineCoordinatorError::ValidationAndCleanupFailed {
            validation_error: Box::new(error),
            cleanup_operation,
            cleanup_error,
        };
        set_failed(state, snapshots, target, generation, &combined);
        return Err(combined);
    }
    set_failed(state, snapshots, target, generation, &error);
    Err(error)
}

pub(crate) async fn transition_to_off(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    operation_timeout: Duration,
    generation_store: Option<&dyn EngineGenerationStore>,
) -> Result<EngineSnapshot, EngineCoordinatorError> {
    let was_already_off = state.native_lease.is_none() && state.snapshot.state == EngineState::Off;
    state.snapshot.desired_mode = EngineMode::Off;
    stop_owned_runtime(backend, state, snapshots, operation_timeout).await?;
    set_off(state, snapshots);
    if was_already_off {
        return Ok(state.snapshot.clone());
    }

    // Stopping uses the exact context of the runtime we already own and must
    // never depend on allocating a future generation. Persisting the Off
    // transition happens only after the native stop barrier; if it fails, the
    // caller sees the journal error while the published state remains Off.
    let generation = reserve_next_generation(state, generation_store)?;
    state.snapshot.generation = generation;
    publish(state, snapshots);
    Ok(state.snapshot.clone())
}
