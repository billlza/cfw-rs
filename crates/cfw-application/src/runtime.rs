use std::time::Duration;

use cfw_engine_api::{
    BackendError, BackendErrorKind, EngineBackend, EngineCommandContext, EngineGenerationStore,
    EngineLineage, EngineMode, EngineOwner, EngineSessionIdentity, EngineSnapshot, EngineState,
    NativeEngineStatus, RuntimeIdentity,
};
use tokio::{sync::watch, time::timeout};
use uuid::Uuid;

use crate::RecoveredRuntimeMismatch;
use crate::{EngineCoordinatorError, EngineOperation};

#[derive(Debug, Clone, Copy)]
pub(crate) enum NativeLeaseKind {
    SystemProxy,
    TunnelInstallation,
    TunnelRuntime,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeLease {
    pub(crate) kind: NativeLeaseKind,
    pub(crate) context: EngineCommandContext,
}

pub(crate) struct CoordinatorState {
    pub(crate) snapshot: EngineSnapshot,
    pub(crate) native_lease: Option<NativeLease>,
}

#[derive(Clone, Copy)]
pub(crate) struct TransitionContext<'a> {
    pub(crate) backend: &'a dyn EngineBackend,
    pub(crate) snapshots: &'a watch::Sender<EngineSnapshot>,
    pub(crate) session: &'a EngineSessionIdentity,
    pub(crate) generation_store: Option<&'a dyn EngineGenerationStore>,
    pub(crate) operation_timeout: Duration,
    pub(crate) status_query_timeout: Duration,
}

pub(crate) fn validate_runtime(
    runtime: &RuntimeIdentity,
    expected_owner: EngineOwner,
    expected_context: &EngineCommandContext,
    expected_digest: &str,
) -> Result<(), EngineCoordinatorError> {
    if runtime.owner == expected_owner
        && runtime.context == *expected_context
        && runtime.config_digest == expected_digest
        && runtime.ready
    {
        return Ok(());
    }

    Err(EngineCoordinatorError::RuntimeIdentityMismatch {
        expected_owner,
        expected_context: expected_context.clone(),
        expected_digest: expected_digest.to_owned(),
        actual: Box::new(runtime.clone()),
    })
}

/// Revalidates an active snapshot against a fresh native observation.
///
/// The coordinator actor is the only caller, so no transition can interleave
/// with the query. A failed observation deliberately preserves `native_lease`:
/// an Off report, identity drift, or transport error is not proof that the
/// exact runtime ownership has been released.
pub(crate) async fn reconcile_active_runtime(
    backend: &dyn EngineBackend,
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    operation_timeout: Duration,
) -> Result<(), EngineCoordinatorError> {
    let (expected_mode, expected_owner, expected_runtime) = match &state.snapshot.state {
        EngineState::ProxyActive { runtime } => (
            EngineMode::SystemProxy,
            EngineOwner::ProxyAgent,
            runtime.clone(),
        ),
        EngineState::TunnelActive { runtime } => (
            EngineMode::Tunnel,
            EngineOwner::PacketTunnelSystemExtension,
            runtime.clone(),
        ),
        _ => return Ok(()),
    };

    let observation = match call_backend(
        operation_timeout,
        EngineOperation::QueryStatus,
        backend.query_status(),
    )
    .await
    {
        Ok(observation) => observation,
        Err(source) => {
            let error = backend_error(EngineOperation::QueryStatus, source);
            let generation = state.snapshot.generation;
            set_failed(state, snapshots, expected_mode, generation, &error);
            return Err(error);
        }
    };

    let observed_runtime = match (&observation, expected_mode) {
        (NativeEngineStatus::SystemProxy { runtime }, EngineMode::SystemProxy)
        | (NativeEngineStatus::Tunnel { runtime }, EngineMode::Tunnel) => runtime,
        _ => {
            let error = EngineCoordinatorError::ActiveRuntimeStatusMismatch {
                expected_mode,
                actual: Box::new(observation),
            };
            let generation = state.snapshot.generation;
            set_failed(state, snapshots, expected_mode, generation, &error);
            return Err(error);
        }
    };

    if let Err(error) = validate_runtime(
        observed_runtime,
        expected_owner,
        &expected_runtime.context,
        &expected_runtime.config_digest,
    ) {
        let generation = state.snapshot.generation;
        set_failed(state, snapshots, expected_mode, generation, &error);
        return Err(error);
    }

    Ok(())
}

pub(crate) fn validate_recovered_runtime(
    runtime: &RuntimeIdentity,
    mode: EngineMode,
    expected_owner: EngineOwner,
    session: &EngineSessionIdentity,
    expected_generation: u64,
) -> Result<(), EngineCoordinatorError> {
    let mismatch = if runtime.owner != expected_owner {
        Some(RecoveredRuntimeMismatch::Owner {
            mode,
            expected: expected_owner,
            actual: runtime.owner,
        })
    } else if runtime.context.installation_id != session.installation_id {
        Some(RecoveredRuntimeMismatch::Installation)
    } else if runtime.context.config_epoch != session.config_epoch {
        Some(RecoveredRuntimeMismatch::Epoch)
    } else if runtime.context.generation != expected_generation {
        Some(RecoveredRuntimeMismatch::Generation {
            expected: expected_generation,
            actual: runtime.context.generation,
        })
    } else if runtime.config_digest.len() != 64
        || !runtime
            .config_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Some(RecoveredRuntimeMismatch::Digest)
    } else if !runtime.ready {
        Some(RecoveredRuntimeMismatch::NotReady)
    } else {
        None
    };
    match mismatch {
        Some(mismatch) => Err(EngineCoordinatorError::RecoveredRuntimeMismatch {
            mismatch,
            actual: Box::new(runtime.clone()),
        }),
        None => Ok(()),
    }
}

pub(crate) fn validate_cleanup_runtime(
    runtime: &RuntimeIdentity,
    mode: EngineMode,
    expected_owner: EngineOwner,
) -> Result<(), EngineCoordinatorError> {
    let canonical_installation = Uuid::parse_str(&runtime.context.installation_id)
        .ok()
        .map(|uuid| uuid.hyphenated().to_string());
    let mismatch = if runtime.owner != expected_owner {
        Some(RecoveredRuntimeMismatch::Owner {
            mode,
            expected: expected_owner,
            actual: runtime.owner,
        })
    } else if canonical_installation.as_deref() != Some(runtime.context.installation_id.as_str()) {
        Some(RecoveredRuntimeMismatch::InvalidInstallation)
    } else if runtime.context.config_epoch == 0 {
        Some(RecoveredRuntimeMismatch::InvalidEpoch)
    } else if runtime.context.generation == 0 {
        Some(RecoveredRuntimeMismatch::InvalidGeneration)
    } else if runtime.config_digest.len() != 64
        || !runtime
            .config_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Some(RecoveredRuntimeMismatch::Digest)
    } else if !runtime.ready {
        Some(RecoveredRuntimeMismatch::NotReady)
    } else {
        None
    };
    match mismatch {
        Some(mismatch) => Err(EngineCoordinatorError::RecoveredRuntimeMismatch {
            mismatch,
            actual: Box::new(runtime.clone()),
        }),
        None => Ok(()),
    }
}

pub(crate) async fn call_backend<T>(
    operation_timeout: Duration,
    operation: EngineOperation,
    future: cfw_engine_api::BackendFuture<'_, T>,
) -> Result<T, BackendError> {
    match timeout(operation_timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(BackendError::new(
            BackendErrorKind::Timeout,
            format!("{operation} exceeded {operation_timeout:?}"),
        )),
    }
}

pub(crate) fn reserve_next_generation(
    state: &CoordinatorState,
    generation_store: Option<&dyn EngineGenerationStore>,
) -> Result<u64, EngineCoordinatorError> {
    let expected = state
        .snapshot
        .generation
        .checked_add(1)
        .ok_or(EngineCoordinatorError::GenerationExhausted)?;
    let Some(generation_store) = generation_store else {
        return Ok(expected);
    };
    let actual = generation_store
        .reserve_next(state.snapshot.generation)
        .map_err(EngineCoordinatorError::Journal)?;
    if actual != expected {
        return Err(EngineCoordinatorError::JournalGenerationMismatch { expected, actual });
    }
    Ok(actual)
}

pub(crate) fn validate_lineage(lineage: &EngineLineage) -> Result<(), EngineCoordinatorError> {
    if lineage.session.installation_id.trim().is_empty() {
        return Err(EngineCoordinatorError::InvalidLineage(
            "installation identifier is empty".into(),
        ));
    }
    if lineage.session.config_epoch == 0 {
        return Err(EngineCoordinatorError::InvalidLineage(
            "configuration epoch must be nonzero".into(),
        ));
    }
    Ok(())
}

pub(crate) fn backend_error(
    operation: EngineOperation,
    source: BackendError,
) -> EngineCoordinatorError {
    EngineCoordinatorError::Backend { operation, source }
}

pub(crate) fn set_off(state: &mut CoordinatorState, snapshots: &watch::Sender<EngineSnapshot>) {
    state.snapshot.state = EngineState::Off;
    state.snapshot.config_digest = None;
    publish(state, snapshots);
}

pub(crate) fn set_failed(
    state: &mut CoordinatorState,
    snapshots: &watch::Sender<EngineSnapshot>,
    target: EngineMode,
    generation: u64,
    error: &EngineCoordinatorError,
) {
    state.snapshot.state = EngineState::Failed {
        generation,
        target,
        error: error.to_string(),
    };
    publish(state, snapshots);
}

pub(crate) fn publish(state: &CoordinatorState, snapshots: &watch::Sender<EngineSnapshot>) {
    snapshots.send_replace(state.snapshot.clone());
}
