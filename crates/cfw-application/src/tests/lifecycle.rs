use std::{sync::Arc, time::Duration};

use cfw_engine_api::{
    BackendError, BackendErrorKind, BackendFuture, EngineBackend, EngineCommandContext, EngineMode,
    EngineOwner, EngineStartRequest, EngineState, NativeEngineStatus, RuntimeIdentity,
    TunnelInstallOutcome,
};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};
use tokio::sync::Notify;

use crate::{
    CoordinatorOptions, EngineCoordinatorError, EngineModeCoordinator,
    coordinator::COMMAND_QUEUE_CAPACITY,
};

use super::support::{FakeBackend, MemoryGenerationStore, coordinator, test_session};

mod commands;
mod host_restart;
mod lineage;
mod reconciliation;
mod shutdown;
mod startup;

fn recovered_runtime(owner: EngineOwner, generation: u64) -> RuntimeIdentity {
    let session = test_session();
    RuntimeIdentity {
        owner,
        context: EngineCommandContext::new(&session, generation),
        config_digest: "a".repeat(64),
        ready: true,
    }
}

fn cleanup_only_runtime(owner: EngineOwner, generation: u64) -> RuntimeIdentity {
    RuntimeIdentity {
        owner,
        context: EngineCommandContext {
            installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
            config_epoch: 4,
            generation,
        },
        config_digest: "a".repeat(64),
        ready: true,
    }
}
