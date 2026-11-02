//! Session, lineage and command identities, and the runtime identity an owner attests.

use serde::{Deserialize, Serialize};

use crate::EngineOwner;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSessionIdentity {
    pub installation_id: String,
    pub config_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineLineage {
    pub session: EngineSessionIdentity,
    pub generation: u64,
}

pub trait EngineGenerationStore: Send + Sync + 'static {
    fn load(&self) -> Result<EngineLineage, String>;
    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCommandContext {
    pub installation_id: String,
    pub config_epoch: u64,
    pub generation: u64,
}

impl EngineCommandContext {
    pub fn new(session: &EngineSessionIdentity, generation: u64) -> Self {
        Self {
            installation_id: session.installation_id.clone(),
            config_epoch: session.config_epoch,
            generation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    pub owner: EngineOwner,
    pub context: EngineCommandContext,
    pub config_digest: String,
    pub ready: bool,
}
