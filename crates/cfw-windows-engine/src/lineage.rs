//! Machine-wide lineage obtained from the authenticated SYSTEM Authority.
//! No user-local counter can substitute for its committed allocation journal.
use crate::{
    ServiceClientRole, VerifiedExecutable,
    authority::{
        AuthorityChannel, AuthorityLineage,
        wire::{Command, Request, Response, WireError},
    },
};
use cfw_engine_api::{EngineGenerationStore, EngineLineage, EngineSessionIdentity};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    #[error("Windows lineage Authority: {0}")]
    Authority(#[from] WireError),
    #[error("Windows lineage Authority returned an unrelated response")]
    Response,
    #[error("Windows lineage compare-and-swap conflict: expected {expected}, found {actual}")]
    Conflict { expected: u64, actual: u64 },
    #[error("Windows lineage installation identity changed while this store was active")]
    IdentityChanged,
    #[error("Windows lineage local identity binding is poisoned")]
    BindingPoisoned,
}

/// Synchronous native adapter for the shared coordinator. Each operation uses a
/// fresh authenticated connection on its calling native worker. The service
/// serializes and journals allocations; this object caches only an identity
/// binding, never an authoritative counter. Uncertain writes are not replayed.
#[derive(Clone)]
pub struct WindowsEngineGenerationStore {
    service: String,
    image: Arc<VerifiedExecutable>,
    bound_session: Arc<Mutex<Option<EngineSessionIdentity>>>,
}
impl WindowsEngineGenerationStore {
    pub fn new(service: String, image: Arc<VerifiedExecutable>) -> Self {
        Self {
            service,
            image,
            bound_session: Arc::new(Mutex::new(None)),
        }
    }
    fn connect(&self) -> Result<AuthorityChannel, LineageError> {
        Ok(AuthorityChannel::connect(
            &self.service,
            ServiceClientRole::Desktop,
            Arc::clone(&self.image),
        )?)
    }
    pub fn load_lineage(&self) -> Result<EngineLineage, LineageError> {
        self.load_lineage_until(Instant::now() + Duration::from_secs(5))
    }
    pub(crate) fn load_lineage_until(
        &self,
        deadline: Instant,
    ) -> Result<EngineLineage, LineageError> {
        let mut binding = self
            .bound_session
            .lock()
            .map_err(|_| LineageError::BindingPoisoned)?;
        let value = request_until(&mut self.connect()?, Command::LoadLineage, deadline)?;
        let lineage = shared(&value);
        bind(&mut binding, &lineage.session)?;
        Ok(lineage)
    }
    pub fn reserve_generation(&self, expected: u64) -> Result<u64, LineageError> {
        let mut binding = self
            .bound_session
            .lock()
            .map_err(|_| LineageError::BindingPoisoned)?;
        let mut channel = self.connect()?;
        let current = request(&mut channel, Command::LoadLineage)?;
        bind(&mut binding, &shared(&current).session)?;
        if current.generation != expected {
            return Err(LineageError::Conflict {
                expected,
                actual: current.generation,
            });
        }
        let reserved = request(&mut channel, Command::ReserveGeneration(current))?;
        // AuthorityChannel correlates the exact installation/epoch and +1
        // generation. A lost reply remains an error even if the write committed.
        Ok(reserved.generation)
    }
}
fn request(
    channel: &mut AuthorityChannel,
    command: Command,
) -> Result<AuthorityLineage, LineageError> {
    request_until(channel, command, Instant::now() + Duration::from_secs(5))
}
fn request_until(
    channel: &mut AuthorityChannel,
    command: Command,
    deadline: Instant,
) -> Result<AuthorityLineage, LineageError> {
    match channel.request(
        Request::new(command)?,
        deadline.min(Instant::now() + Duration::from_secs(5)),
    )? {
        Response::Lineage(value) => Ok(value),
        _ => Err(LineageError::Response),
    }
}
fn shared(value: &AuthorityLineage) -> EngineLineage {
    EngineLineage {
        session: EngineSessionIdentity {
            installation_id: value.installation_id.to_string(),
            config_epoch: value.config_epoch,
        },
        generation: value.generation,
    }
}
fn bind(
    binding: &mut Option<EngineSessionIdentity>,
    session: &EngineSessionIdentity,
) -> Result<(), LineageError> {
    if binding.as_ref().is_some_and(|expected| expected != session) {
        return Err(LineageError::IdentityChanged);
    }
    *binding = Some(session.clone());
    Ok(())
}
impl EngineGenerationStore for WindowsEngineGenerationStore {
    fn load(&self) -> Result<EngineLineage, String> {
        self.load_lineage().map_err(|error| error.to_string())
    }
    fn reserve_next(&self, expected_generation: u64) -> Result<u64, String> {
        self.reserve_generation(expected_generation)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests;
