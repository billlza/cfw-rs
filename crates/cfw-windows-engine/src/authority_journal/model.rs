use super::*;
use cfw_engine_api::authority_v1::{AuthorityMode, AuthorityState, RootContext};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fmt;
use uuid::Uuid;

type Result<T> = std::result::Result<T, JournalValidationError>;

/// A recorded account/logon/session claim. Decoding never constructs a
/// NativeUserSession; a restarted service must observe and authorize peers anew.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedOwner {
    sid: Vec<u8>,
    authentication_id: u64,
    session_id: u32,
}
impl RecordedOwner {
    #[cfg(windows)]
    pub fn from_native(owner: &crate::NativeUserSession) -> Result<Self> {
        let value = Self {
            sid: owner.user_sid_bytes().to_vec(),
            authentication_id: owner.authentication_id(),
            session_id: owner.session_id(),
        };
        value.validate()?;
        Ok(value)
    }
    #[cfg(windows)]
    pub fn matches_native(&self, owner: &crate::NativeUserSession) -> bool {
        self.sid == owner.user_sid_bytes()
            && self.authentication_id == owner.authentication_id()
            && self.session_id == owner.session_id()
    }
    pub fn sid_bytes(&self) -> &[u8] {
        &self.sid
    }
    pub fn authentication_id(&self) -> u64 {
        self.authentication_id
    }
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.sid.len() < 8
            || self.sid[0] != 1
            || self.sid[1] > 15
            || self.sid.len() != 8 + 4 * usize::from(self.sid[1])
            || matches!(self.authentication_id, 0 | u64::MAX)
            || matches!(self.session_id, 0 | u32::MAX)
        {
            return Err(JournalValidationError::InvalidState);
        }
        Ok(())
    }
}
impl fmt::Debug for RecordedOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedOwner")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalTransition {
    EnrollOff,
    Checkpoint,
    ReserveGeneration,
    Prepare,
    BindOwner,
    Ready,
    BeginStop,
    OwnerStopped,
    AbortPrepared,
    RevokeForConsoleChange,
    RevokeForTimeout,
    GlobalOff,
    ReconcileOff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalOperation {
    operation_id: Uuid,
    mode: AuthorityMode,
    config_sha256: [u8; 32],
    identity_sha256: [u8; 32],
    lease_id: Uuid,
    owner: RecordedOwner,
}
impl JournalOperation {
    pub fn new(
        operation_id: Uuid,
        mode: AuthorityMode,
        config_sha256: [u8; 32],
        identity_sha256: [u8; 32],
        lease_id: Uuid,
        owner: RecordedOwner,
    ) -> Result<Self> {
        let value = Self {
            operation_id,
            mode,
            config_sha256,
            identity_sha256,
            lease_id,
            owner,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub fn mode(&self) -> AuthorityMode {
        self.mode
    }
    pub fn config_sha256(&self) -> &[u8; 32] {
        &self.config_sha256
    }
    pub fn identity_sha256(&self) -> &[u8; 32] {
        &self.identity_sha256
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.owner.validate()?;
        if self.operation_id.is_nil() || self.lease_id.is_nil() {
            return Err(JournalValidationError::InvalidState);
        }
        Ok(())
    }
    pub fn lease_id(&self) -> Uuid {
        self.lease_id
    }
    pub fn owner(&self) -> &RecordedOwner {
        &self.owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCommittedState {
    schema_version: u16,
    root: RootContext,
    allocated_generation: u64,
    revision: u64,
    transition: JournalTransition,
    state: AuthorityState,
    operation: Option<JournalOperation>,
}
impl AuthorityCommittedState {
    pub fn enrollment(installation_id: Uuid) -> Self {
        Self {
            schema_version: 6,
            root: RootContext {
                installation_id,
                epoch: 0,
                generation: 0,
            },
            allocated_generation: 0,
            revision: 1,
            transition: JournalTransition::EnrollOff,
            state: AuthorityState::Off,
            operation: None,
        }
    }
    pub fn new(
        root: RootContext,
        revision: u64,
        transition: JournalTransition,
        state: AuthorityState,
        operation: Option<JournalOperation>,
    ) -> Result<Self> {
        let value = Self {
            schema_version: 6,
            allocated_generation: root.generation,
            root,
            revision,
            transition,
            state,
            operation,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn root(&self) -> &RootContext {
        &self.root
    }
    /// A durable allocation is not a runtime grant. Off reservations survive
    /// restart and compaction even when no process ever consumed them.
    pub fn allocated_generation(&self) -> u64 {
        self.allocated_generation
    }
    pub fn reserve_next_generation(&self) -> Result<Self> {
        self.validate()?;
        if self.state != AuthorityState::Off || self.operation.is_some() {
            return Err(JournalValidationError::Sequence);
        }
        let mut next = self.clone();
        next.allocated_generation = self
            .allocated_generation
            .checked_add(1)
            .ok_or(JournalValidationError::InvalidState)?;
        next.revision = self
            .revision
            .checked_add(1)
            .ok_or(JournalValidationError::InvalidState)?;
        next.transition = JournalTransition::ReserveGeneration;
        next.validate_successor(self)?;
        Ok(next)
    }
    pub(crate) fn transition_to(
        &self,
        revision: u64,
        transition: JournalTransition,
        state: AuthorityState,
        operation: Option<JournalOperation>,
    ) -> Result<Self> {
        let mut next = self.clone();
        next.revision = revision;
        next.transition = transition;
        next.state = state;
        next.operation = operation;
        next.validate_successor(self)?;
        Ok(next)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn state(&self) -> AuthorityState {
        self.state
    }
    pub fn transition(&self) -> JournalTransition {
        self.transition
    }
    pub fn operation(&self) -> Option<&JournalOperation> {
        self.operation.as_ref()
    }
    pub fn checkpoint(&self) -> Result<Self> {
        let mut value = self.clone();
        value.transition = JournalTransition::Checkpoint;
        value.validate()?;
        Ok(value)
    }
    pub fn restart_action(&self) -> Result<RecoveryAction> {
        self.validate()?;
        match self.state {
            AuthorityState::Off => Ok(RecoveryAction::VerifyOff),
            AuthorityState::Active => Ok(RecoveryAction::ReattestOwner),
            AuthorityState::Preparing | AuthorityState::Starting | AuthorityState::Stopping => {
                Ok(RecoveryAction::StopOwner)
            }
            AuthorityState::Quarantined
                if matches!(
                    self.transition,
                    JournalTransition::ReconcileOff | JournalTransition::Checkpoint
                ) =>
            {
                Ok(RecoveryAction::StopOwner)
            }
            AuthorityState::Recovering | AuthorityState::Quarantined => {
                Err(JournalValidationError::InvalidState)
            }
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_RECORD_PAYLOAD)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_RECORD_PAYLOAD)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        // Schema 6 also requires the proxy template to exclude system
        // interfaces and extra services. Older development journals cannot
        // prove that resource scope. No implicit migration/reset is safe.
        if self.schema_version != 6 {
            return Err(JournalValidationError::UnsupportedSchema);
        }
        if self.revision == 0
            || self.root.installation_id.is_nil()
            || self.allocated_generation < self.root.generation
        {
            return Err(JournalValidationError::InvalidState);
        }
        if let Some(operation) = &self.operation {
            operation.validate()?;
        }
        match self.state {
            AuthorityState::Off if self.operation.is_some() => {
                return Err(JournalValidationError::InvalidState);
            }
            AuthorityState::Preparing
            | AuthorityState::Starting
            | AuthorityState::Active
            | AuthorityState::Stopping
                if self.operation.is_none() =>
            {
                return Err(JournalValidationError::InvalidState);
            }
            _ => {}
        }
        if self.transition == JournalTransition::EnrollOff {
            if self.root.epoch != 0
                || self.root.generation != 0
                || self.revision != 1
                || self.state != AuthorityState::Off
                || self.operation.is_some()
                || self.allocated_generation != 0
            {
                return Err(JournalValidationError::InvalidState);
            }
        } else if (self.root.epoch == 0 || self.root.generation == 0)
            && (self.root.epoch != 0
                || self.root.generation != 0
                || self.state != AuthorityState::Off
                || !matches!(
                    self.transition,
                    JournalTransition::ReserveGeneration | JournalTransition::Checkpoint
                ))
        {
            return Err(JournalValidationError::InvalidState);
        }
        if self.operation.is_some() && self.allocated_generation != self.root.generation
            || self.transition == JournalTransition::ReserveGeneration
                && (self.state != AuthorityState::Off || self.allocated_generation == 0)
        {
            return Err(JournalValidationError::InvalidState);
        }
        Ok(())
    }
    pub fn validate_successor(&self, prior: &Self) -> Result<()> {
        self.validate()?;
        prior.validate()?;
        if self.root.installation_id != prior.root.installation_id
            || prior.revision.checked_add(1) != Some(self.revision)
            || matches!(
                self.transition,
                JournalTransition::EnrollOff | JournalTransition::Checkpoint
            )
        {
            return Err(JournalValidationError::Sequence);
        }
        let before = (prior.root.epoch, prior.root.generation);
        let after = (self.root.epoch, self.root.generation);
        if self.transition != JournalTransition::Prepare
            && self.state != AuthorityState::Off
            && self.operation != prior.operation
        {
            return Err(JournalValidationError::Sequence);
        }
        if self.transition == JournalTransition::ReserveGeneration {
            if prior.state != AuthorityState::Off
                || self.state != AuthorityState::Off
                || after != before
                || prior.allocated_generation.checked_add(1) != Some(self.allocated_generation)
            {
                return Err(JournalValidationError::Sequence);
            }
        } else if self.allocated_generation != prior.allocated_generation {
            return Err(JournalValidationError::Sequence);
        } else if self.transition == JournalTransition::Prepare {
            if prior.state != AuthorityState::Off
                || self.state != AuthorityState::Preparing
                || after <= before
                || self.root.epoch != prior.root.epoch.max(1)
                || self.root.generation != prior.allocated_generation
            {
                return Err(JournalValidationError::Sequence);
            }
        } else if after != before {
            return Err(JournalValidationError::Sequence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    VerifyOff,
    StopOwner,
    ReattestOwner,
}

/// Same cursor in the file head and the independent SYSTEM anchor. Journal
/// generation is distinct from the runtime root's epoch/generation high-water.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCursor {
    generation: u64,
    sequence: u64,
    committed_length: u64,
    record_sha256: [u8; 32],
    state_revision: u64,
}
impl JournalCursor {
    pub fn new(
        generation: u64,
        sequence: u64,
        committed_length: u64,
        record_sha256: [u8; 32],
        state_revision: u64,
    ) -> Result<Self> {
        let value = Self {
            generation,
            sequence,
            committed_length,
            record_sha256,
            state_revision,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn committed_length(&self) -> u64 {
        self.committed_length
    }
    pub fn record_sha256(&self) -> &[u8; 32] {
        &self.record_sha256
    }
    pub fn state_revision(&self) -> u64 {
        self.state_revision
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_HEAD_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_HEAD_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.generation == 0
            || self.sequence == 0
            || self.sequence > MAX_RECORDS
            || self.committed_length <= codec::HEADER_BYTES as u64
            || self.committed_length > MAX_JOURNAL_BYTES as u64
            || self.state_revision == 0
        {
            return Err(JournalValidationError::Anchor);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalAnchor {
    schema_version: u16,
    store_id: Uuid,
    committed: Option<JournalCursor>,
    pending: Option<JournalCursor>,
}
impl JournalAnchor {
    pub fn new(
        store_id: Uuid,
        committed: Option<JournalCursor>,
        pending: Option<JournalCursor>,
    ) -> Result<Self> {
        let value = Self {
            schema_version: 1,
            store_id,
            committed,
            pending,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn store_id(&self) -> Uuid {
        self.store_id
    }
    pub fn committed(&self) -> Option<&JournalCursor> {
        self.committed.as_ref()
    }
    pub fn pending(&self) -> Option<&JournalCursor> {
        self.pending.as_ref()
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_ANCHOR_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let value: Self = decode(bytes, MAX_ANCHOR_BYTES)?;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(JournalValidationError::UnsupportedSchema);
        }
        if let Some(value) = &self.committed {
            value.validate()?;
        }
        let Some(pending) = &self.pending else {
            return Ok(());
        };
        pending.validate()?;
        if let Some(committed) = &self.committed {
            if pending.generation == committed.generation {
                if committed.sequence.checked_add(1) != Some(pending.sequence)
                    || committed.state_revision.checked_add(1) != Some(pending.state_revision)
                    || pending.committed_length <= committed.committed_length
                {
                    return Err(JournalValidationError::Anchor);
                }
            } else if committed.generation.checked_add(1) != Some(pending.generation)
                || pending.sequence != 1
                || pending.state_revision != committed.state_revision
            {
                return Err(JournalValidationError::Anchor);
            }
        } else if pending.generation != 1 || pending.sequence != 1 || pending.state_revision != 1 {
            return Err(JournalValidationError::Anchor);
        }
        Ok(())
    }
}

pub(crate) fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| JournalValidationError::Encoding)?;
    if bytes.len() > maximum {
        return Err(JournalValidationError::Capacity);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(JournalValidationError::Capacity);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| JournalValidationError::Encoding)?;
    if encode(&value, maximum)? != bytes {
        return Err(JournalValidationError::Encoding);
    }
    Ok(value)
}
