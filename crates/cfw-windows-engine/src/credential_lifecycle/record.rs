use super::{CredentialLifecycleError as Error, Result};
use crate::{
    CheckedStartConfiguration, authority::AuthoritySnapshot, authority_journal::JournalOperation,
};
use cfw_engine_api::{
    TunnelNetworkOptions,
    authority_v1::{AuthorityMode, AuthorityState, RootContext, WireValidate},
};
use cfw_singbox_config::{
    CredentialAudience, CredentialBinding, CredentialSlot, MAX_CREDENTIAL_SLOTS, ProjectionMode,
    configuration_identity_digest,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub(super) const MAX_BYTES: usize = 2 * 1024 * 1024;

/// Public references and hashes only. The controller key, template, ticket and
/// resolved credentials never enter this record.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    schema_version: u16,
    root: RootContext,
    operation_id: Uuid,
    mode: ProjectionMode,
    configuration_sha256: String,
    identity_sha256: String,
    audience: CredentialAudience,
    slots: Vec<CredentialSlot>,
    #[serde(deserialize_with = "required_options")]
    network_options: Option<TunnelNetworkOptions>,
}
fn required_options<'de, D: Deserializer<'de>>(
    value: D,
) -> std::result::Result<Option<TunnelNetworkOptions>, D::Error> {
    Option::deserialize(value)
}
impl Record {
    pub(super) fn new(request: &CheckedStartConfiguration, operation_id: Uuid) -> Result<Self> {
        let context = request.context();
        let value = Self {
            schema_version: 1,
            root: RootContext {
                installation_id: Uuid::parse_str(&context.installation_id)
                    .map_err(|_| Error::Record)?,
                epoch: context.config_epoch,
                generation: context.generation,
            },
            operation_id,
            mode: request.mode(),
            configuration_sha256: request.configuration_digest().into(),
            identity_sha256: request.digest().into(),
            audience: request.credential_audience().clone(),
            slots: request.credential_slots().to_vec(),
            network_options: request.shared_request().tunnel_options,
        };
        value.validate()?;
        Ok(value)
    }
    pub(super) fn root(&self) -> &RootContext {
        &self.root
    }
    pub(super) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(super) fn mode(&self) -> AuthorityMode {
        match self.mode {
            ProjectionMode::LocalProxy => AuthorityMode::LocalProxy,
            ProjectionMode::SystemProxy => AuthorityMode::SystemProxy,
            ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => AuthorityMode::Tunnel,
        }
    }
    pub(super) fn content_digest(&self) -> Result<[u8; 32]> {
        digest(&self.configuration_sha256)
    }
    pub(super) fn identity_digest(&self) -> Result<[u8; 32]> {
        digest(&self.identity_sha256)
    }
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(Error::Schema);
        }
        self.root.validate().map_err(|_| Error::Record)?;
        if self.operation_id.is_nil() || self.slots.len() > MAX_CREDENTIAL_SLOTS {
            return Err(Error::Record);
        }
        self.content_digest()?;
        self.identity_digest()?;
        let options_match = match self.mode {
            ProjectionMode::LocalProxy | ProjectionMode::SystemProxy => {
                self.network_options.is_none()
            }
            ProjectionMode::Tunnel => self
                .network_options
                .is_some_and(|v| v.system_proxy_port.is_none()),
            ProjectionMode::TunnelSystemProxy => self
                .network_options
                .is_some_and(|v| v.system_proxy_port.is_some()),
        };
        if !options_match {
            return Err(Error::Record);
        }
        let mut pointers = BTreeSet::new();
        let mut references = BTreeMap::new();
        for slot in &self.slots {
            if !pointers.insert(slot.json_pointer()) {
                return Err(Error::Record);
            }
            if references
                .insert(slot.reference().id(), slot.reference().kind())
                .is_some_and(|old| old != slot.reference().kind())
            {
                return Err(Error::Record);
            }
        }
        let expected = configuration_identity_digest(
            &self.configuration_sha256,
            &self.audience,
            &self.slots,
            self.mode,
            &self.network_options,
        )
        .map_err(|_| Error::Record)?;
        if expected != self.identity_sha256 {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Record)?;
        if bytes.len() > MAX_BYTES {
            return Err(Error::Record);
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(Error::Record);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Record)?;
        if value.encode()? != bytes {
            return Err(Error::Record);
        }
        Ok(value)
    }
    fn matches(&self, root: &RootContext, operation: &JournalOperation) -> Result<()> {
        self.validate()?;
        if &self.root != root
            || self.operation_id != operation.operation_id()
            || self.mode() != operation.mode()
            || &self.content_digest()? != operation.config_sha256()
            || &self.identity_digest()? != operation.identity_sha256()
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
    fn bindings(&self) -> Vec<CredentialBinding> {
        self.slots
            .iter()
            .map(|slot| CredentialBinding::new(self.audience.clone(), slot.reference().clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Only the native adapter supplies the snapshot/operation, from a freshly
/// authenticated ReadRuntimeScope response while holding the lifecycle guard.
pub(super) fn protected(
    snapshot: &AuthoritySnapshot,
    operation: Option<&JournalOperation>,
    record: Option<&Record>,
) -> Result<Vec<CredentialBinding>> {
    if snapshot.revision.is_none() || snapshot.root.is_none() {
        return Err(Error::Unavailable);
    }
    if let Some(record) = record {
        record.validate()?;
    }
    if snapshot.state == AuthorityState::Off {
        return if operation.is_none() {
            Ok(Vec::new())
        } else {
            Err(Error::Identity)
        };
    }
    let operation = operation.ok_or(Error::Unavailable)?;
    let record = record.ok_or(Error::Unavailable)?;
    record.matches(snapshot.root.as_ref().ok_or(Error::Unavailable)?, operation)?;
    Ok(record.bindings())
}
fn digest(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(Error::Record);
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| Error::Record)?;
    }
    Ok(bytes)
}
