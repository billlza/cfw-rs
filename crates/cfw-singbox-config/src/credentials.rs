use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_CREDENTIAL_SLOTS: usize = 256;
const MAX_CREDENTIAL_OUTBOUNDS: usize = 128;
const MAX_CREDENTIAL_SECRET_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ShadowsocksPassword,
    VmessUuid,
    VlessUuid,
    TrojanPassword,
    Hysteria2Password,
    Hysteria2ObfsPassword,
}

/// Stable, non-secret reference to a credential stored outside profile files.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRef {
    id: String,
    kind: CredentialKind,
}

impl CredentialRef {
    pub fn new(id: impl Into<String>, kind: CredentialKind) -> Result<Self, InvalidCredentialRef> {
        let id = id.into();
        let parsed = Uuid::parse_str(&id).map_err(|_| InvalidCredentialRef)?;
        if parsed.hyphenated().to_string() != id {
            return Err(InvalidCredentialRef);
        }
        Ok(Self { id, kind })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> CredentialKind {
        self.kind
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRef")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRefWire {
    id: String,
    kind: CredentialKind,
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CredentialRefWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.kind).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("credential id must be a canonical lowercase hyphenated UUID")]
pub struct InvalidCredentialRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialTarget {
    ShadowsocksPassword,
    VmessUuid,
    VlessUuid,
    TrojanPassword,
    Hysteria2Password,
    Hysteria2ObfsPassword,
}

impl CredentialTarget {
    pub fn credential_kind(self) -> CredentialKind {
        match self {
            Self::ShadowsocksPassword => CredentialKind::ShadowsocksPassword,
            Self::VmessUuid => CredentialKind::VmessUuid,
            Self::VlessUuid => CredentialKind::VlessUuid,
            Self::TrojanPassword => CredentialKind::TrojanPassword,
            Self::Hysteria2Password => CredentialKind::Hysteria2Password,
            Self::Hysteria2ObfsPassword => CredentialKind::Hysteria2ObfsPassword,
        }
    }

    fn pointer_suffix(self) -> &'static str {
        match self {
            Self::ShadowsocksPassword | Self::TrojanPassword | Self::Hysteria2Password => {
                "password"
            }
            Self::VmessUuid | Self::VlessUuid => "uuid",
            Self::Hysteria2ObfsPassword => "obfs/password",
        }
    }
}

/// Closed credential-injection instruction consumed by the native vault.
///
/// `json_pointer` is serialized for cross-language verification, but is always
/// derived from `target` and `outbound_index`; deserialization rejects any
/// disagreement or unknown field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSlot {
    reference: CredentialRef,
    target: CredentialTarget,
    outbound_index: u16,
    json_pointer: String,
}

impl CredentialSlot {
    pub fn new(
        reference: CredentialRef,
        target: CredentialTarget,
        outbound_index: usize,
    ) -> Result<Self, CredentialSlotError> {
        if outbound_index >= MAX_CREDENTIAL_OUTBOUNDS {
            return Err(CredentialSlotError::OutboundIndexOutOfRange);
        }
        let outbound_index = u16::try_from(outbound_index)
            .map_err(|_| CredentialSlotError::OutboundIndexOutOfRange)?;
        if reference.kind() != target.credential_kind() {
            return Err(CredentialSlotError::KindMismatch);
        }
        let json_pointer = format!("/outbounds/{outbound_index}/{}", target.pointer_suffix());
        Ok(Self {
            reference,
            target,
            outbound_index,
            json_pointer,
        })
    }

    pub fn reference(&self) -> &CredentialRef {
        &self.reference
    }

    pub fn target(&self) -> CredentialTarget {
        self.target
    }

    pub fn outbound_index(&self) -> u16 {
        self.outbound_index
    }

    pub fn json_pointer(&self) -> &str {
        &self.json_pointer
    }

    fn validate(&self) -> Result<(), CredentialSlotError> {
        let expected = Self::new(
            self.reference.clone(),
            self.target,
            usize::from(self.outbound_index),
        )?;
        if expected.json_pointer != self.json_pointer {
            return Err(CredentialSlotError::PointerMismatch);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialSlotWire {
    reference: CredentialRef,
    target: CredentialTarget,
    outbound_index: u16,
    json_pointer: String,
}

impl<'de> Deserialize<'de> for CredentialSlot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CredentialSlotWire::deserialize(deserializer)?;
        let slot = Self {
            reference: wire.reference,
            target: wire.target,
            outbound_index: wire.outbound_index,
            json_pointer: wire.json_pointer,
        };
        slot.validate().map_err(serde::de::Error::custom)?;
        Ok(slot)
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum CredentialSlotError {
    #[error("credential slot kind does not match its reference kind")]
    KindMismatch,
    #[error("credential slot outbound index is out of range")]
    OutboundIndexOutOfRange,
    #[error("credential slot JSON pointer does not match its closed target")]
    PointerMismatch,
    #[error("credential slot list exceeds the supported bound")]
    TooManySlots,
    #[error("credential slot JSON pointer is duplicated")]
    DuplicatePointer,
    #[error("one credential id is used with more than one credential kind")]
    ConflictingReferenceKind,
    #[error("credential slot target does not contain an empty string placeholder")]
    NonEmptyPlaceholder,
}

pub(crate) fn validate_slots(
    root: &serde_json::Value,
    slots: &[CredentialSlot],
) -> Result<(), CredentialSlotError> {
    if slots.len() > MAX_CREDENTIAL_SLOTS {
        return Err(CredentialSlotError::TooManySlots);
    }
    let mut pointers = BTreeSet::new();
    let mut reference_kinds = BTreeMap::new();
    for slot in slots {
        slot.validate()?;
        if !pointers.insert(slot.json_pointer()) {
            return Err(CredentialSlotError::DuplicatePointer);
        }
        match reference_kinds.insert(slot.reference().id(), slot.reference().kind()) {
            Some(kind) if kind != slot.reference().kind() => {
                return Err(CredentialSlotError::ConflictingReferenceKind);
            }
            _ => {}
        }
        if root.pointer(slot.json_pointer()) != Some(&serde_json::Value::String(String::new())) {
            return Err(CredentialSlotError::NonEmptyPlaceholder);
        }
    }
    Ok(())
}

/// Borrowed secret accepted only at the future native vault provisioning edge.
/// It is never serializable, cloneable, displayable, or owned by profile state.
pub struct CredentialSecret<'a>(&'a str);

impl<'a> CredentialSecret<'a> {
    pub fn new(value: &'a str) -> Result<Self, InvalidCredentialSecret> {
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_SECRET_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(InvalidCredentialSecret);
        }
        Ok(Self(value))
    }

    pub fn expose_to_vault(&self) -> &str {
        self.0
    }
}

impl fmt::Debug for CredentialSecret<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSecret([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("credential secret is empty, oversized, or contains control characters")]
pub struct InvalidCredentialSecret;
