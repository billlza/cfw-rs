//! Secret-bearing start tickets, owner capabilities and credential material.

use super::*;

pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    pub fn new(bytes: &[u8], maximum: usize) -> Result<Self, CodecError> {
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn expose(&self, consume: impl FnOnce(&[u8])) {
        consume(&self.0);
    }

    pub(super) fn transport_copy(&self) -> Vec<u8> {
        self.0.clone()
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct StartTicket(pub(super) SensitiveBytes);
impl StartTicket {
    pub fn new(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != TICKET_BYTES {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(SensitiveBytes::new(bytes, TICKET_BYTES)?))
    }

    pub fn expose(&self, consume: impl FnOnce(&[u8])) {
        self.0.expose(consume);
    }
}

pub struct OwnerCapability(pub(super) SensitiveBytes);
impl OwnerCapability {
    pub fn new(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != CAPABILITY_BYTES {
            return Err(CodecError::BoundViolation);
        }
        Ok(Self(SensitiveBytes::new(bytes, CAPABILITY_BYTES)?))
    }
}

pub struct SecretSlot {
    reference: CredentialRef,
    bytes: SensitiveBytes,
}
impl SecretSlot {
    pub fn new(reference: CredentialRef, bytes: &[u8]) -> Result<Self, CodecError> {
        Ok(Self {
            reference,
            bytes: SensitiveBytes::new(bytes, MAX_INDIVIDUAL_SECRET_BYTES)?,
        })
    }
}

pub struct SecretMaterial {
    slots: Vec<SecretSlot>,
    total_bytes: usize,
}
impl SecretMaterial {
    pub fn new(slots: Vec<SecretSlot>) -> Result<Self, CodecError> {
        if slots.len() > MAX_CREDENTIAL_SLOTS {
            return Err(CodecError::BoundViolation);
        }
        let mut references = BTreeSet::new();
        let mut total_bytes = 0usize;
        for slot in &slots {
            if !references.insert(slot.reference.id()) {
                return Err(CodecError::BoundViolation);
            }
            total_bytes = total_bytes
                .checked_add(slot.bytes.0.len())
                .ok_or(CodecError::BoundViolation)?;
            if total_bytes > MAX_TOTAL_SECRET_BYTES {
                return Err(CodecError::BoundViolation);
            }
        }
        Ok(Self { slots, total_bytes })
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn total_byte_count(&self) -> usize {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests;
