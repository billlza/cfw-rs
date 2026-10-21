//! Durable service-maintenance intent. This is not MSI/package acceptance or
//! permission to replace files: the installed image pins remain held by callers.
use super::{HostError, Result};
use crate::authority::AuthoritySnapshot;
use cfw_engine_api::authority_v1::AuthorityState;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(windows)]
mod native;
#[cfg(all(windows, feature = "native-service-validation"))]
pub use native::ServiceMaintenanceFault;
#[cfg(windows)]
pub(super) use native::require_service_start_allowed;

const MAX_RECORD: usize = 2048;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    transaction: Uuid,
    manifest_sha256: String,
    original_start: u32,
    phase: Phase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Preparing,
    Prepared { off: AuthoritySnapshot },
}
impl Record {
    fn preparing(transaction: Uuid, manifest_sha256: String, original_start: u32) -> Result<Self> {
        let value = Self {
            schema_version: 1,
            transaction,
            manifest_sha256,
            original_start,
            phase: Phase::Preparing,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        // These are the native SERVICE_AUTO_START and SERVICE_DEMAND_START
        // values. Disabled is an operation result, never an original default.
        if self.schema_version != 1
            || self.transaction.is_nil()
            || !matches!(self.original_start, 2 | 3)
            || self.manifest_sha256.len() != 64
            || !self
                .manifest_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(HostError::State("invalid service maintenance record"));
        }
        if let Phase::Prepared { off } = &self.phase {
            let root = off
                .root
                .as_ref()
                .ok_or(HostError::State("maintenance Off has no root"))?;
            if off.state != AuthorityState::Off
                || off.revision.is_none_or(|r| r == 0)
                || root.installation_id.is_nil()
                || (root.epoch == 0) != (root.generation == 0)
            {
                return Err(HostError::State(
                    "maintenance record does not contain explicit Off",
                ));
            }
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| HostError::State("maintenance record encoding failed"))?;
        if bytes.len() > MAX_RECORD {
            return Err(HostError::State("maintenance record is oversized"));
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD {
            return Err(HostError::State("maintenance record size is invalid"));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| HostError::State("maintenance record decoding failed"))?;
        if value.encode()? != bytes {
            return Err(HostError::State("maintenance record is not canonical"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::authority_v1::RootContext;
    fn record() -> Record {
        Record::preparing(Uuid::from_u128(1), "ab".repeat(32), 3).unwrap()
    }
    #[test]
    fn maintenance_record_requires_exact_transaction_start_mode_and_manifest_identity() {
        let original = record().encode().unwrap();
        Record::decode(&original).unwrap();
        for (key, value) in [
            ("schema_version", serde_json::json!(2)),
            ("transaction", serde_json::json!(Uuid::nil())),
            ("original_start", serde_json::json!(4)),
            ("manifest_sha256", serde_json::json!("AB".repeat(32))),
            ("path", serde_json::json!("C:\\arbitrary")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
            changed[key] = value;
            assert!(Record::decode(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        let mut duplicate = String::from_utf8(original.clone()).unwrap();
        duplicate.pop();
        duplicate.push_str(",\"original_start\":3}");
        assert!(Record::decode(duplicate.as_bytes()).is_err());
        assert!(Record::decode(&[original, vec![b' ']].concat()).is_err());
        assert!(Record::decode(&vec![b' '; MAX_RECORD + 1]).is_err());
    }
    #[test]
    fn maintenance_prepared_phase_requires_explicit_bound_off() {
        let off = AuthoritySnapshot {
            state: AuthorityState::Off,
            revision: Some(8),
            root: Some(RootContext {
                installation_id: Uuid::from_u128(2),
                epoch: 1,
                generation: 1,
            }),
        };
        let mut value = record();
        value.phase = Phase::Prepared { off: off.clone() };
        Record::decode(&value.encode().unwrap()).unwrap();
        for changed in [
            AuthoritySnapshot {
                state: AuthorityState::Recovering,
                ..off.clone()
            },
            AuthoritySnapshot {
                revision: None,
                ..off.clone()
            },
            AuthoritySnapshot { root: None, ..off },
        ] {
            value.phase = Phase::Prepared { off: changed };
            assert!(value.encode().is_err());
        }
    }
}
