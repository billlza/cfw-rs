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
    target_manifest_sha256: Option<String>,
    original_start: u32,
    original_running: bool,
    phase: Phase,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Preparing,
    Prepared {
        off: AuthoritySnapshot,
    },
    Committing {
        off: AuthoritySnapshot,
    },
    /// Retain the original identity/startup for MSI rollback even after the
    /// target is admitted. Only the exact target may start while this remains.
    Committed {
        off: AuthoritySnapshot,
    },
    /// Block target startup before MSI restores any original files.
    RetiringTarget {
        off: AuthoritySnapshot,
    },
    /// Only the original image may restart while rollback completes.
    RestoringOriginal,
}
impl Record {
    fn preparing(
        transaction: Uuid,
        manifest_sha256: String,
        target_manifest_sha256: Option<String>,
        original_start: u32,
        original_running: bool,
    ) -> Result<Self> {
        let value = Self {
            schema_version: 3,
            transaction,
            manifest_sha256,
            target_manifest_sha256,
            original_start,
            original_running,
            phase: Phase::Preparing,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        // These are the native SERVICE_AUTO_START and SERVICE_DEMAND_START
        // values. Disabled is an operation result, never an original default.
        if self.schema_version != 3
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
        if let Some(target) = &self.target_manifest_sha256 {
            super::manifest::Manifest::digest(target)?;
            if target == &self.manifest_sha256 {
                return Err(HostError::State(
                    "maintenance target is the original manifest",
                ));
            }
        }
        if matches!(
            self.phase,
            Phase::Committing { .. }
                | Phase::Committed { .. }
                | Phase::RetiringTarget { .. }
                | Phase::RestoringOriginal
        ) && self.target_manifest_sha256.is_none()
        {
            return Err(HostError::State(
                "committed maintenance has no target manifest",
            ));
        }
        if let Phase::Prepared { off }
        | Phase::Committing { off }
        | Phase::Committed { off }
        | Phase::RetiringTarget { off } = &self.phase
        {
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

    fn bind_original(&self, transaction: Uuid, manifest: &str) -> Result<()> {
        if self.transaction != transaction || self.manifest_sha256 != manifest {
            return Err(HostError::State(
                "maintenance belongs to a different transaction or original manifest",
            ));
        }
        Ok(())
    }

    fn bind_target(&self, transaction: Uuid, manifest: &str) -> Result<()> {
        if self.transaction != transaction
            || self.target_manifest_sha256.as_deref() != Some(manifest)
        {
            return Err(HostError::State(
                "maintenance belongs to a different transaction or target manifest",
            ));
        }
        Ok(())
    }

    fn permits_start(&self, manifest: &str) -> bool {
        match self.phase {
            Phase::Committed { .. } => self.target_manifest_sha256.as_deref() == Some(manifest),
            Phase::RestoringOriginal => self.original_running && self.manifest_sha256 == manifest,
            _ => false,
        }
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
        Record::preparing(Uuid::from_u128(1), "ab".repeat(32), None, 3, true).unwrap()
    }
    #[test]
    fn maintenance_record_requires_exact_transaction_start_mode_and_manifest_identity() {
        let original = record().encode().unwrap();
        Record::decode(&original).unwrap();
        for (key, value) in [
            ("schema_version", serde_json::json!(1)),
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

    #[test]
    fn committed_update_admits_only_its_target_and_retains_original_rollback_identity() {
        let transaction = Uuid::from_u128(9);
        let original = "ab".repeat(32);
        let target = "cd".repeat(32);
        let mut value =
            Record::preparing(transaction, original.clone(), Some(target.clone()), 2, true)
                .unwrap();
        let off = AuthoritySnapshot {
            state: AuthorityState::Off,
            revision: Some(8),
            root: Some(RootContext {
                installation_id: Uuid::from_u128(2),
                epoch: 1,
                generation: 1,
            }),
        };
        assert!(!value.permits_start(&target));
        value.phase = Phase::Prepared { off: off.clone() };
        assert!(!value.permits_start(&target));
        value.phase = Phase::Committing { off: off.clone() };
        assert!(!value.permits_start(&target));
        value.phase = Phase::Committed { off };
        let decoded = Record::decode(&value.encode().unwrap()).unwrap();
        assert!(decoded.permits_start(&target));
        assert!(!decoded.permits_start(&original));
        decoded.bind_original(transaction, &original).unwrap();
        decoded.bind_target(transaction, &target).unwrap();
        assert!(decoded.bind_original(transaction, &target).is_err());
        assert!(decoded.bind_target(transaction, &original).is_err());
        assert!(decoded.bind_target(Uuid::from_u128(10), &target).is_err());
        assert_eq!(decoded.original_start, 2);
        assert_eq!(decoded.manifest_sha256, original);
    }

    #[test]
    fn update_target_cannot_be_missing_malformed_or_equal_to_the_original() {
        for target in [
            "ab".repeat(32),
            "CD".repeat(32),
            "cd".repeat(31),
            "gg".repeat(32),
        ] {
            assert!(
                Record::preparing(Uuid::from_u128(1), "ab".repeat(32), Some(target), 3, false)
                    .is_err()
            );
        }
        let mut value = record();
        assert!(
            value
                .bind_target(value.transaction, &"cd".repeat(32))
                .is_err()
        );
        value.phase = Phase::Committed {
            off: AuthoritySnapshot {
                state: AuthorityState::Off,
                revision: Some(8),
                root: Some(RootContext {
                    installation_id: Uuid::from_u128(2),
                    epoch: 1,
                    generation: 1,
                }),
            },
        };
        assert!(value.encode().is_err());
    }

    #[test]
    fn rollback_admission_tracks_the_original_running_state_and_never_admits_target() {
        let original = "ab".repeat(32);
        let target = "cd".repeat(32);
        for was_running in [true, false] {
            let mut value = Record::preparing(
                Uuid::from_u128(1),
                original.clone(),
                Some(target.clone()),
                3,
                was_running,
            )
            .unwrap();
            value.phase = Phase::RestoringOriginal;
            let decoded = Record::decode(&value.encode().unwrap()).unwrap();
            assert_eq!(decoded.permits_start(&original), was_running);
            assert!(!decoded.permits_start(&target));
            assert!(!decoded.permits_start(&"ef".repeat(32)));
            value.phase = Phase::RetiringTarget {
                off: AuthoritySnapshot {
                    state: AuthorityState::Off,
                    revision: Some(8),
                    root: Some(RootContext {
                        installation_id: Uuid::from_u128(2),
                        epoch: 1,
                        generation: 1,
                    }),
                },
            };
            Record::decode(&value.encode().unwrap()).unwrap();
            assert!(!value.permits_start(&original));
            assert!(!value.permits_start(&target));
        }
        let mut service_only = record();
        service_only.phase = Phase::RestoringOriginal;
        assert!(service_only.encode().is_err());
    }
}
