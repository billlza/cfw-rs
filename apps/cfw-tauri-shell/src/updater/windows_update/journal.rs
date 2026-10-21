//! A Windows MSI transaction is not a macOS bundle swap. Stored fields are
//! expectations/receipts; package and installation trust is re-observed natively.
use crate::{
    private_store::{AtomicWriteError, PrivateDirectory, PrivateDocument, PrivateReadError},
    process_identity::ProcessIdentity,
};
use cfw_core::update::UpdateAuthorization;
use cfw_windows_engine::{runtime_host::InstallationSnapshot, update_package::MsiIdentity};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const DOCUMENT: PrivateDocument = PrivateDocument {
    subject: "Windows update transaction",
    file: "update-msi-v1.json",
    temporary: ".update-msi-v1.tmp",
    maximum_bytes: 64 * 1024,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Phase {
    HandedOff,
    Finishing {
        process: ProcessIdentity,
    },
    Launching {
        process: ProcessIdentity,
    },
    Installing {
        process: ProcessIdentity,
        installer: ProcessIdentity,
        overdue: bool,
    },
    Finished {
        process: Option<ProcessIdentity>,
        exit_code: Option<u32>,
        disposition: Disposition,
        code: Option<String>,
    },
}
impl Phase {
    fn permits(&self, next: &Self) -> bool {
        match (self, next) {
            (Self::HandedOff, Self::Finishing { .. })
            | (Self::Finishing { .. }, Self::Launching { .. })
            | (Self::Launching { .. }, Self::Installing { .. })
            | (Self::Launching { .. } | Self::Installing { .. }, Self::Finished { .. }) => true,
            (Self::HandedOff | Self::Finishing { .. }, Self::Finished { disposition, .. }) => {
                *disposition != Disposition::Installed
            }
            (
                Self::Installing {
                    process: a,
                    installer: b,
                    overdue: false,
                },
                Self::Installing {
                    process: c,
                    installer: d,
                    overdue: true,
                },
            ) => a == c && b == d,
            (
                Self::Finished {
                    disposition: Disposition::Original,
                    ..
                },
                Self::Finished {
                    disposition: Disposition::Original,
                    ..
                },
            ) => true,
            _ => false,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Disposition {
    Installed,
    Original,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    schema_version: u32,
    pub transaction: Uuid,
    pub original: InstallationSnapshot,
    pub target: MsiIdentity,
    pub authorization: UpdateAuthorization,
    pub package_sha256: String,
    pub dashboard: ProcessIdentity,
    pub phase: Phase,
}
impl Record {
    pub fn new(
        transaction: Uuid,
        original: InstallationSnapshot,
        target: MsiIdentity,
        authorization: UpdateAuthorization,
        digest: [u8; 32],
        dashboard: ProcessIdentity,
    ) -> Self {
        Self {
            schema_version: 1,
            transaction,
            original,
            target,
            authorization,
            package_sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
            dashboard,
            phase: Phase::HandedOff,
        }
    }
    pub fn target_snapshot(&self) -> InstallationSnapshot {
        InstallationSnapshot::from_package(&self.target)
    }
    pub fn same_request(&self, other: &Self) -> bool {
        let mut compared = other.clone();
        compared.phase = self.phase.clone();
        &compared == self
    }
    pub fn finisher(&self) -> Option<&ProcessIdentity> {
        match &self.phase {
            Phase::Finishing { process }
            | Phase::Launching { process }
            | Phase::Installing { process, .. } => Some(process),
            Phase::Finished { process, .. } => process.as_ref(),
            Phase::HandedOff => None,
        }
    }
    fn validate(&self) -> Result<(), String> {
        let bad = || "Windows update record violates its version 1 contract".to_owned();
        let from = semver::Version::parse(&self.original.release.version).map_err(|_| bad())?;
        let to = semver::Version::parse(&self.target.version).map_err(|_| bad())?;
        let digest = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let guid = |s: &str| {
            Uuid::parse_str(s)
                .is_ok_and(|id| !id.is_nil() && id.braced().to_string().to_ascii_uppercase() == s)
        };
        if self.schema_version != 1
            || self.transaction.is_nil()
            || from.to_string() != self.original.release.version
            || to.to_string() != self.target.version
            || to <= from
            || self.original.release.build == 0
            || self.target.build <= self.original.release.build
            || self.target.architecture != "x86_64"
            || !digest(&self.package_sha256)
            || !digest(&self.original.manifest_sha256)
            || !digest(&self.target.runtime_manifest_sha256)
            || self.original.manifest_sha256 == self.target.runtime_manifest_sha256
            || ![
                &self.original.release.product_code,
                &self.original.release.package_code,
                &self.target.product_code,
                &self.target.package_code,
            ]
            .into_iter()
            .all(|s| guid(s))
            || self.target.product_code == self.original.release.product_code
            || self.target.package_code == self.original.release.package_code
            || self.authorization.version != self.target.version
        {
            return Err(bad());
        }
        self.authorization
            .validate_for(cfw_core::update::ReleaseTarget::WindowsX64)
            .map_err(|e| e.to_string())?;
        if let Phase::Installing {
            process, installer, ..
        } = &self.phase
        {
            if process.pid == installer.pid {
                return Err(bad());
            }
        }
        if let Phase::Finished {
            exit_code,
            disposition,
            code,
            ..
        } = &self.phase
        {
            if *disposition == Disposition::Installed {
                if *exit_code != Some(0) || code.is_some() {
                    return Err(bad());
                }
            } else if code.as_ref().is_none_or(|s| {
                s.is_empty()
                    || s.len() > 64
                    || !s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            }) {
                return Err(bad());
            }
        }
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() as u64 > DOCUMENT.maximum_bytes {
            return Err("Windows update record is oversized".into());
        }
        Ok(bytes)
    }
}

pub(super) struct Journal {
    root: PathBuf,
}
impl Journal {
    pub fn new(home: &Path) -> Self {
        Self {
            root: home.to_owned(),
        }
    }
    fn directory(&self) -> Result<PrivateDirectory, String> {
        PrivateDirectory::open_or_create(&self.root, DOCUMENT)
    }
    pub fn load(&self) -> Result<Option<Record>, String> {
        let directory = self.directory()?;
        directory.lock()?;
        read(&directory)
    }
    pub fn begin(&self, record: &Record) -> Result<(), String> {
        let directory = self.directory()?;
        directory.lock()?;
        if read(&directory)?.is_some() {
            return Err("an earlier Windows update must be resolved before handoff".into());
        }
        write(&directory, record)
    }
    pub fn change(&self, expected: &Record, phase: Phase) -> Result<Record, String> {
        if !expected.phase.permits(&phase) {
            return Err("invalid Windows update phase transition".into());
        }
        let directory = self.directory()?;
        directory.lock()?;
        if read(&directory)?.as_ref() != Some(expected) {
            return Err("Windows update changed during handoff".into());
        }
        let mut next = expected.clone();
        next.phase = phase;
        write(&directory, &next)?;
        Ok(next)
    }
    pub fn clear(&self, expected: &Record) -> Result<(), String> {
        let directory = self.directory()?;
        directory.lock()?;
        if read(&directory)?.as_ref() != Some(expected) {
            return Err("Windows update changed before cleanup".into());
        }
        directory.remove()
    }
}
fn read(directory: &PrivateDirectory) -> Result<Option<Record>, String> {
    let bytes = match directory.read() {
        Ok(None) => return Ok(None),
        Ok(Some(bytes)) => bytes,
        Err(PrivateReadError::Failed(e) | PrivateReadError::Unusable(e)) => return Err(e),
    };
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|e| format!("Windows update record: {e}"))?;
    if record.bytes()? != bytes {
        return Err("Windows update record is not canonical".into());
    }
    Ok(Some(record))
}
fn write(directory: &PrivateDirectory, record: &Record) -> Result<(), String> {
    directory
        .write_atomic_with_directory_sync(&record.bytes()?, File::sync_all)
        .map_err(|e| match e {
            AtomicWriteError::Failed(e) => e,
            AtomicWriteError::CommitUncertain(e) => {
                format!("Windows update record durability is uncertain: {e}")
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_core::update::ReleaseTarget;
    use cfw_windows_engine::runtime_host::InstalledRelease;
    fn record() -> Record {
        let version = "0.5.1";
        let target = ReleaseTarget::WindowsX64;
        let archive = target.archive_name(version);
        let dashboard =
            crate::process_identity::current_process_identity(&std::env::current_exe().unwrap())
                .unwrap();
        Record::new(
            Uuid::new_v4(),
            InstallationSnapshot {
                release: InstalledRelease {
                    version: "0.5.0".into(),
                    build: 1,
                    product_code: Uuid::from_u128(1).braced().to_string().to_ascii_uppercase(),
                    package_code: Uuid::from_u128(2).braced().to_string().to_ascii_uppercase(),
                },
                manifest_sha256: "ab".repeat(32),
            },
            MsiIdentity {
                version: version.into(),
                build: 2,
                product_code: Uuid::from_u128(3).braced().to_string().to_ascii_uppercase(),
                package_code: Uuid::from_u128(4).braced().to_string().to_ascii_uppercase(),
                architecture: "x86_64".into(),
                minimum_windows_version: "10.0.19041".into(),
                runtime_manifest_sha256: "cd".repeat(32),
            },
            UpdateAuthorization {
                version: version.into(),
                download_url: target.download_url(version, &archive),
                archive_name: archive,
                signature: "unverified-signature-claim".into(),
            },
            [42; 32],
            dashboard,
        )
    }
    #[test]
    fn record_rejects_replayed_release_claims_and_success_without_a_zero_exit() {
        let original = record();
        original.bytes().unwrap();
        for field in ["archive_name", "download_url", "signature"] {
            let mut json = serde_json::to_value(&original).unwrap();
            json["authorization"][field] = serde_json::json!("");
            let changed: Record = serde_json::from_value(json).unwrap();
            assert!(changed.bytes().is_err());
        }
        let mut changed = original.clone();
        changed.phase = Phase::Finished {
            process: None,
            exit_code: Some(3010),
            disposition: Disposition::Installed,
            code: None,
        };
        assert!(changed.bytes().is_err());
        changed.phase = Phase::Finished {
            process: None,
            exit_code: None,
            disposition: Disposition::Uncertain,
            code: Some("installation_unconfirmed".into()),
        };
        changed.bytes().unwrap();
        let mut extra = serde_json::to_value(&original).unwrap();
        extra["trusted"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Record>(extra).is_err());
    }
    #[test]
    fn journal_refuses_premature_success_and_preserves_mismatched_transactions() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("private");
        let journal = Journal::new(&home);
        let initial = record();
        journal.begin(&initial).unwrap();
        assert!(initial.finisher().is_none());
        assert!(initial.same_request(&initial));
        assert!(
            journal
                .change(
                    &initial,
                    Phase::Finished {
                        process: None,
                        exit_code: Some(0),
                        disposition: Disposition::Installed,
                        code: None
                    }
                )
                .is_err()
        );
        assert_eq!(journal.load().unwrap(), Some(initial.clone()));
        let mut foreign = initial.clone();
        foreign.transaction = Uuid::new_v4();
        assert!(journal.clear(&foreign).is_err());
        let finishing = journal
            .change(
                &initial,
                Phase::Finishing {
                    process: initial.dashboard.clone(),
                },
            )
            .unwrap();
        assert!(initial.same_request(&finishing));
        assert_eq!(finishing.finisher(), Some(&initial.dashboard));
        assert!(
            journal
                .change(
                    &initial,
                    Phase::Launching {
                        process: initial.dashboard.clone()
                    }
                )
                .is_err()
        );
        let launching = journal
            .change(
                &finishing,
                Phase::Launching {
                    process: initial.dashboard.clone(),
                },
            )
            .unwrap();
        let completed = journal
            .change(
                &launching,
                Phase::Finished {
                    process: Some(initial.dashboard.clone()),
                    exit_code: Some(0),
                    disposition: Disposition::Installed,
                    code: None,
                },
            )
            .unwrap();
        assert_eq!(
            completed.target_snapshot().manifest_sha256,
            initial.target.runtime_manifest_sha256
        );
        assert!(journal.change(&completed, Phase::HandedOff).is_err());
        journal.clear(&completed).unwrap();
        assert!(journal.load().unwrap().is_none());
    }
}
