use std::fs::File;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::admission::BundleIdentity;
use crate::private_store::{AtomicWriteError, PrivateDirectory, PrivateDocument, PrivateReadError};
use crate::process_identity::ProcessIdentity;

const SCHEMA_VERSION: u16 = 1;
pub(super) use super::install_lease::{UpdateInstallLease, UpdateInstallLeaseError};
const RECORD_DOCUMENT: PrivateDocument = PrivateDocument {
    subject: "update installation record",
    file: "update-install-v1.json",
    temporary: ".update-install-v1.tmp",
    maximum_bytes: 4 * 1024,
};

/// Where one installation attempt stands. A later release reads the record an
/// earlier one wrote, so this vocabulary and the record layout are a
/// cross-version contract: extend it only with a new schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum InstallPhase {
    /// The dashboard stopped networking and started the installer process.
    HandedOff,
    /// Both background services are unregistered; nothing was exchanged yet.
    Decommissioned,
    /// The new bundle is installed. The replaced one is kept in staging until
    /// the new application has started.
    Swapped,
    /// The attempt ended and the installed application was not replaced.
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallRecord {
    schema_version: u16,
    pub(super) transaction: Uuid,
    pub(super) phase: InstallPhase,
    pub(super) from: RecordedIdentity,
    pub(super) to: RecordedIdentity,
    /// The dashboard that handed off. The installer waits for it to exit.
    pub(super) dashboard: ProcessIdentity,
    /// Stable failure code, present exactly when the attempt was aborted.
    pub(super) failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordedIdentity {
    pub(super) version: String,
    pub(super) build: u64,
}

impl From<&BundleIdentity> for RecordedIdentity {
    fn from(identity: &BundleIdentity) -> Self {
        Self {
            version: identity.version.clone(),
            build: identity.build,
        }
    }
}

impl InstallRecord {
    pub(super) fn handed_off(
        transaction: Uuid,
        from: &BundleIdentity,
        to: &BundleIdentity,
        dashboard: ProcessIdentity,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            transaction,
            phase: InstallPhase::HandedOff,
            from: from.into(),
            to: to.into(),
            dashboard,
            failure: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        let canonical_version = |identity: &RecordedIdentity| {
            semver::Version::parse(&identity.version)
                .is_ok_and(|parsed| parsed.to_string() == identity.version)
                && identity.build > 0
        };
        if self.schema_version != SCHEMA_VERSION
            || self.transaction.is_nil()
            || !canonical_version(&self.from)
            || !canonical_version(&self.to)
            || self.to.build <= self.from.build
            || self.failure.is_some() != (self.phase == InstallPhase::Aborted)
            || self.failure.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 64
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
            })
        {
            return Err("update installation record is not a valid version 1 record".into());
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("failed to encode update installation record: {error}"))?;
        if bytes.len() as u64 > RECORD_DOCUMENT.maximum_bytes {
            return Err("update installation record exceeds its size bound".into());
        }
        Ok(bytes)
    }
}

/// What the record file holds, as far as this version can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Recorded {
    Absent,
    Valid(InstallRecord),
    /// The file was read safely, but its content is not a version 1 record.
    /// The detail says why; the content itself is never acted on.
    Uninterpretable(String),
}

#[derive(Debug, Clone)]
pub(super) struct InstallJournal {
    root: PathBuf,
}

impl InstallJournal {
    pub(super) fn new(app_home: impl Into<PathBuf>) -> Self {
        Self {
            root: app_home.into(),
        }
    }

    pub(super) fn load(&self) -> Result<Option<InstallRecord>, String> {
        match self.inspect()? {
            Recorded::Absent => Ok(None),
            Recorded::Valid(record) => Ok(Some(record)),
            Recorded::Uninterpretable(detail) => Err(detail),
        }
    }

    /// Reads the record and tells an unusable store apart from a stored file
    /// this version cannot interpret.
    pub(super) fn inspect(&self) -> Result<Recorded, String> {
        let directory = self.directory()?;
        directory.lock()?;
        read_record(&directory)
    }

    /// Removes a record file this version cannot interpret, so it cannot keep
    /// every later installation from starting. A valid record is never
    /// removed this way.
    pub(super) fn discard_uninterpretable(&self) -> Result<(), String> {
        let directory = self.directory()?;
        directory.lock()?;
        match read_record(&directory)? {
            Recorded::Uninterpretable(_) => directory.remove(),
            Recorded::Absent => Ok(()),
            Recorded::Valid(_) => Err("a valid update installation record is not discarded".into()),
        }
    }

    /// Records the hand-off. An unfinished earlier attempt must be resolved
    /// first; it is never overwritten.
    ///
    /// The one exception is a hand-off record of the same dashboard process:
    /// that process only survives a hand-off whose installer was never
    /// started, so the record is its own abandoned attempt.
    pub(super) fn begin(&self, record: &InstallRecord) -> Result<(), String> {
        if record.phase != InstallPhase::HandedOff {
            return Err("an update installation begins with the hand-off".into());
        }
        let directory = self.directory()?;
        directory.lock()?;
        match read_record(&directory)? {
            Recorded::Absent => write_record(&directory, record),
            Recorded::Valid(existing)
                if existing.phase == InstallPhase::HandedOff
                    && existing.dashboard == record.dashboard =>
            {
                write_record(&directory, record)
            }
            Recorded::Valid(existing) => Err(format!(
                "an earlier update installation record in phase {:?} has not been resolved",
                existing.phase
            )),
            Recorded::Uninterpretable(detail) => Err(detail),
        }
    }

    /// Moves the named transaction from `expected` to `next`.
    pub(super) fn advance(
        &self,
        transaction: &Uuid,
        expected: InstallPhase,
        next: InstallPhase,
    ) -> Result<InstallRecord, String> {
        if !matches!(
            (expected, next),
            (InstallPhase::HandedOff, InstallPhase::Decommissioned)
                | (InstallPhase::Decommissioned, InstallPhase::Swapped)
        ) {
            return Err("invalid update installation phase transition".into());
        }
        self.rewrite(transaction, &[expected], |record| record.phase = next)
    }

    /// Ends the named transaction without a replaced application. Only an
    /// attempt that has not exchanged the bundles can be aborted.
    pub(super) fn abort(
        &self,
        transaction: &Uuid,
        code: &'static str,
    ) -> Result<InstallRecord, String> {
        self.rewrite(
            transaction,
            &[InstallPhase::HandedOff, InstallPhase::Decommissioned],
            |record| {
                record.phase = InstallPhase::Aborted;
                record.failure = Some(code.to_owned());
            },
        )
    }

    /// Removes the record once its outcome has been acted on.
    pub(super) fn clear(&self, transaction: &Uuid) -> Result<(), String> {
        let directory = self.directory()?;
        directory.lock()?;
        match read_record(&directory)? {
            Recorded::Valid(record) if record.transaction == *transaction => directory.remove(),
            Recorded::Valid(_) => Err("a different update installation record is present".into()),
            Recorded::Uninterpretable(detail) => Err(detail),
            Recorded::Absent => Ok(()),
        }
    }

    fn rewrite(
        &self,
        transaction: &Uuid,
        expected: &[InstallPhase],
        change: impl FnOnce(&mut InstallRecord),
    ) -> Result<InstallRecord, String> {
        let directory = self.directory()?;
        directory.lock()?;
        let mut record = match read_record(&directory)? {
            Recorded::Valid(record) => record,
            Recorded::Absent => return Err("update installation record is missing".into()),
            Recorded::Uninterpretable(detail) => return Err(detail),
        };
        if record.transaction != *transaction || !expected.contains(&record.phase) {
            return Err(format!(
                "update installation record is {:?}, expected {expected:?} of this transaction",
                record.phase
            ));
        }
        change(&mut record);
        write_record(&directory, &record)?;
        Ok(record)
    }

    fn directory(&self) -> Result<PrivateDirectory, String> {
        PrivateDirectory::open_or_create(&self.root, RECORD_DOCUMENT)
    }
}

fn read_record(directory: &PrivateDirectory) -> Result<Recorded, String> {
    let bytes = match directory.read() {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(Recorded::Absent),
        // Whatever sits in the record's place is not a record this version
        // can act on; like one it cannot interpret, it is discarded rather
        // than left to refuse every later installation.
        Err(PrivateReadError::Unusable(detail)) => return Ok(Recorded::Uninterpretable(detail)),
        Err(PrivateReadError::Failed(detail)) => return Err(detail),
    };
    let interpreted = serde_json::from_slice::<InstallRecord>(&bytes)
        .map_err(|error| format!("update installation record JSON is invalid: {error}"))
        .and_then(|record| {
            if record.canonical_bytes()? != bytes {
                return Err("update installation record is not canonical JSON".into());
            }
            Ok(record)
        });
    Ok(match interpreted {
        Ok(record) => Recorded::Valid(record),
        Err(detail) => Recorded::Uninterpretable(detail),
    })
}

fn write_record(directory: &PrivateDirectory, record: &InstallRecord) -> Result<(), String> {
    directory
        .write_atomic_with_directory_sync(&record.canonical_bytes()?, File::sync_all)
        .map_err(|error| match error {
            AtomicWriteError::Failed(message) => message,
            AtomicWriteError::CommitUncertain(message) => {
                format!("update installation record durability is uncertain: {message}")
            }
        })
}

#[cfg(test)]
pub(super) mod tests;
