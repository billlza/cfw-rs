use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::admission::BundleIdentity;
use crate::legacy::ProcessIdentity;
use crate::private_store::{
    AtomicWriteError, LockFileError, PrivateDirectory, PrivateDocument, PrivateReadError,
};

const SCHEMA_VERSION: u16 = 1;
const LEASE_FILE: &str = "update-install-v1.lock";
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

/// Held by the installer process from before it unregisters services until the
/// bundles are exchanged. A dashboard refuses to start while it is held, so no
/// instance of the application can re-register services underneath the
/// exchange.
#[derive(Debug)]
pub(crate) struct UpdateInstallLease {
    _file: File,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpdateInstallLeaseError {
    /// Another process holds the lease: an installation is in progress.
    Held,
    Unavailable(String),
}

impl std::fmt::Display for UpdateInstallLeaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held => formatter.write_str("an update installation is in progress"),
            Self::Unavailable(detail) => {
                write!(
                    formatter,
                    "update installation lease is unavailable: {detail}"
                )
            }
        }
    }
}

impl UpdateInstallLease {
    pub(crate) fn acquire(app_home: &Path) -> Result<Self, UpdateInstallLeaseError> {
        PrivateDirectory::open_or_create(app_home, RECORD_DOCUMENT)
            .map_err(UpdateInstallLeaseError::Unavailable)?
            .acquire_lock_file(LEASE_FILE)
            .map(|file| Self { _file: file })
            .map_err(|error| match error {
                LockFileError::Busy => UpdateInstallLeaseError::Held,
                LockFileError::UnsafeMetadata => {
                    UpdateInstallLeaseError::Unavailable("lock file has unsafe metadata".into())
                }
                LockFileError::Open(error)
                | LockFileError::Inspect(error)
                | LockFileError::Lock(error) => {
                    UpdateInstallLeaseError::Unavailable(error.to_string())
                }
            })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    pub(in crate::updater) fn dashboard() -> ProcessIdentity {
        serde_json::from_value(serde_json::json!({
            "uid": unsafe { libc::geteuid() },
            "pid": 4242,
            "start_identity": { "seconds": 1_790_000_000_u64, "microseconds": 7 },
            "executable": "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
        }))
        .expect("dashboard identity")
    }

    pub(in crate::updater) fn identity(version: &str, build: u64) -> BundleIdentity {
        BundleIdentity {
            version: version.into(),
            build,
        }
    }

    pub(in crate::updater) fn record(transaction: u128) -> InstallRecord {
        InstallRecord::handed_off(
            Uuid::from_u128(transaction),
            &identity("0.4.0", 40074),
            &identity("0.5.0", 50021),
            dashboard(),
        )
    }

    #[test]
    fn the_record_layout_is_the_version_one_contract() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        journal.begin(&record(7)).expect("begin");
        let stored = fs::read(home.path().join("update-install-v1.json")).expect("record file");
        assert_eq!(
            String::from_utf8(stored).expect("UTF-8"),
            concat!(
                r#"{"schema_version":1,"transaction":"00000000-0000-0000-0000-000000000007","#,
                r#""phase":"handed_off","from":{"version":"0.4.0","build":40074},"#,
                r#""to":{"version":"0.5.0","build":50021},"dashboard":{"uid":"#,
            )
            .to_owned()
                + &format!(
                    r#"{},"pid":4242,"start_identity":{{"seconds":1790000000,"microseconds":7}},"executable":"/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac"}},"failure":null}}"#,
                    unsafe { libc::geteuid() }
                )
        );
        let mode = fs::metadata(home.path().join("update-install-v1.json"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn phases_advance_only_forward_and_only_for_the_named_transaction() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        let transaction = Uuid::from_u128(1);
        assert_eq!(journal.load().expect("empty"), None);
        journal.begin(&record(1)).expect("begin");

        assert!(
            journal
                .advance(
                    &Uuid::from_u128(9),
                    InstallPhase::HandedOff,
                    InstallPhase::Decommissioned
                )
                .is_err(),
            "another transaction cannot advance this record"
        );
        assert!(
            journal
                .advance(&transaction, InstallPhase::HandedOff, InstallPhase::Swapped)
                .is_err(),
            "the exchange cannot be recorded before the services are unregistered"
        );
        assert!(
            journal
                .advance(
                    &transaction,
                    InstallPhase::Decommissioned,
                    InstallPhase::Swapped
                )
                .is_err(),
            "the recorded phase must match"
        );
        let decommissioned = journal
            .advance(
                &transaction,
                InstallPhase::HandedOff,
                InstallPhase::Decommissioned,
            )
            .expect("decommissioned");
        assert_eq!(decommissioned.phase, InstallPhase::Decommissioned);
        let swapped = journal
            .advance(
                &transaction,
                InstallPhase::Decommissioned,
                InstallPhase::Swapped,
            )
            .expect("swapped");
        assert_eq!(journal.load().expect("load"), Some(swapped));
        assert!(
            journal.abort(&transaction, "late").is_err(),
            "an exchanged installation is never reported as aborted"
        );

        assert!(journal.clear(&Uuid::from_u128(9)).is_err());
        journal.clear(&transaction).expect("clear");
        journal
            .clear(&transaction)
            .expect("clearing an absent record is not an error");
        assert_eq!(journal.load().expect("load"), None);
    }

    #[test]
    fn a_dashboard_replaces_only_its_own_unfinished_hand_off() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        journal.begin(&record(1)).expect("first hand-off");
        journal
            .begin(&record(2))
            .expect("the same dashboard hands off again");
        assert_eq!(journal.load().expect("load"), Some(record(2)));

        let mut another_dashboard = record(3);
        another_dashboard.dashboard = serde_json::from_value(serde_json::json!({
            "uid": unsafe { libc::geteuid() },
            "pid": 4243,
            "start_identity": { "seconds": 1_790_000_000_u64, "microseconds": 7 },
            "executable": "/Applications/Clash for Mac.app/Contents/MacOS/clash-for-mac",
        }))
        .expect("dashboard identity");
        assert!(
            journal.begin(&another_dashboard).is_err(),
            "the record of another dashboard is resolved, never replaced"
        );

        journal
            .advance(
                &Uuid::from_u128(2),
                InstallPhase::HandedOff,
                InstallPhase::Decommissioned,
            )
            .expect("an installer is at work");
        assert!(
            journal.begin(&record(4)).is_err(),
            "a record an installer advanced is never replaced"
        );
    }

    #[test]
    fn an_abort_records_its_stable_code() {
        for phase in [InstallPhase::HandedOff, InstallPhase::Decommissioned] {
            let home = tempfile::tempdir().expect("app home");
            let journal = InstallJournal::new(home.path());
            let transaction = Uuid::from_u128(3);
            journal.begin(&record(3)).expect("begin");
            if phase == InstallPhase::Decommissioned {
                journal
                    .advance(
                        &transaction,
                        InstallPhase::HandedOff,
                        InstallPhase::Decommissioned,
                    )
                    .expect("decommissioned");
            }
            assert!(
                journal.abort(&Uuid::from_u128(9), "other").is_err(),
                "another transaction cannot abort this record"
            );
            let aborted = journal
                .abort(&transaction, "dashboard_still_running")
                .expect("abort");
            assert_eq!(aborted.phase, InstallPhase::Aborted);
            assert_eq!(aborted.failure.as_deref(), Some("dashboard_still_running"));
            assert_eq!(journal.load().expect("load"), Some(aborted));
            assert!(
                journal.abort(&transaction, "again").is_err(),
                "an ended attempt is not aborted twice"
            );
        }
    }

    #[test]
    fn only_an_uninterpretable_record_can_be_discarded() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        let path = home.path().join("update-install-v1.json");
        assert_eq!(journal.inspect().expect("empty"), Recorded::Absent);
        journal
            .discard_uninterpretable()
            .expect("nothing to discard");

        journal.begin(&record(6)).expect("begin");
        assert_eq!(
            journal.inspect().expect("valid"),
            Recorded::Valid(record(6))
        );
        assert!(
            journal.discard_uninterpretable().is_err(),
            "a valid record is resolved, never discarded"
        );
        assert!(path.exists());

        let newer = String::from_utf8(fs::read(&path).expect("canonical bytes"))
            .expect("UTF-8")
            .replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1);
        fs::write(&path, newer).expect("a record of another schema version");
        assert!(matches!(
            journal.inspect().expect("readable"),
            Recorded::Uninterpretable(_)
        ));
        assert!(journal.load().is_err());
        assert!(
            journal.begin(&record(7)).is_err(),
            "an uninterpretable record is never overwritten"
        );
        journal.discard_uninterpretable().expect("discard");
        assert_eq!(journal.inspect().expect("empty"), Recorded::Absent);
        journal.begin(&record(7)).expect("a new attempt can begin");
    }

    #[test]
    fn malformed_noncanonical_or_shared_records_fail_closed() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        let path = home.path().join("update-install-v1.json");
        journal.begin(&record(5)).expect("begin");
        let canonical = fs::read(&path).expect("canonical bytes");

        let mut spaced = canonical.clone();
        spaced.push(b'\n');
        fs::write(&path, &spaced).expect("noncanonical");
        assert!(journal.load().is_err());

        let unknown = String::from_utf8(canonical.clone())
            .expect("UTF-8")
            .replacen(r#""failure":null"#, r#""failure":null,"extra":1"#, 1);
        fs::write(&path, unknown).expect("unknown field");
        assert!(journal.load().is_err());

        let downgrade = String::from_utf8(canonical.clone())
            .expect("UTF-8")
            .replacen(r#""build":50021"#, r#""build":40074"#, 1);
        fs::write(&path, downgrade).expect("non-increasing build");
        assert!(journal.load().is_err());

        let inconsistent = String::from_utf8(canonical.clone())
            .expect("UTF-8")
            .replacen(r#""failure":null"#, r#""failure":"code""#, 1);
        fs::write(&path, inconsistent).expect("failure without abort");
        assert!(journal.load().is_err());

        fs::write(&path, &canonical).expect("restore");
        assert!(journal.load().expect("restored").is_some());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("shared mode");
        assert!(journal.load().is_err());
    }

    #[test]
    fn a_record_file_this_process_may_not_use_is_discardable_but_a_failed_read_is_not() {
        let home = tempfile::tempdir().expect("app home");
        let journal = InstallJournal::new(home.path());
        let path = home.path().join("update-install-v1.json");
        journal.begin(&record(8)).expect("begin");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("shared mode");
        assert!(matches!(
            journal.inspect().expect("inspected"),
            Recorded::Uninterpretable(detail) if detail.contains("unsafe metadata")
        ));
        journal.discard_uninterpretable().expect("discard");
        assert!(!path.exists());

        std::os::unix::fs::symlink(home.path().join("elsewhere"), &path).expect("link in place");
        assert!(matches!(
            journal.inspect().expect("inspected"),
            Recorded::Uninterpretable(detail) if detail.contains("symbolic link")
        ));
        journal.discard_uninterpretable().expect("discard the link");
        assert!(fs::symlink_metadata(&path).is_err());

        journal.begin(&record(8)).expect("begin again");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("unreadable");
        let failed = journal.inspect();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("readable again");
        assert!(
            matches!(&failed, Err(detail) if detail.contains("failed to open")),
            "{failed:?}"
        );
        assert_eq!(
            journal.inspect().expect("valid"),
            Recorded::Valid(record(8))
        );
    }

    #[test]
    fn the_lease_excludes_a_second_holder_until_it_is_dropped() {
        let home = tempfile::tempdir().expect("app home");
        let held = UpdateInstallLease::acquire(home.path()).expect("first holder");
        assert_eq!(
            UpdateInstallLease::acquire(home.path()).map(|_| ()),
            Err(UpdateInstallLeaseError::Held)
        );
        drop(held);
        UpdateInstallLease::acquire(home.path()).expect("released lease");
    }
}
