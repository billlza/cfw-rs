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
