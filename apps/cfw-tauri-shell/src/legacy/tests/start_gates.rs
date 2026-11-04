//! What a normal start requires: no unfinished cutover phase, no running
//! legacy runtime or network-capable legacy job, and no active maintenance;
//! and when runtime preferences may change.

use super::*;

#[test]
fn normal_start_leaves_legacy_files_and_missing_marker_untouched() {
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    store.ensure_layout().expect("modern layout");
    let old_settings = b"unparsed legacy settings retained for optional cleanup";
    fs::write(&store.paths().legacy_settings_file, old_settings).expect("old settings");
    fs::create_dir(&store.paths().legacy_cores_dir).expect("old core directory");
    fs::write(
        store.paths().legacy_cores_dir.join("mihomo"),
        b"unused old executable",
    )
    .expect("old executable");
    let gate = LegacyRetirementGate::default();
    let mut observed = false;
    require_network_start_with(&gate, &store, |cores| {
        assert_eq!(cores, store.paths().legacy_cores_dir);
        observed = true;
        Ok(())
    })
    .expect("legacy data is not a network start prerequisite");
    assert!(observed);
    assert!(
        !store
            .legacy_retirement_completed()
            .expect("marker remains absent")
    );
    assert_eq!(
        fs::read(&store.paths().legacy_settings_file).expect("retained settings"),
        old_settings
    );
    assert!(store.paths().legacy_cores_dir.join("mihomo").is_file());
}

#[test]
fn normal_start_preserves_runtime_observation_failure() {
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    store.ensure_layout().expect("modern layout");
    let refused = "legacy process observation was denied by the operating system";
    let error = require_network_start_with(&LegacyRetirementGate::default(), &store, |_| {
        Err(refused.to_owned())
    })
    .expect_err("unobservable runtime cannot be admitted as inactive");
    assert_eq!(error, refused);
    assert!(
        !store
            .legacy_retirement_completed()
            .expect("marker unchanged")
    );
}

#[test]
fn normal_start_rejects_corrupt_journal_before_runtime_observation() {
    let root = tempfile::tempdir().expect("temporary app home");
    let store = SettingsStore::new(AppPaths::from_app_home(root.path()));
    store.ensure_layout().expect("modern layout");
    let journal = root.path().join("legacy-cutover-journal-v1.json");
    fs::write(&journal, b"broken journal").expect("corrupt journal");
    let error = require_network_start_with(&LegacyRetirementGate::default(), &store, |_| {
        panic!("corrupt journal cannot proceed to runtime admission")
    })
    .expect_err("journal is authoritative even when its bytes are invalid");
    assert!(error.contains("journal"));
    assert_eq!(
        fs::read(journal).expect("unchanged journal"),
        b"broken journal"
    );
}

#[test]
fn runtime_preferences_change_only_while_no_cutover_journal_governs_startup() {
    use crate::legacy::journal::{
        CutoverJournalStore, CutoverPhase, write_journal_governing_startup,
    };
    let root = tempfile::tempdir().expect("temporary app home");
    assert_eq!(require_runtime_preferences_changeable(root.path()), Ok(()));
    write_journal_governing_startup(root.path(), cfw_singbox_config::EngineSettings::default());
    assert_eq!(
        require_runtime_preferences_changeable(root.path()),
        Err(RuntimePreferencesLocked::CutoverCleanupPending)
    );
    CutoverJournalStore::new(root.path())
        .advance(
            CutoverPhase::ReplacementActive,
            CutoverPhase::CleanupComplete,
        )
        .expect("cleanup complete");
    assert_eq!(require_runtime_preferences_changeable(root.path()), Ok(()));

    let corrupt = tempfile::tempdir().expect("temporary app home");
    let journal = corrupt.path().join("legacy-cutover-journal-v1.json");
    fs::write(&journal, b"broken journal").expect("corrupt journal");
    assert!(
        matches!(
            require_runtime_preferences_changeable(corrupt.path()),
            Err(RuntimePreferencesLocked::JournalUnavailable(_))
        ),
        "an unreadable journal refuses the change instead of allowing it"
    );
    assert_eq!(
        fs::read(journal).expect("unchanged journal"),
        b"broken journal"
    );
}

#[test]
fn unfinished_network_phases_cannot_be_skipped_by_optional_cleanup_status() {
    use crate::legacy::journal::CutoverPhase;
    let optional = LegacyRetirementStatus::AwaitingConfirmation;
    for phase in [
        CutoverPhase::Prepared,
        CutoverPhase::GuiStopped,
        CutoverPhase::NetworkRetiring,
        CutoverPhase::LegacyRetired,
        CutoverPhase::ReplacementActive,
    ] {
        assert!(
            require_normal_start_phase(Some(phase), &optional).is_err(),
            "{phase:?}"
        );
    }
    assert!(require_normal_start_phase(None, &optional).is_ok());
    assert!(require_normal_start_phase(Some(CutoverPhase::CleanupComplete), &optional).is_ok());
    assert!(
        require_normal_start_phase(
            Some(CutoverPhase::ReplacementActive),
            &LegacyRetirementStatus::PostCutoverCleanupRequired {
                message: "old YAML remains".into()
            }
        )
        .is_ok()
    );
}

#[test]
fn normal_start_rejects_real_legacy_runtime_but_not_cfw_or_unused_files() {
    let cores = Path::new("/Users/test/Library/Application Support/Clash for Mac/cores");
    let other = "0 17 Mon Sep 7 10:00:00 2026 /Applications/Clash for Windows.app/Contents/Resources/static/files/darwin/x64/clash-darwin";
    require_no_legacy_runtime_processes(other, cores).expect("CFW is a different application");
    for executable in [
        cores.join("mihomo"),
        PathBuf::from("/Library/PrivilegedHelperTools/com.bill.clashformac.helper"),
    ] {
        let output = format!(
            "0 18 Mon Sep 7 10:00:00 2026 {} --service",
            executable.display()
        );
        assert!(require_no_legacy_runtime_processes(&output, cores).is_err());
    }
    assert!(require_no_legacy_runtime_processes("invalid process record", cores).is_err());
}

/// `ps` prints the uid of `nobody` (4294967294) as `-2`, and such a process
/// is in every macOS process table. It is not a legacy runtime and must not
/// make the whole table unreadable, which would refuse every network start.
#[test]
fn a_process_of_the_nobody_user_does_not_make_the_process_table_unreadable() {
    let cores = Path::new("/Users/test/Library/Application Support/Clash for Mac/cores");
    let table = "    -2 47975 Mon Oct  5 17:30:27 2026     /usr/libexec/dhcp6d\n    0 18 Mon Sep 7 10:00:00 2026 /sbin/launchd\n";
    require_no_legacy_runtime_processes(table, cores)
        .expect("nobody's process is not a legacy runtime");
    let record = parse_managed_process(
        &format!(
            "-2 19 Mon Sep 7 10:00:00 2026 {}",
            cores.join("mihomo").display()
        ),
        cores,
    )
    .expect("a readable record")
    .expect("the managed executable");
    assert_eq!(
        record.uid,
        u32::MAX - 1,
        "the signed rendering maps back to the uid"
    );
    assert!(parse_managed_process("-4294967297 19 Mon Sep 7 10:00:00 2026 /x", cores).is_err());
    assert!(parse_managed_process("4294967296 19 Mon Sep 7 10:00:00 2026 /x", cores).is_err());
}

#[test]
fn only_network_capable_legacy_jobs_block_normal_start() {
    require_no_launchable_legacy_helper(LegacyServiceJobObservation::Unloaded).expect("unloaded");
    for program in [
        LegacyServiceJobProgram::LegacyHelper,
        LegacyServiceJobProgram::RetirementTombstone,
    ] {
        for job in [
            LegacyServiceJobObservation::LoadedInactive { program },
            LegacyServiceJobObservation::LoadedActive { program },
        ] {
            assert_eq!(
                require_no_launchable_legacy_helper(job).is_ok(),
                program == LegacyServiceJobProgram::RetirementTombstone
            );
        }
    }
}

#[test]
fn optional_cleanup_does_not_hide_start_but_active_maintenance_still_serializes_it() {
    let gate = LegacyRetirementGate::default();
    gate.require_start_allowed()
        .expect("new install can start normally");
    let mut attempt = gate
        .begin_attempt()
        .expect("maintenance state")
        .expect("new attempt");
    assert!(gate.require_start_allowed().is_err());
    attempt
        .mark_failed(LegacyCleanupAction::ReviewDns, "optional old DNS setting")
        .expect("cleanup failed");
    gate.require_start_allowed()
        .expect("cleanup error is not proof of a live conflict");
    gate.apply_launch_preflight(LegacyRetirementStatus::RecoveryStartRequired {
        target: EngineMode::Tunnel,
        message: "unfinished network mutation".into(),
    })
    .expect("recovery state");
    assert!(gate.require_start_allowed().is_err());
}
