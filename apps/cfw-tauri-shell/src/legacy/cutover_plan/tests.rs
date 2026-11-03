use std::cell::Cell;
use std::fs;

use cfw_core::AppPaths;
use cfw_platform::LegacyServiceJobProgram;

use super::*;

const LEGACY_WRITER_BASE: &str = "retain_window_bounds: true\nlaunch_at_login: false\nsilent_start: false\nsystem_proxy: false\n";

fn fresh_store() -> (tempfile::TempDir, SettingsStore) {
    let temporary = tempfile::tempdir().expect("fresh installation fixture");
    let store = SettingsStore::new(AppPaths::from_app_home(temporary.path().join("app")));
    store.ensure_layout().expect("new settings layout");
    (temporary, store)
}

fn upgrade_kinds() -> [LegacyRuntimePlanKind; 3] {
    [
        LegacyRuntimePlanKind::OfflineUpgrade,
        LegacyRuntimePlanKind::DormantRegistered {
            service_job: LegacyServiceJobObservation::LoadedInactive {
                program: LegacyServiceJobProgram::RetirementTombstone,
            },
        },
        LegacyRuntimePlanKind::LiveOwned {
            service_job: LegacyServiceJobObservation::LoadedActive {
                program: LegacyServiceJobProgram::LegacyHelper,
            },
        },
    ]
}

#[test]
fn fresh_install_without_legacy_settings_has_no_recorded_proxy_endpoint() {
    let (_temporary, store) = fresh_store();
    assert!(
        LegacySettingsMigration::read(store.paths())
            .expect("read absent legacy settings")
            .is_none()
    );
    let runtime_kind = classify_legacy_runtime(LegacyRuntimeEvidence {
        retirement_completed: false,
        legacy_settings_present: false,
        service_status: ServiceModeStatus::NotRegistered,
        service_job: LegacyServiceJobObservation::Unloaded,
        control_session_present: false,
        managed_process_count: 0,
    })
    .expect("authoritatively absent legacy runtime");
    assert_eq!(runtime_kind, LegacyRuntimePlanKind::FreshInstall);

    let absence = LegacyProxyAbsence::resolve(&store, runtime_kind)
        .expect("a fresh installation never recorded a legacy proxy endpoint");
    assert_eq!(absence, LegacyProxyAbsence::FreshInstall);
    let privileged_calls = Cell::new(0);
    for _ in 0..2 {
        absence
            .verify_with(
                &store,
                "fresh installation",
                || {
                    privileged_calls.set(privileged_calls.get() + 1);
                    Ok(())
                },
                |_, _| panic!("fresh installation must not inspect or clear foreign proxies"),
            )
            .expect("current legacy resources remain absent");
    }
    assert_eq!(
        privileged_calls.get(),
        2,
        "absence results are never cached"
    );
}

#[test]
fn fresh_install_rechecks_real_managed_paths_after_resolution() {
    let (_temporary, store) = fresh_store();
    let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
        .expect("fresh strategy");
    for path in [
        store.paths().legacy_settings_file.clone(),
        store.paths().legacy_config_file.clone(),
        store.paths().legacy_cores_dir.clone(),
        store.paths().legacy_helpers_dir.clone(),
        store.paths().legacy_profiles_dir.clone(),
        store.paths().app_home.join("proxy.pac"),
    ] {
        fs::write(&path, b"late legacy resource").expect("create late resource");
        let error = absence
            .verify_with(
                &store,
                "fresh installation recheck",
                || Ok(()),
                |_, _| panic!("fresh failure must not inspect foreign proxies"),
            )
            .expect_err("a previously selected fresh strategy is not an absence receipt");
        assert!(error.contains("remains at"), "{error}");
        fs::remove_file(path).expect("remove fixture resource");
    }
    let pac = store.paths().app_home.join("proxy.pac");
    std::os::unix::fs::symlink("missing-pac-target", &pac).expect("broken PAC symlink");
    let error = absence
        .verify_with(&store, "fresh recheck", || Ok(()), |_, _| unreachable!())
        .expect_err("a broken symlink is still a legacy resource");
    assert!(error.contains("remains at"), "{error}");
}

#[test]
fn fresh_install_requires_each_privileged_absence_observation() {
    let (_temporary, store) = fresh_store();
    let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
        .expect("fresh strategy");
    for failure in [
        "legacy helper remains",
        "legacy service observation is unavailable",
        "legacy control session remains",
        "legacy managed process appeared",
    ] {
        let error = absence
            .verify_with(
                &store,
                "fresh recheck",
                || Err(failure.to_owned()),
                |_, _| panic!("failed absence must not fall back to proxy inspection"),
            )
            .expect_err("unverified runtime absence must fail");
        assert_eq!(error, format!("fresh recheck: {failure}"));
    }
}

#[test]
fn upgrade_kinds_never_become_fresh_when_settings_or_the_port_are_missing() {
    let (_temporary, store) = fresh_store();
    for kind in upgrade_kinds() {
        let error = LegacyProxyAbsence::resolve(&store, kind)
            .expect_err("missing settings do not change the journal's runtime kind");
        assert!(
            error.contains("do not record the retired mixed port"),
            "{error}"
        );
    }
    fs::write(&store.paths().legacy_settings_file, LEGACY_WRITER_BASE)
        .expect("valid legacy settings without a port");
    for kind in upgrade_kinds() {
        let error = LegacyProxyAbsence::resolve(&store, kind)
            .expect_err("a recorded installation must identify its owned endpoint");
        assert!(
            error.contains("do not record the retired mixed port"),
            "{error}"
        );
    }
}

#[test]
fn fresh_install_rejects_settings_with_or_without_a_recorded_port() {
    let (_temporary, store) = fresh_store();
    for port_field in ["", "mixed_port: 7902\n"] {
        fs::write(
            &store.paths().legacy_settings_file,
            format!("{LEGACY_WRITER_BASE}{port_field}"),
        )
        .expect("legacy settings");
        let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
            .expect_err("new legacy settings must not select a different absence strategy");
        assert!(
            error.contains("settings appeared in a fresh installation"),
            "{error}"
        );
    }
}

#[test]
fn unreadable_legacy_settings_never_become_fresh_absence() {
    let (_temporary, store) = fresh_store();
    fs::write(&store.paths().legacy_settings_file, [0xff]).expect("invalid UTF-8 settings");
    let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
        .expect_err("invalid content is not missing content");
    assert!(error.contains("legacy settings are unreadable"), "{error}");
    fs::remove_file(&store.paths().legacy_settings_file).expect("remove invalid fixture");
    std::os::unix::fs::symlink(
        "missing-settings-target",
        &store.paths().legacy_settings_file,
    )
    .expect("broken settings symlink");
    let error = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
        .expect_err("an unreadable settings path is not absent");
    assert!(error.contains("legacy settings are unreadable"), "{error}");
}

#[test]
fn recorded_endpoint_keeps_its_exact_proxy_boundary() {
    let (_temporary, store) = fresh_store();
    fs::write(
        &store.paths().legacy_settings_file,
        format!("{LEGACY_WRITER_BASE}mixed_port: 7902\n"),
    )
    .expect("recorded legacy port");
    fs::write(store.paths().app_home.join("proxy.pac"), b"fixture PAC")
        .expect("recorded PAC presence");
    let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::OfflineUpgrade)
        .expect("recorded strategy");
    assert_eq!(
        absence,
        LegacyProxyAbsence::RecordedEndpoint {
            owned_port: 7902,
            pac_present: true
        }
    );
    let proxy_calls = Cell::new(0);
    let error = absence
        .verify_with(
            &store,
            "recorded endpoint",
            || panic!("an upgrade must not acquire fresh-install absence"),
            |port, pac_present| {
                proxy_calls.set(proxy_calls.get() + 1);
                assert_eq!(port, 7902);
                assert!(pac_present);
                Err("recorded proxy remains".into())
            },
        )
        .expect_err("recorded proxy failure remains explicit");
    assert_eq!(proxy_calls.get(), 1);
    assert_eq!(error, "recorded endpoint: recorded proxy remains");
}

#[test]
fn fresh_absence_remains_valid_after_the_completion_marker() {
    let (_temporary, store) = fresh_store();
    store
        .commit_legacy_retirement()
        .expect("completed data retirement marker");
    let absence = LegacyProxyAbsence::resolve(&store, LegacyRuntimePlanKind::FreshInstall)
        .expect("recovery preserves the original journal kind");
    absence
        .verify_with(
            &store,
            "completed fresh installation",
            || Ok(()),
            |_, _| panic!("completed fresh installation has no retired proxy endpoint"),
        )
        .expect("the marker does not invalidate current absence");
}
