//! Which profile a non-Off mode starts with, and what counts as Off.

use super::*;

#[test]
fn non_off_mode_uses_the_digest_bound_selected_profile() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    let expected = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"shadowsocks","tag":"selected","server":"proxy.example.com","server_port":443,"method":"2022-blake3-aes-128-gcm","credential_ref":{"id":"34db18b6-9903-4e9f-8854-15648e19e4f3","kind":"shadowsocks_password"}}],"route":{"final":"selected"}}"#,
    )
    .expect("typed profile");
    let imported = repository
        .import(Some("Selected"), &expected)
        .expect("import");
    repository.select(&imported.id).expect("select");
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy).expect("selected"),
        (imported.id.clone(), expected)
    );
}

#[test]
fn non_off_mode_rejects_absent_or_stale_selection_but_off_remains_available() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::Tunnel),
        Err(ProfileError::NoSelectedProfile)
    ));
    let imported = repository
        .import(Some("Selected"), &ValidatedSingBoxProfile::direct())
        .expect("import");
    repository.select(&imported.id).expect("select");
    fs::remove_file(
        root.path()
            .join("profiles")
            .join(format!("{}.profile.json", imported.id)),
    )
    .expect("remove selected profile");
    assert!(matches!(
        selected_profile_for_mode(&repository, EngineMode::SystemProxy),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::Off).expect("Off profile"),
        (
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
        )
    );
}

#[test]
fn only_an_engine_requested_and_observed_off_counts_as_off() {
    assert!(engine_snapshot_is_off(&EngineSnapshot::default()));
    for (desired_mode, state) in [
        (EngineMode::SystemProxy, EngineState::Off),
        (EngineMode::LocalProxy, EngineState::Off),
        (EngineMode::TunnelSystemProxy, EngineState::Off),
        (
            EngineMode::Off,
            EngineState::ProxyStarting { generation: 1 },
        ),
        (
            EngineMode::Off,
            EngineState::ProxyStopping { generation: 1 },
        ),
        (
            EngineMode::Off,
            EngineState::TunnelStopping { generation: 1 },
        ),
        (
            EngineMode::Off,
            EngineState::Failed {
                generation: 1,
                target: EngineMode::Off,
                error: "native startup reconciliation is pending".into(),
                recheck_pending: true,
            },
        ),
        (
            EngineMode::Tunnel,
            EngineState::TunnelStarting { generation: 1 },
        ),
    ] {
        assert!(
            !engine_snapshot_is_off(&EngineSnapshot {
                desired_mode,
                state: state.clone(),
                ..EngineSnapshot::default()
            }),
            "{desired_mode:?} {state:?}"
        );
    }
}

#[test]
fn non_off_mode_refuses_a_selected_profile_that_fails_validation_without_a_fallback() {
    let root = tempfile::tempdir().expect("temporary repository");
    let repository = ProfileRepository::new(root.path().join("profiles"));
    repository
        .import(Some("Other"), &ValidatedSingBoxProfile::direct())
        .expect("import other profile");
    let invalid_id = crate::profile_fixtures::store_selected_reality_without_utls(
        root.path().join("profiles").as_path(),
        &repository,
    );
    assert_eq!(
        repository.snapshot().expect("snapshot").invalid_profiles[0].id,
        invalid_id
    );
    for mode in [EngineMode::SystemProxy, EngineMode::Tunnel] {
        let error = selected_profile_for_mode(&repository, mode).expect_err("refused");
        assert!(
            matches!(&error, ProfileError::StoredProfileInvalid { id, .. } if *id == invalid_id),
            "{error}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "stored profile \"Reality node\" ({invalid_id}) is invalid: unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
            )
        );
    }
    assert_eq!(
        selected_profile_for_mode(&repository, EngineMode::Off).expect("Off profile"),
        (
            "00000000-0000-4000-8000-000000000000".to_owned(),
            ValidatedSingBoxProfile::direct(),
        )
    );
}
