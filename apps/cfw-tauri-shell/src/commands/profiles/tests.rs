use super::*;
use cfw_engine_api::{
    CredentialAudience, CredentialBinding, CredentialGarbageCollectionCommitFuture,
    CredentialGarbageCollectionPreviewFuture, CredentialPresenceFuture, CredentialPresenceRequest,
    CredentialProvisionRequest, CredentialVaultError, CredentialVaultFuture,
};
use cfw_singbox_config::ValidatedSingBoxProfile;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;

#[test]
fn saved_selection_persists_the_app_selector_choice_of_a_profile_without_a_group() {
    let directory = TempDir::new().expect("profile directory");
    let repository = ProfileRepository::new(directory.path().join("profiles"));
    let profile = ValidatedSingBoxProfile::parse(&serde_json::json!({
        "outbounds": [
            {"type": "socks5", "tag": "first", "server": "first.example.com", "server_port": 1080},
            {"type": "socks5", "tag": "second", "server": "second.example.com", "server_port": 1080}
        ]
    }).to_string()).expect("profile without a selector group");
    let imported = repository.import(Some("Nodes"), &profile).expect("import");
    repository.select(&imported.id).expect("select profile");
    persist_saved_proxy_selection(&repository, &imported.id, "cfw-proxy-selector", "second")
        .expect("save the app selector choice");
    let selected = repository
        .load_selected()
        .expect("reload")
        .expect("selected profile");
    assert_eq!(
        selected.profile.proxy_selections()["cfw-proxy-selector"],
        "second"
    );
    assert_eq!(selected.profile.as_json(), profile.as_json());
    assert_eq!(selected.profile.digest(), profile.digest());
    let refused =
        persist_saved_proxy_selection(&repository, &imported.id, "cfw-proxy-selector", "absent")
            .expect_err("a node the profile does not declare is refused");
    assert!(refused.contains("member"), "{refused}");
    let unchanged = repository
        .load_selected()
        .expect("reload")
        .expect("selected profile");
    assert_eq!(
        unchanged.profile.proxy_selections()["cfw-proxy-selector"],
        "second"
    );
}

#[test]
fn saved_selection_updates_only_the_selected_profile_and_preserves_credentials() {
    let directory = TempDir::new().expect("profile directory");
    let repository = ProfileRepository::new(directory.path().join("profiles"));
    let profile = ValidatedSingBoxProfile::parse(&serde_json::json!({
        "outbounds": [
            {"type": "socks5", "tag": "Work node", "server": "proxy.example.com", "server_port": 1080, "authentication": {
                "username_credential_ref": {"id": "11111111-1111-4111-8111-111111111111", "kind": "socks5_username"},
                "password_credential_ref": {"id": "22222222-2222-4222-8222-222222222222", "kind": "socks5_password"}
            }},
            {"type": "direct", "tag": "DIRECT"}, {"type": "block", "tag": "REJECT"},
            {"type": "selector", "tag": "PROXY", "outbounds": ["Work node", "DIRECT", "REJECT"]}
        ], "route": {"final": "PROXY"}
    }).to_string()).expect("selector profile");
    let imported = repository.import(Some("Work"), &profile).expect("import");
    repository.select(&imported.id).expect("select profile");
    persist_saved_proxy_selection(&repository, &imported.id, "PROXY", "REJECT")
        .expect("save selection");
    let selected = repository
        .load_selected()
        .expect("reload")
        .expect("selected profile");
    assert_eq!(selected.profile.proxy_selections()["PROXY"], "REJECT");
    assert_eq!(selected.profile.as_json(), profile.as_json());
    assert_eq!(selected.record.name, "Work");
    assert_eq!(
        selected.profile.credential_references(),
        profile.credential_references()
    );
    assert_eq!(selected.profile.digest(), profile.digest());
    for (id, group, node) in [
        ("different-profile", "PROXY", "DIRECT"),
        (imported.id.as_str(), "PROXY", "absent"),
    ] {
        assert!(persist_saved_proxy_selection(&repository, id, group, node).is_err());
        assert_eq!(
            repository
                .load_selected()
                .expect("reload after rejection")
                .expect("selected")
                .profile,
            selected.profile
        );
    }
}

#[test]
fn profile_snapshot_serialization_exposes_no_path_url_or_credentials() {
    let record = ProfileRecord {
        id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
        name: "Profile".into(),
        bytes: 128,
        digest: "01".repeat(32),
        created_epoch_secs: 42,
        source_kind: ProfileSourceKind::Subscription,
    };

    let value =
        serde_json::to_value(UiProfileRecord::from_record(record, true)).expect("serialize record");
    let object = value.as_object().expect("record object");
    assert_eq!(
        object.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "active".to_string(),
            "bytes".to_string(),
            "id".to_string(),
            "name".to_string(),
            "source_kind".to_string(),
            "updated_epoch_secs".to_string(),
        ])
    );
    assert!(!value.to_string().contains("digest"));
    assert!(!value.to_string().contains("path"));
    assert!(!value.to_string().contains("url"));
    assert_eq!(value["active"], true);
    assert_eq!(value["source_kind"], "subscription");
}

fn invalid_record(id: &str) -> InvalidProfileRecord {
    InvalidProfileRecord {
        id: id.into(),
        name: "Reality node".into(),
        created_epoch_secs: 3,
        source_kind: ProfileSourceKind::Subscription,
        error: cfw_singbox_config::ConfigError::UnsupportedPolicyShape {
            path: "$.outbounds[0].tls.utls".into(),
            reason: "Reality requires uTLS".into(),
        },
    }
}

fn valid_records(selected_id: &str, other_id: &str) -> Vec<ProfileRecord> {
    vec![
        ProfileRecord {
            id: selected_id.into(),
            name: "Selected".into(),
            bytes: 10,
            digest: "01".repeat(32),
            created_epoch_secs: 1,
            source_kind: ProfileSourceKind::Local,
        },
        ProfileRecord {
            id: other_id.into(),
            name: "Other".into(),
            bytes: 11,
            digest: "02".repeat(32),
            created_epoch_secs: 2,
            source_kind: ProfileSourceKind::Subscription,
        },
    ]
}

#[test]
fn snapshot_marks_only_the_digest_bound_selection_active() {
    let selected_id = "34db18b6-9903-4e9f-8854-15648e19e4f3";
    let other_id = "62b37965-02bb-45a8-a1a5-3b617c5cbd17";
    let invalid_id = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
    let view = snapshot_view(ProfileRepositorySnapshot {
        profiles: valid_records(selected_id, other_id),
        invalid_profiles: vec![invalid_record(invalid_id)],
        selected_profile_id: Some(selected_id.into()),
    });

    assert_eq!(view.profiles.len(), 2);
    assert!(view.profiles[0].active);
    assert!(!view.profiles[1].active);
    assert_eq!(view.invalid_profiles.len(), 1);
    assert!(!view.invalid_profiles[0].selected);
}

#[test]
fn a_selected_invalid_profile_is_reported_selected_and_no_valid_profile_is_active() {
    let invalid_id = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
    let view = snapshot_view(ProfileRepositorySnapshot {
        profiles: valid_records(
            "34db18b6-9903-4e9f-8854-15648e19e4f3",
            "62b37965-02bb-45a8-a1a5-3b617c5cbd17",
        ),
        invalid_profiles: vec![invalid_record(invalid_id)],
        selected_profile_id: Some(invalid_id.into()),
    });

    assert!(view.profiles.iter().all(|record| !record.active));
    assert!(view.invalid_profiles[0].selected);
    let value = serde_json::to_value(&view).expect("serialize snapshot");
    assert_eq!(
        value
            .as_object()
            .expect("snapshot object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["invalid_profiles".to_string(), "profiles".to_string()])
    );
    let invalid = &value["invalid_profiles"][0];
    assert_eq!(
        invalid
            .as_object()
            .expect("invalid record object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "error".to_string(),
            "id".to_string(),
            "name".to_string(),
            "selected".to_string(),
            "source_kind".to_string(),
            "updated_epoch_secs".to_string(),
        ])
    );
    assert_eq!(
        invalid["error"],
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
    assert_eq!(invalid["source_kind"], "subscription");
    assert_eq!(invalid["updated_epoch_secs"], 3);
    assert!(!value.to_string().contains("digest"));
    assert!(!value.to_string().contains("url"));
}

#[test]
fn a_kept_invalid_selection_tells_the_user_how_to_delete_it() {
    assert_eq!(
        deletion_error(cfw_profiles::ProfileError::InvalidSelectionKept(
            cfw_profiles::ProfileLabel {
                id: "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d".into(),
                name: "Reality node".into(),
            }
        )),
        "the selected profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid; stop the core, or select another profile, before deleting it"
    );
    assert_eq!(
        deletion_error(cfw_profiles::ProfileError::NoSelectedProfile),
        "no profile is selected"
    );
}

#[test]
fn a_long_validator_message_is_bounded_on_the_card() {
    let short = invalid_record("3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d");
    assert_eq!(
        UiInvalidProfileRecord::from_record(short, false).error,
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
    let mut long = invalid_record("3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d");
    long.error = cfw_singbox_config::ConfigError::InvalidJson("界".repeat(600));
    let listed = UiInvalidProfileRecord::from_record(long, false).error;
    assert_eq!(listed.chars().count(), MAX_LISTED_ERROR_CHARS + 1);
    assert!(listed.starts_with("sing-box profile JSON is invalid: 界"));
    assert!(listed.ends_with('…'));
}

#[test]
fn credential_requirements_are_loaded_from_the_validated_stored_profile() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let profile = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#,
    )
    .expect("typed profile");
    let imported = repository
        .import(Some("Credentials"), &profile)
        .expect("profile import");

    assert_eq!(
        credential_requirements(&repository, &imported.id).expect("requirements"),
        profile.credential_references()
    );
    assert!(credential_requirements(&repository, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").is_err());
}

#[test]
fn renderer_credential_input_has_a_closed_shape_and_redacted_debug_output() {
    let credential: UiCredentialProvision = serde_json::from_value(serde_json::json!({
        "reference": {
            "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "kind": "trojan_password",
        },
        "secret": "never-print-this-secret",
    }))
    .expect("credential input");
    let debug = format!("{credential:?}");
    assert!(!debug.contains("never-print-this-secret"));
    assert!(debug.contains("[REDACTED]"));

    assert!(
        serde_json::from_value::<UiCredentialProvision>(serde_json::json!({
            "reference": {
                "id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "kind": "trojan_password",
            },
            "secret": "bounded",
            "unexpected": true,
        }))
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn repository_reads_wait_off_executor_while_an_online_transaction_holds_the_lock() {
    let temporary = TempDir::new().expect("temporary repository");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let transaction = repository.begin_credential_profile_mutation().unwrap();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let reader = tokio::spawn(async move {
        read_repository(&repository, move |repository| {
            let _ = entered.send(());
            repository.snapshot().map_err(|error| error.to_string())
        })
        .await
    });
    waiting.await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!reader.is_finished());
    drop(transaction);
    let result = tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(result.profiles.is_empty());
}

mod gc_cleanup;
