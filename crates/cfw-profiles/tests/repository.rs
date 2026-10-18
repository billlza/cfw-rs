use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use cfw_profiles::{
    InvalidSelection, ProfileError, ProfileLabel, ProfileRecord, ProfileRepository,
    ProfileSelectionState, ProfileSourceKind, ValidatedSingBoxProfile,
};
use cfw_singbox_config::{ConfigError, sha256_hex};
use uuid::Uuid;

const MAX_STORED_BYTES: usize = cfw_singbox_config::MAX_PROFILE_BYTES + 256 * 1024;

fn repository(name: &str) -> (PathBuf, ProfileRepository) {
    let root = std::env::temp_dir().join(format!(
        "cfw-profile-repository-{name}-{}-{}",
        std::process::id(),
        Uuid::new_v4()
    ));
    let repository = ProfileRepository::new(root.join("profiles"));
    (root, repository)
}

fn profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(
        r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#,
    )
    .expect("valid profile")
}

#[test]
fn provider_sources_round_trip_privately_and_participate_in_update_conflict_detection() {
    use std::collections::BTreeMap;
    let value = serde_json::json!({"outbounds":[{"type":"socks5","tag":"node","server":"node.example.com","server_port":1080}],
        "providers":{"proxies":[{"name":"Japan","source":{"interval_seconds":3600},"members":[{"tag":"node","name":"Tokyo"}],"filter":{}}]}});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string())
        .unwrap()
        .with_provider_sources(BTreeMap::from([(
            "proxy:Japan".into(),
            "https://resource.example/nodes?token=private-token".into(),
        )]))
        .unwrap();
    let (root, repository) = repository("provider-private-source");
    let imported = repository.import(Some("Providers"), &profile).unwrap();
    let stored = repository.load(&imported.id).unwrap().unwrap();
    assert_eq!(
        stored.profile.provider_sources(),
        profile.provider_sources()
    );
    assert!(!stored.profile.as_json().contains("private-token"));
    assert!(
        !serde_json::to_string(&repository.snapshot().unwrap())
            .unwrap()
            .contains("private-token")
    );
    let public = ValidatedSingBoxProfile::parse(stored.profile.as_json()).unwrap();
    assert!(public.provider_sources().is_empty());
    assert_eq!(public.digest(), profile.digest());
    let changed = profile
        .with_provider_sources(BTreeMap::from([(
            "proxy:Japan".into(),
            "https://resource.example/new".into(),
        )]))
        .unwrap();
    repository
        .begin_credential_profile_mutation_if_unchanged(&stored)
        .unwrap()
        .commit_replace_if_unchanged(&stored, None, &changed, None)
        .unwrap();
    assert!(
        repository
            .begin_credential_profile_mutation_if_unchanged(&stored)
            .is_err(),
        "same-digest source URL drift must not overwrite the new source"
    );
    fs::remove_dir_all(root).unwrap();
}

fn credential_profile(reference_id: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{reference_id}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
    ))
    .expect("valid credential profile")
}

fn stored_path(root: &std::path::Path, id: &str) -> PathBuf {
    root.join("profiles").join(format!("{id}.profile.json"))
}

fn selection_path(root: &std::path::Path) -> PathBuf {
    root.join("profiles").join("selected-profile-v1.json")
}

/// The valid profiles of a repository these tests expect to hold no invalid
/// entry; one would fail the call instead of being left out.
fn listed(repository: &ProfileRepository) -> Result<Vec<ProfileRecord>, ProfileError> {
    let snapshot = repository.snapshot()?;
    assert!(
        snapshot.invalid_profiles.is_empty(),
        "unexpected invalid profiles: {:?}",
        snapshot.invalid_profiles
    );
    Ok(snapshot.profiles)
}

/// A subscription VLESS Reality node without a uTLS fingerprint, exactly as
/// the 0.5 line stored and selected it before Reality required uTLS (bytes
/// written by commit 8415a1b).
const EARLIER_REALITY_ID: &str = "3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d";
const EARLIER_REALITY_DIGEST: &str =
    "0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa";
const EARLIER_REALITY_ENVELOPE: &str = r#"{"schema_version":1,"id":"3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d","name":"Reality node","profile":{"outbounds":[{"credential_ref":{"id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","kind":"vless_uuid"},"flow":"xtls-rprx-vision","server":"vless.example.com","server_port":443,"tag":"proxy","tls":{"enabled":true,"reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"},"server_name":"www.example.com"},"type":"vless"}],"route":{"final":"proxy"}},"digest":"0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa","created_epoch_secs":1791415969,"source_url":"https://subscription.example/profile?token=private-test-value"}"#;
const EARLIER_REALITY_SELECTION: &str = r#"{"schema_version":1,"profile_id":"3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d","profile_digest":"0a212f0622cc414ed98a9a138233c8b6224b7625fc6e7d6f9ab1db756d5bc5fa"}"#;

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write repository entry");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("set private entry mode");
}

/// Places the earlier envelope in an existing repository, optionally with
/// the selection record the earlier build wrote for it.
fn store_earlier_reality_profile(root: &std::path::Path, selected: bool) -> PathBuf {
    let path = stored_path(root, EARLIER_REALITY_ID);
    write_private(&path, EARLIER_REALITY_ENVELOPE.as_bytes());
    if selected {
        write_private(&selection_path(root), EARLIER_REALITY_SELECTION.as_bytes());
    }
    path
}

/// The document text inside the earlier envelope.
fn earlier_document() -> &'static str {
    EARLIER_REALITY_ENVELOPE
        .split_once(r#""profile":"#)
        .and_then(|(_, rest)| rest.split_once(r#","digest":"#))
        .map(|(document, _)| document)
        .expect("earlier envelope has a document")
}

/// The earlier envelope for an edited document, with the digest an earlier
/// build would have stored for that document.
fn earlier_envelope_with_document(edit: impl FnOnce(&str) -> String) -> String {
    let edited = edit(earlier_document());
    EARLIER_REALITY_ENVELOPE
        .replacen(earlier_document(), &edited, 1)
        .replacen(EARLIER_REALITY_DIGEST, &sha256_hex(edited.as_bytes()), 1)
}

fn reality_requires_utls() -> ConfigError {
    ConfigError::UnsupportedPolicyShape {
        path: "$.outbounds[0].tls.utls".into(),
        reason: "Reality requires uTLS".into(),
    }
}

fn earlier_label() -> ProfileLabel {
    ProfileLabel {
        id: EARLIER_REALITY_ID.into(),
        name: "Reality node".into(),
    }
}

fn is_earlier_invalid(error: &ProfileError) -> bool {
    matches!(
        error,
        ProfileError::StoredProfileInvalid { id, name, source }
            if id == EARLIER_REALITY_ID && name == "Reality node" && *source == reality_requires_utls()
    )
}

#[test]
fn the_earlier_digest_is_the_hash_of_its_stored_document() {
    // The integrity check for an entry that no longer validates relies on it.
    assert_eq!(
        sha256_hex(earlier_document().as_bytes()),
        EARLIER_REALITY_DIGEST
    );
    let (root, repository) = repository("stored-document-digest");
    let imported = repository
        .import_with_source(
            Some("Current"),
            &credential_profile("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
            Some("https://subscription.example/current"),
        )
        .expect("import current profile");
    let stored = fs::read_to_string(stored_path(&root, &imported.id)).expect("read envelope");
    let document = stored
        .split_once(r#""profile":"#)
        .and_then(|(_, rest)| rest.split_once(r#","digest":"#))
        .map(|(document, _)| document)
        .expect("stored document");
    assert_eq!(sha256_hex(document.as_bytes()), imported.digest);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn earlier_profile_failing_validation_is_listed_and_does_not_block_the_repository() {
    let (root, repository) = repository("earlier-invalid");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let path = store_earlier_reality_profile(&root, false);

    let snapshot = repository
        .snapshot()
        .expect("an invalid profile does not block the snapshot");
    assert_eq!(
        snapshot
            .profiles
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec![other.id.as_str()]
    );
    assert_eq!(snapshot.invalid_profiles.len(), 1);
    let invalid = &snapshot.invalid_profiles[0];
    assert_eq!(invalid.id, EARLIER_REALITY_ID);
    assert_eq!(invalid.name, "Reality node");
    assert_eq!(invalid.created_epoch_secs, 1_791_415_969);
    assert_eq!(invalid.source_kind, ProfileSourceKind::Subscription);
    assert_eq!(invalid.error, reality_requires_utls());
    assert_eq!(snapshot.selected_profile_id, None);
    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    assert!(json.contains(
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    ));
    for secret in [
        "subscription.example",
        "private-test-value",
        "source_url",
        EARLIER_REALITY_DIGEST,
    ] {
        assert!(!json.contains(secret), "snapshot exposes {secret}");
    }

    repository
        .import(Some("Third"), &profile())
        .expect("import beside an invalid profile");
    repository
        .select(&other.id)
        .expect("select a valid profile");
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the unselected invalid profile")
    );
    assert!(!path.exists());
    let after = repository.snapshot().expect("snapshot after deletion");
    assert!(after.invalid_profiles.is_empty());
    assert_eq!(after.profiles.len(), 2);
    assert_eq!(
        after.selected_profile_id.as_deref(),
        Some(other.id.as_str())
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn invalid_profile_is_never_loaded_selected_or_rewritten() {
    let (root, repository) = repository("earlier-refused");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    repository.select(&other.id).expect("select other profile");
    let path = store_earlier_reality_profile(&root, false);
    let selection = fs::read(selection_path(&root)).expect("read selection");

    let error = repository
        .load(EARLIER_REALITY_ID)
        .expect_err("load is refused");
    assert!(is_earlier_invalid(&error), "{error}");
    assert_eq!(
        error.to_string(),
        "stored profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid: unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
    // Each attempt releases the repository lock before the next one runs.
    let attempts: [&dyn Fn() -> Result<(), ProfileError>; 5] = [
        &|| repository.select(EARLIER_REALITY_ID).map(|_| ()),
        &|| {
            repository
                .replace(EARLIER_REALITY_ID, None, &profile(), None)
                .map(|_| ())
        },
        &|| {
            repository
                .update_metadata(EARLIER_REALITY_ID, Some("Renamed"), None)
                .map(|_| ())
        },
        &|| {
            repository
                .begin_credential_profile_mutation()?
                .profile(EARLIER_REALITY_ID)
                .map(|_| ())
        },
        &|| {
            repository
                .begin_credential_profile_mutation()?
                .commit_selection(EARLIER_REALITY_ID)
                .map(|_| ())
        },
    ];
    for attempt in attempts {
        let error = attempt().expect_err("an invalid profile is refused");
        assert!(is_earlier_invalid(&error), "{error}");
    }
    // An exact-id import, such as a migration replay, names the invalid entry.
    let error = repository
        .import_with_id_and_source(EARLIER_REALITY_ID, Some("Reality node"), &profile(), None)
        .expect_err("the id is taken by an invalid entry");
    assert!(is_earlier_invalid(&error), "{error}");
    assert_eq!(
        fs::read_to_string(&path).expect("read envelope"),
        EARLIER_REALITY_ENVELOPE
    );
    assert_eq!(
        fs::read(selection_path(&root)).expect("read selection"),
        selection
    );
    assert_eq!(
        repository
            .require_selected()
            .expect("selection unchanged")
            .record
            .id,
        other.id
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn selected_invalid_profile_is_reported_and_never_started_or_replaced() {
    let (root, repository) = repository("earlier-selected");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);

    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(EARLIER_REALITY_ID)
    );
    assert_eq!(snapshot.invalid_profiles[0].id, EARLIER_REALITY_ID);
    for error in [
        repository.load_selected().map(|_| ()).expect_err("load"),
        repository
            .require_selected()
            .map(|_| ())
            .expect_err("require"),
        repository.lock_selected().map(|_| ()).expect_err("lock"),
    ] {
        assert!(is_earlier_invalid(&error), "{error}");
    }
    {
        let mutation = repository
            .begin_credential_profile_mutation()
            .expect("mutation lock");
        let state = mutation.selected_profile().expect("selection state");
        assert!(matches!(
            &state,
            ProfileSelectionState::Invalid(record)
                if record.id == EARLIER_REALITY_ID && record.error == reality_requires_utls()
        ));
        assert_eq!(state.clone().into_valid(), None);
        let error = state.into_loaded().expect_err("invalid selection");
        assert!(is_earlier_invalid(&error), "{error}");
    }

    // Choosing a valid profile is the in-app way off an invalid selection.
    repository
        .select(&other.id)
        .expect("select a valid profile");
    assert_eq!(
        repository
            .require_selected()
            .expect("valid selection")
            .record
            .id,
        other.id
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn deleting_the_selected_invalid_profile_needs_the_engine_off_and_selects_nothing() {
    let (root, repository) = repository("earlier-selected-delete");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let path = store_earlier_reality_profile(&root, true);

    let error = repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect_err("a selected profile is kept while the engine may run");
    assert!(matches!(
        &error,
        ProfileError::InvalidSelectionKept(profile) if *profile == earlier_label()
    ));
    assert_eq!(
        error.to_string(),
        "the selected profile \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d) is invalid; deleting it would also clear the selection"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("envelope kept"),
        EARLIER_REALITY_ENVELOPE
    );
    assert_eq!(
        fs::read_to_string(selection_path(&root)).expect("selection kept"),
        EARLIER_REALITY_SELECTION
    );

    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .expect("delete with the engine Off")
    );
    assert!(!path.exists());
    assert!(!selection_path(&root).exists());
    let snapshot = repository.snapshot().expect("snapshot after deletion");
    assert_eq!(snapshot.selected_profile_id, None);
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(snapshot.profiles[0].id, other.id);
    assert!(
        repository.load_selected().expect("no selection").is_none(),
        "no other profile is selected in its place"
    );
    assert!(matches!(
        repository.require_selected(),
        Err(ProfileError::NoSelectedProfile)
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn credential_cleanup_is_refused_while_an_invalid_profile_is_listed() {
    let (root, repository) = repository("earlier-credential-cleanup");
    let other = repository
        .import(
            Some("Other"),
            &credential_profile("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
        )
        .expect("import other profile");
    store_earlier_reality_profile(&root, false);

    for error in [
        repository
            .credential_snapshot()
            .map(|_| ())
            .expect_err("snapshot refused"),
        repository
            .lock_credential_snapshot()
            .map(|_| ())
            .expect_err("locked snapshot refused"),
    ] {
        assert!(matches!(
            &error,
            ProfileError::CredentialCleanupBlocked { profiles } if *profiles == [earlier_label()]
        ));
        assert_eq!(
            error.to_string(),
            "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d)"
        );
    }

    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete invalid profile");
    let snapshot = repository
        .credential_snapshot()
        .expect("cleanup is available again");
    assert_eq!(snapshot.profile_count, 1);
    assert_eq!(snapshot.catalog[0].audience.profile_id(), other.id);
    assert!(repository.lock_credential_snapshot().is_ok());
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn the_source_of_an_invalid_subscription_can_be_read_and_imported_again() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-reimport");
    let local = repository
        .import(Some("Local"), &profile())
        .expect("import local profile");
    store_earlier_reality_profile(&root, false);

    assert_eq!(
        repository
            .source_url(EARLIER_REALITY_ID)
            .expect("source of the invalid entry")
            .as_deref(),
        Some(URL)
    );
    assert_eq!(
        repository
            .source_url(&local.id)
            .expect("source of a local profile"),
        None
    );
    assert!(matches!(
        repository.source_url("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        Err(ProfileError::ProfileNotFound(id)) if id == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    ));

    let replacement = repository
        .import_with_source(Some("Reality node"), &profile(), Some(URL))
        .expect("the same subscription imports beside the invalid entry");
    assert_eq!(
        repository
            .source_url(&replacement.id)
            .expect("replacement source")
            .as_deref(),
        Some(URL)
    );
    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete the old entry");
    let snapshot = repository.snapshot().expect("snapshot");
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(snapshot.profiles.len(), 2);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_document_that_no_longer_deserializes_is_listed_invalid() {
    let (root, repository) = repository("earlier-unknown-field");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    let envelope = earlier_envelope_with_document(|document| {
        document.replacen(
            r#""flow":"xtls-rprx-vision","#,
            r#""flow":"xtls-rprx-vision","legacy_option":true,"#,
            1,
        )
    });
    assert_ne!(envelope, EARLIER_REALITY_ENVELOPE);
    write_private(&stored_path(&root, EARLIER_REALITY_ID), envelope.as_bytes());

    let snapshot = repository.snapshot().expect("an intact envelope is listed");
    assert_eq!(snapshot.invalid_profiles.len(), 1);
    assert!(
        matches!(&snapshot.invalid_profiles[0].error, ConfigError::InvalidJson(message) if message.contains("legacy_option")),
        "{:?}",
        snapshot.invalid_profiles[0].error
    );
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete")
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn damaged_invalid_profiles_still_fail_closed_and_are_never_deleted() {
    type Expect = fn(&ProfileError) -> bool;
    let cases: [(&str, String, Expect); 6] = [
        (
            "document edited, digest kept",
            EARLIER_REALITY_ENVELOPE.replacen(r#""server_port":443"#, r#""server_port":444"#, 1),
            |error| matches!(error, ProfileError::DigestMismatch { id } if id == EARLIER_REALITY_ID),
        ),
        (
            "digest edited",
            EARLIER_REALITY_ENVELOPE.replacen(EARLIER_REALITY_DIGEST, &"00".repeat(32), 1),
            |error| matches!(error, ProfileError::DigestMismatch { id } if id == EARLIER_REALITY_ID),
        ),
        (
            "non-canonical",
            format!("{EARLIER_REALITY_ENVELOPE}\n"),
            |error| matches!(error, ProfileError::NonCanonicalEnvelope(id) if id == EARLIER_REALITY_ID),
        ),
        (
            "unknown envelope field",
            format!(
                "{},\"unexpected\":true}}",
                EARLIER_REALITY_ENVELOPE
                    .strip_suffix('}')
                    .expect("envelope object")
            ),
            |error| matches!(error, ProfileError::InvalidEnvelopeJson(_)),
        ),
        (
            "schema version",
            EARLIER_REALITY_ENVELOPE.replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1),
            |error| matches!(error, ProfileError::UnsupportedSchema(2)),
        ),
        (
            "identity",
            EARLIER_REALITY_ENVELOPE.replacen(
                EARLIER_REALITY_ID,
                "4c0e7d3f-5a2b-4f9c-8d8e-3b6a9f2c1d5e",
                1,
            ),
            |error| matches!(error, ProfileError::IdentityMismatch { .. }),
        ),
    ];
    for (case, envelope, expected) in cases {
        let (root, repository) = repository("earlier-damaged");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = stored_path(&root, EARLIER_REALITY_ID);
        write_private(&path, envelope.as_bytes());
        let error = repository.snapshot().expect_err(case);
        assert!(expected(&error), "{case}: {error}");
        let error = repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .expect_err(case);
        assert!(expected(&error), "{case}: {error}");
        assert_eq!(
            fs::read_to_string(&path).expect("entry kept"),
            envelope,
            "{case}"
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }

    for case in ["mode", "hard link"] {
        let (root, repository) = repository("earlier-unsafe");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = store_earlier_reality_profile(&root, false);
        if case == "mode" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("weaken mode");
        } else {
            fs::hard_link(&path, root.join("external-link.json")).expect("hard link");
        }
        assert!(
            matches!(repository.snapshot(), Err(ProfileError::UnsafeProfileFile(id)) if id == EARLIER_REALITY_ID),
            "{case}"
        );
        assert!(
            matches!(
                repository.delete(EARLIER_REALITY_ID, InvalidSelection::Clear),
                Err(ProfileError::UnsafeProfileFile(_))
            ),
            "{case}"
        );
        assert!(path.exists(), "{case}");
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn a_selection_bound_to_another_digest_of_an_invalid_profile_fails_closed() {
    let (root, repository) = repository("earlier-stale-selection");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);
    write_private(
        &selection_path(&root),
        EARLIER_REALITY_SELECTION
            .replacen(EARLIER_REALITY_DIGEST, &"11".repeat(32), 1)
            .as_bytes(),
    );
    assert!(matches!(
        repository.snapshot(),
        Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == EARLIER_REALITY_ID
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn prepared_online_selection_is_invisible_until_commit_and_drop_keeps_the_prior_profile() {
    let (root, repository) = repository("online-selection");
    let first = repository.import(Some("First"), &profile()).unwrap();
    let second = repository.import(Some("Second"), &profile()).unwrap();
    repository.select(&first.id).unwrap();
    let before = fs::read(selection_path(&root)).unwrap();
    {
        let mutation = repository.begin_credential_profile_mutation().unwrap();
        assert_eq!(
            mutation
                .selected_profile()
                .unwrap()
                .into_valid()
                .unwrap()
                .record
                .id,
            first.id
        );
        assert_eq!(mutation.profile(&second.id).unwrap().record.id, second.id);
        assert_eq!(fs::read(selection_path(&root)).unwrap(), before);
    }
    assert_eq!(repository.require_selected().unwrap().record.id, first.id);
    repository
        .begin_credential_profile_mutation()
        .unwrap()
        .commit_selection(&second.id)
        .unwrap();
    assert_eq!(repository.require_selected().unwrap().record.id, second.id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_failed_prepared_selection_preserves_the_prior_selection() {
    let (root, repository) = repository("online-selection-failure");
    let first = repository.import(Some("First"), &profile()).unwrap();
    repository.select(&first.id).unwrap();
    let before = fs::read(selection_path(&root)).unwrap();
    let missing = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let error = repository
        .begin_credential_profile_mutation()
        .unwrap()
        .commit_selection(missing)
        .unwrap_err();
    assert!(matches!(error, ProfileError::SelectedProfileMissing(_)));
    assert_eq!(fs::read(selection_path(&root)).unwrap(), before);
    assert_eq!(repository.require_selected().unwrap().record.id, first.id);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn import_list_load_and_delete_round_trip_is_private_and_atomic() {
    let (root, repository) = repository("round-trip");
    let imported = repository
        .import(Some(" Work profile "), &profile())
        .expect("import profile");
    assert_eq!(imported.name, "Work profile");

    let profiles_dir = root.join("profiles");
    assert_eq!(
        fs::metadata(&profiles_dir)
            .expect("directory metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&profiles_dir)
            .expect("directory metadata")
            .uid(),
        unsafe { libc::geteuid() }
    );
    let entries = fs::read_dir(&profiles_dir)
        .expect("read profiles")
        .collect::<Result<Vec<_>, _>>()
        .expect("profile entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0]
            .metadata()
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        entries[0].metadata().expect("file metadata").uid(),
        unsafe { libc::geteuid() }
    );
    assert!(!entries[0].file_name().to_string_lossy().contains(".tmp"));

    let records = listed(&repository).expect("list profiles");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, imported.id);
    assert_eq!(records[0].digest, imported.digest);
    let loaded = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(loaded.profile, profile());

    assert!(
        repository
            .delete(&imported.id, InvalidSelection::Keep)
            .expect("delete profile")
    );
    assert!(
        !repository
            .delete(&imported.id, InvalidSelection::Keep)
            .expect("idempotent delete")
    );
    assert!(listed(&repository).expect("empty list").is_empty());
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn exact_id_import_is_idempotent_and_never_overwrites_a_conflict() {
    let (root, repository) = repository("exact-id-import");
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let original = profile();
    let imported = repository
        .import_with_id_and_source_outcome(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/profile"),
        )
        .expect("first exact import");
    assert!(imported.created);
    let replayed = repository
        .import_with_id_and_source_outcome(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/profile"),
        )
        .expect("exact replay");
    assert!(!replayed.created);
    assert_eq!(replayed.profile, imported.profile);

    for conflict in [
        repository.import_with_id_and_source(
            id,
            Some("Different name"),
            &original,
            Some("https://subscription.example/profile"),
        ),
        repository.import_with_id_and_source(
            id,
            Some("Migrated subscription"),
            &ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"tag":"block","type":"block"}]}"#)
                .expect("different valid profile"),
            Some("https://subscription.example/profile"),
        ),
        repository.import_with_id_and_source(
            id,
            Some("Migrated subscription"),
            &original,
            Some("https://subscription.example/other"),
        ),
    ] {
        assert!(matches!(conflict, Err(ProfileError::AlreadyExists(existing)) if existing == id));
    }
    assert_eq!(listed(&repository).expect("single exact profile").len(), 1);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn credential_snapshot_is_stable_and_preserves_cross_profile_reference_ownership() {
    const SHARED: &str = "11111111-1111-4111-8111-111111111111";
    const ROTATED: &str = "22222222-2222-4222-8222-222222222222";
    let (root, repository) = repository("credential-snapshot");
    let empty = repository
        .credential_snapshot()
        .expect("empty credential snapshot");
    assert_eq!(empty.profile_count, 0);
    assert!(empty.catalog.is_empty());
    assert_eq!(empty.snapshot_digest.len(), 64);

    let first = repository
        .import(Some("First"), &credential_profile(SHARED))
        .expect("first shared profile");
    let second = repository
        .import(Some("Second"), &credential_profile(SHARED))
        .expect("second shared profile");
    let shared = repository
        .credential_snapshot()
        .expect("shared credential snapshot");
    assert_eq!(shared.profile_count, 2);
    assert_eq!(shared.catalog.len(), 2);
    assert!(
        shared
            .catalog
            .iter()
            .all(|entry| entry.references.len() == 1 && entry.references[0].id() == SHARED)
    );
    assert_ne!(shared.catalog[0].audience, shared.catalog[1].audience);
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("stable credential snapshot"),
        shared
    );

    repository.select(&first.id).expect("select first profile");
    let selected = repository
        .credential_snapshot()
        .expect("selected credential snapshot");
    assert_eq!(
        selected.selected_profile_id.as_deref(),
        Some(first.id.as_str())
    );
    assert_ne!(selected.snapshot_digest, shared.snapshot_digest);

    repository
        .select(&second.id)
        .expect("select second profile");
    assert!(
        repository
            .delete(&first.id, InvalidSelection::Keep)
            .expect("delete unselected shared profile")
    );
    let retained = repository
        .credential_snapshot()
        .expect("shared reference retained");
    assert_eq!(retained.catalog.len(), 1);
    assert_eq!(retained.catalog[0].references[0].id(), SHARED);

    let rotated = repository
        .import(Some("Rotated"), &credential_profile(ROTATED))
        .expect("rotated profile");
    let pending_rotation = repository
        .credential_snapshot()
        .expect("unselected rotation is live");
    assert_eq!(pending_rotation.profile_count, 2);
    // Catalog order is canonical by audience (randomly generated profile
    // ids), so compare reference sets instead of positions.
    let mut pending_reference_ids = pending_rotation
        .catalog
        .iter()
        .flat_map(|entry| entry.references.iter())
        .map(|reference| reference.id())
        .collect::<Vec<_>>();
    pending_reference_ids.sort_unstable();
    assert_eq!(pending_reference_ids, vec![SHARED, ROTATED]);

    repository
        .select(&rotated.id)
        .expect("select rotated profile");
    assert!(
        repository
            .delete(&second.id, InvalidSelection::Keep)
            .expect("delete obsolete profile")
    );
    let completed_rotation = repository
        .credential_snapshot()
        .expect("completed rotation snapshot");
    assert_eq!(completed_rotation.profile_count, 1);
    assert_eq!(completed_rotation.catalog.len(), 1);
    assert_eq!(completed_rotation.catalog[0].references[0].id(), ROTATED);
    assert_ne!(
        completed_rotation.snapshot_digest,
        pending_rotation.snapshot_digest
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn locked_credential_snapshot_blocks_profile_mutation_until_native_commit_finishes() {
    let (root, repository) = repository("credential-snapshot-lock");
    repository
        .import(Some("Initial"), &profile())
        .expect("initial profile");
    let guard = repository
        .lock_credential_snapshot()
        .expect("credential snapshot lock");
    let expected_digest = guard.snapshot().snapshot_digest.clone();
    let writer_repository = repository.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        let result = writer_repository.import(Some("Blocked"), &profile());
        sender.send(result).expect("send writer result");
    });

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(guard.snapshot().snapshot_digest, expected_digest);
    drop(guard);
    receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("writer unblocked")
        .expect("blocked import succeeds");
    writer.join().expect("writer thread");

    let after = repository
        .credential_snapshot()
        .expect("post-commit snapshot");
    assert_ne!(after.snapshot_digest, expected_digest);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn locked_credential_profile_mutation_blocks_gc_reread_until_audience_commit() {
    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const REFERENCE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let (root, repository) = repository("credential-mutation-lock");
    let stale_preview_snapshot = repository
        .credential_snapshot()
        .expect("pre-provision credential snapshot");
    let mutation = repository
        .begin_credential_profile_mutation()
        .expect("credential profile mutation lock");

    let gc_repository = repository.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let gc_reread = std::thread::spawn(move || {
        let locked = gc_repository
            .lock_credential_snapshot()
            .expect("competing GC snapshot lock");
        sender
            .send(locked.snapshot().clone())
            .expect("send GC snapshot");
    });

    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    let imported = mutation
        .commit_exact_import(
            PROFILE_ID,
            Some("Vault prepared"),
            &credential_profile(REFERENCE_ID),
            Some("https://subscription.example/profile"),
        )
        .expect("commit prepared audience");
    assert!(imported.created);

    let current = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("GC reread unblocked after profile commit");
    gc_reread.join().expect("GC reread thread");
    assert_ne!(
        current.snapshot_digest, stale_preview_snapshot.snapshot_digest,
        "a GC commit bound to the pre-provision snapshot must fail closed"
    );
    let live = current
        .catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == PROFILE_ID)
        .expect("new audience is live when GC acquires the lock");
    assert_eq!(live.audience.profile_digest(), imported.profile.digest);
    assert_eq!(live.references.len(), 1);
    assert_eq!(live.references[0].id(), REFERENCE_ID);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn digest_tampering_is_reported_instead_of_skipped() {
    let (root, repository) = repository("digest-tamper");
    let imported = repository.import(None, &profile()).expect("import profile");
    let path = stored_path(&root, &imported.id);
    let raw = fs::read_to_string(&path).expect("read envelope");
    let tampered = raw.replacen(&imported.digest, &"00".repeat(32), 1);
    assert_ne!(tampered, raw);
    fs::write(&path, tampered).expect("tamper envelope");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::DigestMismatch { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn oversized_stored_file_is_rejected_before_deserialization() {
    let (root, repository) = repository("oversized");
    let profiles_dir = root.join("profiles");
    fs::create_dir_all(&profiles_dir).expect("create directory");
    fs::set_permissions(&profiles_dir, fs::Permissions::from_mode(0o700))
        .expect("set directory permissions");
    let id = Uuid::new_v4().hyphenated().to_string();
    let path = stored_path(&root, &id);
    fs::write(&path, vec![b' '; MAX_STORED_BYTES + 1]).expect("write oversized file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set file permissions");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::StoredProfileTooLarge { .. })
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn traversal_and_noncanonical_ids_are_rejected() {
    let (_root, repository) = repository("invalid-id");
    for id in [
        "../profile",
        "00000000000000000000000000000000",
        "NOT-A-UUID",
    ] {
        assert!(matches!(
            repository.load(id),
            Err(ProfileError::InvalidProfileId(_))
        ));
        assert!(matches!(
            repository.delete(id, InvalidSelection::Keep),
            Err(ProfileError::InvalidProfileId(_))
        ));
    }
}

#[test]
fn symlink_profile_is_rejected_without_reading_target() {
    let (root, repository) = repository("symlink");
    fs::create_dir_all(root.join("profiles")).expect("create profiles directory");
    fs::set_permissions(root.join("profiles"), fs::Permissions::from_mode(0o700))
        .expect("set directory mode");
    let outside = root.join("outside.json");
    fs::write(&outside, b"secret").expect("write outside file");
    let id = Uuid::new_v4().hyphenated().to_string();
    symlink(&outside, stored_path(&root, &id)).expect("create symlink");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"secret");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn hard_link_profile_is_rejected() {
    let (root, repository) = repository("hard-link");
    let imported = repository.import(None, &profile()).expect("import profile");
    fs::hard_link(
        stored_path(&root, &imported.id),
        root.join("external-link.json"),
    )
    .expect("create hard link");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnsafeProfileFile(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn one_way_cleanup_unlinks_symlinks_without_touching_targets() {
    let (root, repository) = repository("cleanup");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("external-profile.json");
    fs::write(&outside, b"external").expect("write external file");
    symlink(&outside, root.join("profiles").join("legacy.yaml")).expect("create legacy symlink");

    assert_eq!(
        repository.clear_managed_profiles().expect("clear profiles"),
        2
    );
    assert!(listed(&repository).expect("empty profile list").is_empty());
    assert_eq!(fs::read(&outside).expect("external target"), b"external");
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn malformed_or_unexpected_entries_are_not_silently_skipped() {
    let (root, repository) = repository("unexpected");
    fs::create_dir_all(root.join("profiles")).expect("create directory");
    fs::write(root.join("profiles").join("legacy.yaml"), b"proxies: []")
        .expect("write legacy entry");
    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn concurrent_listing_never_observes_an_atomic_write_temporary() {
    let (root, repository) = repository("concurrent-list");
    let repository = Arc::new(repository);
    assert!(
        listed(&repository)
            .expect("initial profile list")
            .is_empty()
    );
    let barrier = Arc::new(Barrier::new(2));

    let writer_repository = Arc::clone(&repository);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..12 {
            writer_repository
                .import(Some(&format!("Profile {index}")), &profile())
                .expect("atomic profile import");
        }
    });

    barrier.wait();
    for _ in 0..48 {
        listed(&repository).expect("listing must not observe an in-flight temporary file");
    }
    writer.join().expect("writer thread");
    assert_eq!(listed(&repository).expect("final profile list").len(), 12);
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn abandoned_import_and_selection_temporaries_are_recovered_under_the_lock() {
    let (root, repository) = repository("temporary-recovery");
    let imported = repository.import(None, &profile()).expect("import profile");
    let profiles_dir = root.join("profiles");
    let import_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    let selection_temporary = profiles_dir.join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    for path in [&import_temporary, &selection_temporary] {
        fs::write(path, b"interrupted private transaction").expect("write abandoned temporary");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("private temporary mode");
    }

    assert_eq!(
        listed(&repository).expect("recover before listing").len(),
        1
    );
    assert!(!import_temporary.exists());
    assert!(!selection_temporary.exists());
    repository
        .select(&imported.id)
        .expect("selection works after recovery");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn unsafe_matching_temporary_is_rejected_without_following_it() {
    let (root, repository) = repository("unsafe-temporary");
    repository.import(None, &profile()).expect("import profile");
    let outside = root.join("outside-temporary");
    fs::write(&outside, b"external").expect("outside target");
    let temporary = root
        .join("profiles")
        .join(format!(".{}.tmp", Uuid::new_v4().hyphenated()));
    symlink(&outside, &temporary).expect("matching temporary symlink");

    assert!(matches!(
        listed(&repository),
        Err(ProfileError::UnexpectedEntry(_))
    ));
    assert_eq!(fs::read(&outside).expect("outside target"), b"external");
    assert!(temporary.is_symlink());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn selection_round_trip_is_private_digest_bound_and_blocks_selected_deletion() {
    let (root, repository) = repository("selection-round-trip");
    let imported = repository.import(None, &profile()).expect("import profile");

    let selected = repository.select(&imported.id).expect("select profile");
    assert_eq!(selected.id, imported.id);
    let selection_metadata = fs::metadata(selection_path(&root)).expect("selection metadata");
    assert_eq!(selection_metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(selection_metadata.uid(), unsafe { libc::geteuid() });

    let snapshot = repository.snapshot().expect("repository snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(imported.id.as_str())
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected")
            .expect("selected profile")
            .record
            .id,
        imported.id
    );
    // Only an invalid selected profile may be deleted with the engine Off.
    for engine in [InvalidSelection::Keep, InvalidSelection::Clear] {
        assert!(matches!(
            repository.delete(&imported.id, engine),
            Err(ProfileError::SelectedProfileDeletion(id)) if id == imported.id
        ));
    }
    assert!(stored_path(&root, &imported.id).exists());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn missing_selected_profile_is_a_stale_selection_error_without_direct_fallback() {
    let (root, repository) = repository("selection-missing");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    fs::remove_file(stored_path(&root, &imported.id)).expect("remove selected envelope");

    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));
    assert!(matches!(
        repository.import(Some("must not append"), &profile()),
        Err(ProfileError::SelectedProfileMissing(id)) if id == imported.id
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn changed_selection_digest_and_unknown_fields_are_rejected() {
    let (root, repository) = repository("selection-tamper");
    let imported = repository.import(None, &profile()).expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let path = selection_path(&root);

    let raw = fs::read_to_string(&path).expect("read selection");
    let tampered = raw.replacen(&imported.digest, &"00".repeat(32), 1);
    assert_ne!(tampered, raw);
    fs::write(&path, tampered).expect("tamper selection digest");
    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == imported.id
    ));

    let with_unknown = format!(
        "{},\"unexpected\":true}}",
        raw.strip_suffix('}').expect("selection object")
    );
    fs::write(&path, with_unknown).expect("add unknown field");
    assert!(matches!(
        repository.load_selected(),
        Err(ProfileError::InvalidSelectionJson(_))
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn explicit_selection_can_repair_stale_metadata() {
    let (root, repository) = repository("selection-repair");
    let first = repository
        .import(Some("first"), &profile())
        .expect("first profile");
    let second = repository
        .import(Some("second"), &profile())
        .expect("second profile");
    repository.select(&first.id).expect("select first");

    let path = selection_path(&root);
    fs::write(
        &path,
        br#"{"profile_digest":"invalid","profile_id":"invalid","schema_version":1}"#,
    )
    .expect("corrupt selection");
    repository
        .select(&second.id)
        .expect("explicitly replace stale selection");
    assert_eq!(
        repository
            .load_selected()
            .expect("load repaired selection")
            .expect("selected profile")
            .record
            .id,
        second.id
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn subscription_url_survives_a_round_trip_and_is_bounded() {
    let (root, repository) = repository("subscription-round-trip");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &profile(),
            Some("https://example.com/sub?token=t"),
        )
        .expect("import remote profile");
    let stored = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(
        stored.source_url.as_deref(),
        Some("https://example.com/sub?token=t")
    );

    // A local import has no subscription URL, and the listing never carries one.
    let local = repository
        .import(Some("Local"), &profile())
        .expect("import local profile");
    assert_eq!(
        repository
            .load(&local.id)
            .expect("load local")
            .expect("stored local")
            .source_url,
        None
    );
    let listed = serde_json::to_string(&repository.snapshot().expect("list profiles"))
        .expect("serialize records");
    assert!(!listed.contains("token=t"));
    assert!(!listed.contains("source_url"));

    for rejected in [
        "not-a-url",
        "http://example.com/sub",
        "https://example.com/ sub",
        " https://example.com/sub",
    ] {
        assert!(
            matches!(
                repository.import_with_source(Some("Rejected"), &profile(), Some(rejected)),
                Err(ProfileError::InvalidSourceUrl)
            ),
            "accepted invalid subscription URL: {rejected}"
        );
    }
    let oversized = format!("https://example.com/{}", "a".repeat(2_048));
    assert!(matches!(
        repository.import_with_source(Some("Oversized"), &profile(), Some(&oversized)),
        Err(ProfileError::InvalidSourceUrl)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn envelopes_written_before_subscriptions_existed_are_still_canonical() {
    let (root, repository) = repository("legacy-envelope");
    let imported = repository
        .import(Some("Legacy"), &profile())
        .expect("import profile");
    let path = stored_path(&root, &imported.id);
    let bytes = fs::read(&path).expect("read envelope");
    let rendered = String::from_utf8(bytes).expect("utf-8 envelope");
    assert!(
        !rendered.contains("source_url"),
        "an absent subscription URL must not be written"
    );

    // The unchanged bytes must still decode, so an installation created before
    // this field existed keeps working.
    let stored = repository
        .load(&imported.id)
        .expect("load legacy envelope")
        .expect("stored profile");
    assert_eq!(stored.source_url, None);
    assert_eq!(stored.record.name, "Legacy");

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn replace_keeps_identity_credentials_and_rebinds_the_selection_digest() {
    let (root, repository) = repository("replace");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/sub"),
        )
        .expect("import remote profile");
    repository.select(&imported.id).expect("select profile");

    let replacement = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let saved = repository
        .replace(
            &imported.id,
            None,
            &replacement,
            Some("https://example.com/sub2"),
        )
        .expect("replace profile");
    assert_eq!(saved.id, imported.id, "identity must be stable");
    assert_eq!(saved.name, "Remote", "the name is preserved by default");
    assert_eq!(saved.digest, replacement.digest());

    // The selection is rebound under the same lock, so the repository is
    // readable and the selected profile is the replacement.
    let selected = repository
        .load_selected()
        .expect("load selection after replace")
        .expect("selected profile");
    assert_eq!(selected.record.id, imported.id);
    assert_eq!(selected.record.digest, replacement.digest());
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://example.com/sub2")
    );
    assert_eq!(
        selected.profile.credential_references(),
        replacement.credential_references()
    );
    assert_eq!(
        repository
            .credential_snapshot()
            .expect("credential snapshot")
            .catalog
            .into_iter()
            .flat_map(|entry| entry.references)
            .collect::<Vec<_>>(),
        replacement.credential_references(),
        "the replaced document's credential references are no longer live"
    );

    // Only one entry plus the selection exists: replacing never adds a profile.
    let entries = fs::read_dir(root.join("profiles"))
        .expect("read profiles")
        .collect::<Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 2);

    assert!(matches!(
        repository.replace(
            "34db18b6-9903-4e9f-8854-15648e19e4f3",
            None,
            &profile(),
            None
        ),
        Err(ProfileError::Io(_))
    ));
    assert!(matches!(
        repository.replace("not-a-uuid", None, &profile(), None),
        Err(ProfileError::InvalidProfileId(_))
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn rollback_restore_preserves_the_complete_loaded_profile_identity() {
    let (root, repository) = repository("restore");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import original profile");
    repository.select(&imported.id).expect("select profile");
    let original = repository
        .load(&imported.id)
        .expect("load original")
        .expect("original profile");

    repository
        .replace(
            &imported.id,
            Some("Replacement"),
            &profile(),
            Some("https://example.com/replacement"),
        )
        .expect("replace before rollback");
    repository
        .restore(&original)
        .expect("restore exact profile");

    assert_eq!(
        repository
            .load_selected()
            .expect("load restored selection")
            .expect("restored selected profile"),
        original
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn conditional_replace_rejects_rebound_sources_and_out_of_order_responses() {
    let (root, repository) = repository("conditional-replace");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import remote profile");
    let before_rebind = repository
        .load(&imported.id)
        .expect("load before rebind")
        .expect("stored profile");
    repository
        .update_metadata(
            &imported.id,
            Some("Rebound"),
            Some("https://example.com/rebound"),
        )
        .expect("rebind subscription source");

    let stale_response = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    assert!(matches!(
        repository.replace_if_unchanged(
            &before_rebind,
            None,
            &stale_response,
            Some("https://example.com/original")
        ),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    let rebound = repository
        .load(&imported.id)
        .expect("load after stale response")
        .expect("stored profile");
    assert_eq!(rebound.record.name, "Rebound");
    assert_eq!(
        rebound.source_url.as_deref(),
        Some("https://example.com/rebound")
    );
    assert_eq!(rebound.profile, before_rebind.profile);

    let first_fetch_snapshot = rebound.clone();
    let second_fetch_snapshot = rebound.clone();
    let newest_response = credential_profile("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    let older_response = credential_profile("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
    repository
        .replace_if_unchanged(
            &second_fetch_snapshot,
            None,
            &newest_response,
            second_fetch_snapshot.source_url.as_deref(),
        )
        .expect("newest response commits first");
    assert!(matches!(
        repository.replace_if_unchanged(
            &first_fetch_snapshot,
            None,
            &older_response,
            first_fetch_snapshot.source_url.as_deref()
        ),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    assert_eq!(
        repository
            .load(&imported.id)
            .expect("load after out-of-order response")
            .expect("stored profile")
            .profile,
        newest_response
    );

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn conditional_restore_never_overwrites_a_newer_edit() {
    let (root, repository) = repository("conditional-restore");
    let imported = repository
        .import_with_source(
            Some("Remote"),
            &credential_profile("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            Some("https://example.com/original"),
        )
        .expect("import remote profile");
    let original = repository
        .load(&imported.id)
        .expect("load original")
        .expect("stored profile");
    let replacement = credential_profile("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    let (_result, committed) = repository
        .replace_if_unchanged(
            &original,
            None,
            &replacement,
            Some("https://example.com/replacement"),
        )
        .expect("commit replacement");
    repository
        .update_metadata(
            &imported.id,
            Some("Edited after commit"),
            Some("https://example.com/edited"),
        )
        .expect("edit replacement before rollback");

    assert!(matches!(
        repository.restore_if_unchanged(&committed, &original),
        Err(ProfileError::ProfileChanged { ref id }) if id == &imported.id
    ));
    let current = repository
        .load(&imported.id)
        .expect("load after rejected rollback")
        .expect("stored profile");
    assert_eq!(current.record.name, "Edited after commit");
    assert_eq!(
        current.source_url.as_deref(),
        Some("https://example.com/edited")
    );
    assert_eq!(current.profile, replacement);

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn metadata_updates_change_no_document_digest_or_selection() {
    let (root, repository) = repository("metadata");
    let imported = repository
        .import(Some("Original"), &profile())
        .expect("import profile");
    repository.select(&imported.id).expect("select profile");
    let before = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");

    let renamed = repository
        .update_metadata(
            &imported.id,
            Some(" Renamed "),
            Some("https://example.com/sub"),
        )
        .expect("update metadata");
    assert_eq!(renamed.name, "Renamed");
    assert_eq!(renamed.digest, before.record.digest);
    assert_eq!(
        renamed.created_epoch_secs, before.record.created_epoch_secs,
        "renaming is not an update of the profile itself"
    );

    let after = repository
        .load_selected()
        .expect("load selection")
        .expect("selected profile");
    assert_eq!(after.record.id, imported.id);
    assert_eq!(after.record.name, "Renamed");
    assert_eq!(after.source_url.as_deref(), Some("https://example.com/sub"));

    // Clearing the subscription URL is allowed and keeps the profile intact.
    repository
        .update_metadata(&imported.id, None, None)
        .expect("clear subscription");
    let cleared = repository
        .load(&imported.id)
        .expect("load profile")
        .expect("stored profile");
    assert_eq!(cleared.source_url, None);
    assert_eq!(cleared.record.name, "Renamed");
    assert_eq!(cleared.record.digest, before.record.digest);

    assert!(matches!(
        repository.update_metadata(&imported.id, Some("bad/name"), None),
        Err(ProfileError::InvalidName)
    ));

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn profile_entry_name_resolves_only_existing_canonical_ids() {
    let (root, repository) = repository("entry-name");
    let imported = repository
        .import(Some("Local"), &profile())
        .expect("import profile");
    assert_eq!(
        repository
            .profile_entry_name(&imported.id)
            .expect("entry name"),
        Some(format!("{}.profile.json", imported.id))
    );
    assert_eq!(
        repository
            .profile_entry_name("34db18b6-9903-4e9f-8854-15648e19e4f3")
            .expect("absent profile"),
        None
    );
    assert!(repository.profile_entry_name("../escape").is_err());

    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn invalid_profiles_count_toward_the_entry_limit() {
    // Mirrors the crate's 4,096-entry repository limit.
    const MAX_ENTRIES: usize = 4_096;
    let (root, repository) = repository("invalid-capacity");
    let seed = repository
        .import(Some("Seed"), &profile())
        .expect("import seed profile");
    let template = fs::read_to_string(stored_path(&root, &seed.id)).expect("read seed envelope");
    // The seed, the copies and the invalid entry fill the repository.
    for _ in 0..MAX_ENTRIES - 2 {
        let id = Uuid::new_v4().hyphenated().to_string();
        write_private(
            &stored_path(&root, &id),
            template.replacen(&seed.id, &id, 1).as_bytes(),
        );
    }
    store_earlier_reality_profile(&root, false);
    let snapshot = repository
        .snapshot()
        .expect("a full repository still lists");
    assert_eq!(snapshot.profiles.len(), MAX_ENTRIES - 1);
    assert_eq!(snapshot.invalid_profiles.len(), 1);

    assert!(matches!(
        repository.import(Some("One too many"), &profile()),
        Err(ProfileError::TooManyEntries)
    ));
    repository
        .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
        .expect("delete the invalid profile");
    repository
        .import(Some("Fits again"), &profile())
        .expect("the freed entry admits one import");
    fs::remove_dir_all(root).expect("remove test directory");
}

/// Appends optional envelope metadata in its canonical position at the end.
fn with_envelope_metadata(envelope: &str, metadata: &str) -> String {
    format!(
        "{},{metadata}}}",
        envelope.strip_suffix('}').expect("envelope object")
    )
}

#[test]
fn metadata_that_fails_current_validation_lists_the_profile_invalid() {
    let selector = ValidatedSingBoxProfile::parse(
        r#"{"outbounds":[{"type":"selector","tag":"Proxy","outbounds":["direct"]},{"type":"direct","tag":"direct"}],"route":{"final":"Proxy"}}"#,
    )
    .expect("selector profile");
    for (case, profile, metadata, reason) in [
        (
            "provider sources",
            profile(),
            r#""provider_sources":{"proxy:missing":"https://provider.example/list"}"#,
            "unsupported credential-free policy shape at $.providers: provider URLs have no matching catalog",
        ),
        (
            "proxy selections",
            selector.clone(),
            r#""proxy_selections":{"Proxy":"missing"}"#,
            "unsupported credential-free policy shape at $.outbounds: selection must name a member of the group",
        ),
    ] {
        let (root, repository) = repository("metadata-invalid");
        let other = repository
            .import(Some("Other"), &selector)
            .expect("import other profile");
        let target = repository
            .import(Some("Target"), &profile)
            .expect("import target profile");
        let path = stored_path(&root, &target.id);
        let envelope =
            with_envelope_metadata(&fs::read_to_string(&path).expect("read envelope"), metadata);
        write_private(&path, envelope.as_bytes());

        let snapshot = repository.snapshot().expect(case);
        assert_eq!(snapshot.profiles.len(), 1, "{case}");
        assert_eq!(snapshot.profiles[0].id, other.id, "{case}");
        assert_eq!(snapshot.invalid_profiles.len(), 1, "{case}");
        assert_eq!(snapshot.invalid_profiles[0].id, target.id, "{case}");
        assert_eq!(
            snapshot.invalid_profiles[0].error.to_string(),
            reason,
            "{case}"
        );
        assert!(matches!(
            repository.load(&target.id),
            Err(ProfileError::StoredProfileInvalid { id, .. }) if id == target.id
        ));
        repository.select(&other.id).expect(case);
        assert!(
            repository
                .delete(&target.id, InvalidSelection::Keep)
                .expect(case)
        );
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn a_loaded_profile_that_later_fails_validation_is_never_replaced_or_restored() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-stale-load");
    repository
        .import_with_id_and_source(
            EARLIER_REALITY_ID,
            Some("Reality node"),
            &profile(),
            Some(URL),
        )
        .expect("import a valid profile under the earlier id");
    let stored = repository
        .load(EARLIER_REALITY_ID)
        .expect("load")
        .expect("stored profile");
    let path = store_earlier_reality_profile(&root, false);

    let attempts: [&dyn Fn() -> Result<(), ProfileError>; 4] = [
        &|| {
            repository
                .begin_credential_profile_mutation_if_unchanged(&stored)
                .map(|_| ())
        },
        &|| {
            repository
                .replace_if_unchanged(&stored, None, &profile(), Some(URL))
                .map(|_| ())
        },
        &|| repository.restore(&stored).map(|_| ()),
        &|| {
            repository
                .restore_if_unchanged(&stored, &stored)
                .map(|_| ())
        },
    ];
    for attempt in attempts {
        let error = attempt().expect_err("an invalid entry is never overwritten");
        assert!(is_earlier_invalid(&error), "{error}");
    }
    assert_eq!(
        fs::read_to_string(&path).expect("read envelope"),
        EARLIER_REALITY_ENVELOPE
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn invalid_profiles_are_listed_and_named_in_profile_order() {
    const SECOND_ID: &str = "f0000000-0000-4000-8000-000000000001";
    let (root, repository) = repository("earlier-order");
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, false);
    write_private(
        &stored_path(&root, SECOND_ID),
        EARLIER_REALITY_ENVELOPE
            .replacen(EARLIER_REALITY_ID, SECOND_ID, 1)
            .replacen(r#""name":"Reality node""#, r#""name":"A Reality node""#, 1)
            .as_bytes(),
    );

    let snapshot = repository.snapshot().expect("snapshot");
    // By name, then id: the id order alone would list them the other way.
    assert_eq!(
        snapshot
            .invalid_profiles
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec![SECOND_ID, EARLIER_REALITY_ID]
    );
    let error = repository
        .credential_snapshot()
        .expect_err("cleanup refused");
    assert_eq!(
        error.to_string(),
        "credential cleanup needs every stored profile to pass validation; delete the invalid profiles first: \"A Reality node\" (f0000000-0000-4000-8000-000000000001), \"Reality node\" (3b9d6c2e-4f1a-4e8b-9c7d-2a5f8e1b0c4d)"
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn linked_or_oversized_invalid_profiles_still_fail_closed() {
    for case in ["symlink", "oversized"] {
        let (root, repository) = repository("earlier-linked");
        repository
            .import(Some("Other"), &profile())
            .expect("import other profile");
        let path = stored_path(&root, EARLIER_REALITY_ID);
        let outside = root.join("outside.profile.json");
        if case == "symlink" {
            write_private(&outside, EARLIER_REALITY_ENVELOPE.as_bytes());
            symlink(&outside, &path).expect("create symlink");
        } else {
            write_private(
                &path,
                format!("{EARLIER_REALITY_ENVELOPE}{}", " ".repeat(MAX_STORED_BYTES)).as_bytes(),
            );
        }
        for result in [
            repository.snapshot().map(|_| ()),
            repository
                .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
                .map(|_| ()),
        ] {
            let error = result.expect_err(case);
            assert!(
                matches!(
                    (case, &error),
                    ("symlink", ProfileError::UnsafeProfileFile(_))
                        | ("oversized", ProfileError::StoredProfileTooLarge { .. })
                ),
                "{case}: {error}"
            );
        }
        assert!(path.symlink_metadata().is_ok(), "{case}: entry kept");
        if case == "symlink" {
            assert_eq!(
                fs::read_to_string(&outside).expect("target untouched"),
                EARLIER_REALITY_ENVELOPE
            );
        }
        fs::remove_dir_all(root).expect("remove test directory");
    }
}

#[test]
fn the_source_of_a_damaged_missing_or_malformed_entry_is_not_read() {
    let (root, repository) = repository("earlier-source-errors");
    assert!(matches!(
        repository.source_url(EARLIER_REALITY_ID),
        Err(ProfileError::ProfileNotFound(id)) if id == EARLIER_REALITY_ID
    ));
    repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    write_private(
        &stored_path(&root, EARLIER_REALITY_ID),
        EARLIER_REALITY_ENVELOPE
            .replacen(EARLIER_REALITY_DIGEST, &"00".repeat(32), 1)
            .as_bytes(),
    );
    assert!(matches!(
        repository.source_url(EARLIER_REALITY_ID),
        Err(ProfileError::DigestMismatch { id }) if id == EARLIER_REALITY_ID
    ));
    assert!(matches!(
        repository.source_url("../x"),
        Err(ProfileError::InvalidProfileId(_))
    ));
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn selecting_a_valid_profile_repairs_a_stale_selection_of_an_invalid_one() {
    let (root, repository) = repository("earlier-stale-repair");
    let other = repository
        .import(Some("Other"), &profile())
        .expect("import other profile");
    store_earlier_reality_profile(&root, true);
    let stale = EARLIER_REALITY_SELECTION.replacen(EARLIER_REALITY_DIGEST, &"11".repeat(32), 1);
    write_private(&selection_path(&root), stale.as_bytes());
    for result in [
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Clear)
            .map(|_| ()),
        repository.import(Some("Blocked"), &profile()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(ProfileError::SelectedProfileDigestMismatch { id, .. }) if id == EARLIER_REALITY_ID
        ));
    }
    assert_eq!(
        fs::read_to_string(selection_path(&root)).expect("selection kept"),
        stale
    );

    repository
        .select(&other.id)
        .expect("selecting a valid profile replaces the stale record");
    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(other.id.as_str())
    );
    assert_eq!(snapshot.invalid_profiles[0].id, EARLIER_REALITY_ID);
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the unselected invalid profile")
    );
    fs::remove_dir_all(root).expect("remove test directory");
}

#[test]
fn a_repository_holding_only_a_selected_invalid_profile_admits_its_replacement() {
    const URL: &str = "https://subscription.example/profile?token=private-test-value";
    let (root, repository) = repository("earlier-only");
    fs::create_dir_all(root.join("profiles")).expect("create repository");
    fs::set_permissions(root.join("profiles"), fs::Permissions::from_mode(0o700))
        .expect("private repository");
    store_earlier_reality_profile(&root, true);

    let snapshot = repository.snapshot().expect("snapshot");
    assert!(snapshot.profiles.is_empty());
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(EARLIER_REALITY_ID)
    );
    let url = repository
        .source_url(EARLIER_REALITY_ID)
        .expect("source")
        .expect("subscription URL");
    assert_eq!(url, URL);
    let replacement = repository
        .import_with_source(Some("Reality node"), &profile(), Some(&url))
        .expect("import the subscription again");
    repository
        .select(&replacement.id)
        .expect("select the replacement");
    assert!(
        repository
            .delete(EARLIER_REALITY_ID, InvalidSelection::Keep)
            .expect("delete the old entry")
    );
    let snapshot = repository.snapshot().expect("snapshot");
    assert_eq!(snapshot.profiles.len(), 1);
    assert!(snapshot.invalid_profiles.is_empty());
    assert_eq!(
        snapshot.selected_profile_id.as_deref(),
        Some(replacement.id.as_str())
    );
    fs::remove_dir_all(root).expect("remove test directory");
}
