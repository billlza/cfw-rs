//! Local profile files: absolute regular files only, a stable opened inode,
//! bounded reads, and credentials provisioned before a local import becomes
//! visible.

use super::*;

#[test]
fn local_imports_reject_directories_symlinks_and_relative_paths() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let file = temporary.path().join("profile.json");
    std::fs::write(&file, PROFILE_JSON).expect("write profile");
    assert_eq!(
        read_local_profile(&file).expect("read profile"),
        PROFILE_JSON
    );

    let link = temporary.path().join("link.json");
    symlink_file(&file, &link);
    assert!(read_local_profile(&link).is_err());
    assert!(read_local_profile(temporary.path()).is_err());
    assert!(read_local_profile(Path::new("relative.json")).is_err());
}

#[test]
fn opened_profile_inode_is_stable_across_path_replacement() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profile = temporary.path().join("profile.json");
    let retained = temporary.path().join("opened-profile.json");
    let replacement = temporary.path().join("replacement.json");
    std::fs::write(&profile, PROFILE_JSON).expect("write original profile");
    std::fs::write(&replacement, "replacement").expect("write replacement");

    let opened = local_file::open(&profile).expect("open original profile once");
    std::fs::rename(&profile, &retained).expect("retain opened inode under another name");
    symlink_file(&replacement, &profile);

    assert_eq!(
        local_file::read_opened(opened, MAX_SUBSCRIPTION_DOCUMENT_BYTES)
            .expect("read the already-opened file"),
        PROFILE_JSON
    );
    assert!(read_local_profile(&profile).is_err());
}

fn symlink_file(original: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(original, link).expect("create symlink");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(original, link).expect("create symlink");
}

#[test]
fn opened_profile_read_is_bounded_even_when_metadata_exceeds_the_limit() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profile = temporary.path().join("oversized.json");
    std::fs::write(&profile, vec![b'x'; MAX_SUBSCRIPTION_DOCUMENT_BYTES + 1])
        .expect("write oversized profile");
    assert!(read_local_profile(&profile).is_err());
}

#[test]
fn local_source_limit_allows_clash_metadata_without_widening_stored_profiles() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let path = temporary.path().join("nodes.yaml");
    let body = format!(
        "# {}\nproxies:\n  - {{ name: SOCKS5, type: socks5, server: proxy.example.com, port: 1080, udp: true }}\n",
        "x".repeat(MAX_PROFILE_BYTES)
    );
    assert!(body.len() < MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    std::fs::write(&path, &body).expect("write bounded source");
    let loaded = read_local_profile(&path).expect("read larger source document");
    let imported = validated_subscription_import(&loaded, &EngineSettings::default())
        .expect("convert source metadata");
    assert!(imported.profile.as_json().len() < MAX_PROFILE_BYTES);
    assert!(imported.credentials.is_empty());
}

#[tokio::test]
async fn local_socks5_sources_provision_both_credentials_before_profile_visibility() {
    for (extension, body) in [
        (
            "txt",
            "socks://synthetic-user:synthetic-secret@proxy.example.com:29177",
        ),
        (
            "yaml",
            "proxies:\n  - { name: SOCKS5, type: socks5, server: proxy.example.com, port: 29177, username: synthetic-user, password: synthetic-secret, udp: true }",
        ),
        (
            "json",
            r#"{"outbounds":[{"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":29177,"username":"synthetic-user","password":"synthetic-secret"}]}"#,
        ),
    ] {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let path = temporary.path().join(format!("nodes.{extension}"));
        std::fs::write(&path, body).expect("write local source");
        let loaded = read_local_profile(&path).expect("read local source");
        let imported = validated_subscription_import(&loaded, &EngineSettings::default())
            .expect("convert local SOCKS5 source");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = ScriptedCredentialVault::new(
            temporary.path().join("profiles"),
            vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
        );
        let record = commit_profile_import(
            &repository,
            &vault,
            TRANSACTION_PROFILE_ID,
            Some("SOCKS5"),
            ProfileImportSource::Local,
            &imported,
            true,
        )
        .await
        .expect("local vault-first import");
        let requests = vault.requests();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].repository_profile_visible);
        assert_eq!(requests[0].required_references.len(), 2);
        assert_eq!(requests[0].entries.len(), 2);
        for credential in &imported.credentials {
            let expected_secret: [u8; 32] = Sha256::digest(credential.secret.as_bytes()).into();
            assert!(
                requests[0]
                    .entries
                    .contains(&(credential.reference.clone(), expected_secret))
            );
        }
        let stored = repository
            .load(&record.id)
            .expect("load")
            .expect("stored profile");
        assert_eq!(stored.profile, imported.profile);
        assert!(stored.source_url.is_none());
        assert!(!stored.profile.as_json().contains("synthetic-user"));
        assert!(!stored.profile.as_json().contains("synthetic-secret"));
        assert_eq!(
            repository
                .snapshot()
                .expect("snapshot")
                .selected_profile_id
                .as_deref(),
            Some(record.id.as_str())
        );
    }
}

#[tokio::test]
async fn local_socks5_vault_failures_never_commit_or_select_a_partial_profile() {
    let imported = validated_subscription_import(
        "socks://synthetic-user:synthetic-secret@proxy.example.com:1080",
        &EngineSettings::default(),
    )
    .expect("SOCKS5 source");
    for (responses, expected_attempts, expected_error) in [
        (
            vec![Err(CredentialVaultError::AccessDenied)],
            1,
            "access was denied",
        ),
        (
            vec![
                Err(CredentialVaultError::OutcomeUnknown),
                Err(CredentialVaultError::OutcomeUnknown),
            ],
            2,
            "after one outcome-unknown replay",
        ),
        (
            vec![
                Ok(CredentialVaultReceipt {
                    profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                    profile_digest: imported.profile.digest().into(),
                }),
                Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
            ],
            1,
            "different profile audience",
        ),
        (
            vec![
                Err(CredentialVaultError::IdentityRejected),
                Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
            ],
            1,
            "the operation result is unconfirmed",
        ),
    ] {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let original = repository
            .import(Some("Original"), &ValidatedSingBoxProfile::direct())
            .expect("original profile");
        repository.select(&original.id).expect("select original");
        let before = repository.snapshot().expect("original snapshot");
        let vault = ScriptedCredentialVault::new(temporary.path().join("profiles"), responses);
        let error = commit_profile_import(
            &repository,
            &vault,
            TRANSACTION_PROFILE_ID,
            Some("SOCKS5"),
            ProfileImportSource::Local,
            &imported,
            true,
        )
        .await
        .expect_err("unconfirmed credentials must not become visible");
        assert_eq!(repository.snapshot().expect("unchanged snapshot"), before);
        assert_eq!(vault.requests().len(), expected_attempts);
        assert_eq!(vault.garbage_collection_requests(), 0);
        if expected_attempts == 2 {
            assert_eq!(vault.requests()[0], vault.requests()[1]);
        }
        assert!(error.contains(expected_error), "{error}");
        assert!(!error.contains("data is corrupt"));
        assert!(!error.contains("synthetic-user"));
        assert!(!error.contains("synthetic-secret"));
    }
}

#[tokio::test]
async fn local_canonical_reference_only_profiles_preserve_manual_provisioning() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = validated_subscription_import(PROFILE_JSON, &EngineSettings::default())
        .expect("canonical profile awaiting manual provisioning");
    let vault = ScriptedCredentialVault::new(temporary.path().join("profiles"), Vec::new());
    let record = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Manual"),
        ProfileImportSource::Local,
        &imported,
        false,
    )
    .await
    .expect("manual setup remains available");
    assert!(vault.requests().is_empty());
    assert_eq!(
        repository
            .load(&record.id)
            .expect("load")
            .expect("profile")
            .profile,
        imported.profile
    );
    assert!(
        repository
            .snapshot()
            .expect("snapshot")
            .selected_profile_id
            .is_none()
    );
}
