//! Credential references: validation before vault staging, stable and
//! namespace-bound migration references, reuse on update, and append-only kinds.

use super::*;

#[test]
fn uuid_credentials_are_validated_before_vault_staging() {
    for (label, document) in [
        (
            "URL VMess",
            "vmess://not-a-uuid@vm.example.com:443?security=tls",
        ),
        ("VLESS", "vless://not-a-uuid@v.example.com:443?security=tls"),
        (
            "TUIC",
            "tuic://not-a-uuid:TopSecretValue!@q.example.com:443?sni=q.example.com",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains("UUID"), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

#[test]
fn migration_credential_references_are_stable_and_namespace_bound() {
    let body = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#Work";
    let namespace =
        Uuid::parse_str("aaaaaaaa-aaaa-5aaa-8aaa-aaaaaaaaaaaa").expect("migration namespace");
    let other_namespace =
        Uuid::parse_str("bbbbbbbb-bbbb-5bbb-8bbb-bbbbbbbbbbbb").expect("other migration namespace");
    let first = import_subscription_document_with_credential_namespace(body, namespace)
        .expect("first deterministic import");
    let replay = import_subscription_document_with_credential_namespace(body, namespace)
        .expect("deterministic replay");
    let other = import_subscription_document_with_credential_namespace(body, other_namespace)
        .expect("other candidate import");

    assert_eq!(first.profile, replay.profile);
    assert_eq!(
        first.credentials[0].reference,
        replay.credentials[0].reference
    );
    assert_ne!(
        first.credentials[0].reference,
        other.credentials[0].reference
    );
    assert_ne!(first.profile.digest(), other.profile.digest());
    assert_eq!(
        first.credentials[0]
            .reference
            .id()
            .parse::<Uuid>()
            .expect("credential UUID")
            .get_version_num(),
        5
    );
}

#[test]
fn subscription_updates_reuse_references_in_outbound_order() {
    let body =
        "trojan://first@one.example:443#One\nss://YWVzLTI1Ni1nY206c2Vjb25k@two.example:8388#Two";
    let initial = import_subscription_document(body).expect("initial subscription");
    let references = initial.profile.credential_references_in_outbound_order();
    let replay = import_subscription_document_with_reusable_references(body, references.clone())
        .expect("stable subscription update");
    assert_eq!(replay.profile, initial.profile);
    assert_eq!(
        replay.profile.credential_references_in_outbound_order(),
        references
    );
    assert_eq!(
        replay
            .credentials
            .iter()
            .map(|credential| credential.reference.clone())
            .collect::<Vec<_>>(),
        references
    );

    let changed_layout = import_subscription_document_with_reusable_references(
        "ss://YWVzLTI1Ni1nY206bmV3@new.example:8388#New",
        references.clone(),
    )
    .expect("changed credential layout");
    assert_ne!(
        changed_layout.credentials[0].reference, references[0],
        "a kind mismatch must not repurpose an immutable reference"
    );
}

#[test]
fn subscription_updates_handle_shared_references_without_duplicate_provisioning() {
    let initial = import_subscription_document(
        "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
    )
    .expect("initial subscription");
    let shared = initial.credentials[0].reference.clone();

    let unchanged = import_subscription_document_with_reusable_references(
        "trojan://same@one.example:443#One\ntrojan://same@two.example:443#Two",
        vec![shared.clone(), shared.clone()],
    )
    .expect("shared credential update");
    assert_eq!(unchanged.credentials.len(), 1);
    assert_eq!(unchanged.credentials[0].reference, shared);
    assert_eq!(
        unchanged.profile.credential_references_in_outbound_order(),
        vec![shared.clone(), shared.clone()]
    );

    let split = import_subscription_document_with_reusable_references(
        "trojan://first@one.example:443#One\ntrojan://second@two.example:443#Two",
        vec![shared.clone(), shared.clone()],
    )
    .expect("split credential update");
    assert_eq!(split.credentials.len(), 2);
    assert_eq!(split.credentials[0].reference, shared);
    assert_ne!(
        split.credentials[1].reference, split.credentials[0].reference,
        "different material must receive a distinct immutable reference"
    );
    assert_eq!(split.credentials[0].secret, "first");
    assert_eq!(split.credentials[1].secret, "second");
}

#[test]
fn credential_kind_discriminants_are_append_only() {
    assert_eq!(
        [
            CredentialKind::ShadowsocksPassword,
            CredentialKind::VmessUuid,
            CredentialKind::VlessUuid,
            CredentialKind::TrojanPassword,
            CredentialKind::Hysteria2Password,
            CredentialKind::Hysteria2ObfsPassword,
            CredentialKind::AnyTlsPassword,
            CredentialKind::TuicUuid,
            CredentialKind::TuicPassword,
            CredentialKind::Socks5Username,
            CredentialKind::Socks5Password,
            CredentialKind::WireGuardPrivateKey,
            CredentialKind::WireGuardPreSharedKey,
            CredentialKind::HttpProxyUsername,
            CredentialKind::HttpProxyPassword,
            CredentialKind::TailscaleAuthKey,
        ]
        .map(credential_kind_discriminant),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
}
