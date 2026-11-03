use std::fs;

use super::store::JournalAdvanceError;
use super::*;
use cfw_engine_api::{DirectIpv4HostRoutes, EngineStartRequest, TunnelNetworkOptions};

pub(super) fn request() -> CutoverPreflightRequest {
    request_with(9, "11".repeat(32), "22".repeat(32))
}

fn request_with(
    generation: u64,
    system_proxy_digest: String,
    tunnel_digest: String,
) -> CutoverPreflightRequest {
    let context = EngineCommandContext {
        installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
        config_epoch: 1,
        generation,
    };
    let credential_audience = cfw_engine_api::CredentialAudience::new(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
    )
    .expect("audience");
    let proxy = EngineStartRequest {
        mode: cfw_singbox_config::ProjectionMode::SystemProxy,
        context: context.clone(),
        credential_audience: credential_audience.clone(),
        config_json: "{}".into(),
        config_content_digest: "10".repeat(32),
        config_digest: system_proxy_digest,
        credential_slots: Vec::new(),
        tunnel_options: None,
    };
    let tunnel = EngineStartRequest {
        mode: cfw_singbox_config::ProjectionMode::Tunnel,
        context,
        credential_audience,
        config_json: "{}".into(),
        config_content_digest: "20".repeat(32),
        config_digest: tunnel_digest,
        credential_slots: Vec::new(),
        tunnel_options: Some(TunnelNetworkOptions {
            ipv6_enabled: true,
            bypass_private_networks: true,
            direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
            mtu: 1500,
            system_proxy_port: None,
        }),
    };
    CutoverPreflightRequest::new(EngineMode::Tunnel, proxy, tunnel).expect("request")
}

#[test]
fn phase_journal_is_canonical_durable_and_monotonic() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    assert_eq!(store.load().expect("load").expect("journal"), journal);
    assert!(
        store.write_prepared(&journal).is_err(),
        "even an existing Prepared journal cannot be overwritten"
    );
    assert_eq!(
        store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .expect("advance")
            .phase,
        CutoverPhase::NetworkRetiring
    );
    assert!(
        store
            .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
            .is_err()
    );
    store
        .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
        .expect("legacy retired");
}

#[test]
fn replacement_settings_are_source_bound_and_survive_journal_round_trip() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let settings = EngineSettings {
        mixed_port: 7891,
        controller_port: 9091,
        ..EngineSettings::default()
    };
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        settings.clone(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    let loaded = store.load().expect("load").expect("journal");
    assert_eq!(loaded.replacement_settings, settings);
    assert!(loaded.matches_recovery_projection(
        &loaded.profile_id,
        &loaded.profile_digest,
        &request(),
        &settings,
    ));
    let different = EngineSettings {
        mixed_port: 7892,
        ..settings
    };
    assert!(!loaded.matches_recovery_projection(
        &loaded.profile_id,
        &loaded.profile_digest,
        &request(),
        &different,
    ));
}

#[test]
fn replacement_settings_validation_rejects_unusable_persisted_endpoints() {
    let mut journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    journal.replacement_settings.controller_port = journal.replacement_settings.mixed_port;
    assert!(journal.validate().is_err());
}

#[test]
fn endpoint_rebind_atomically_updates_every_projection_binding() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let original_request = request();
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &original_request,
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    let expected = store
        .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
        .expect("network retiring");

    let replacement_settings = EngineSettings {
        mixed_port: expected.replacement_settings.mixed_port + 1,
        ..expected.replacement_settings.clone()
    };
    let replacement_request = request_with(10, "44".repeat(32), "55".repeat(32));
    let rebound = store
        .rebind_endpoint_request(&expected, &replacement_request, &replacement_settings)
        .expect("atomic endpoint rebind");
    assert_eq!(
        rebound.context,
        replacement_request.system_proxy_request().context
    );
    assert_eq!(
        rebound.system_proxy_digest,
        replacement_request.system_proxy_request().config_digest
    );
    assert_eq!(
        rebound.tunnel_digest,
        replacement_request.tunnel_request().config_digest
    );
    assert_eq!(rebound.replacement_settings, replacement_settings);
    assert_eq!(store.load().expect("load").expect("journal"), rebound);
    assert!(
        store
            .rebind_endpoint_request(
                &expected,
                &request_with(11, "66".repeat(32), "77".repeat(32)),
                &EngineSettings {
                    mixed_port: replacement_settings.mixed_port + 1,
                    ..replacement_settings
                },
            )
            .is_err(),
        "a stale journal CAS cannot overwrite the committed binding"
    );
}

#[test]
fn endpoint_rebind_directory_fsync_failure_preserves_exact_recovery_binding() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    let expected = store
        .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
        .expect("network retiring");
    let replacement_settings = EngineSettings {
        mixed_port: expected.replacement_settings.mixed_port + 1,
        controller_port: expected.replacement_settings.controller_port + 1,
        ..expected.replacement_settings.clone()
    };
    let replacement_request = request_with(10, "44".repeat(32), "55".repeat(32));

    let failure = store
        .rebind_endpoint_request_with_directory_sync(
            &expected,
            &replacement_request,
            &replacement_settings,
            |_| {
                Err(std::io::Error::other(
                    "injected endpoint directory fsync failure",
                ))
            },
        )
        .expect_err("directory fsync must remain commit-uncertain");
    assert!(failure.commit_is_uncertain());
    let intended = match failure {
        JournalAdvanceError::CommitUncertain(state) => {
            assert_eq!(
                state.intended.context,
                replacement_request.system_proxy_request().context
            );
            assert_eq!(
                state.intended.system_proxy_digest,
                replacement_request.system_proxy_request().config_digest
            );
            assert_eq!(
                state.intended.tunnel_digest,
                replacement_request.tunnel_request().config_digest
            );
            assert_eq!(state.intended.replacement_settings, replacement_settings);
            assert_eq!(state.persisted, Ok(Some(state.intended.clone())));
            assert!(
                state
                    .detail
                    .contains("injected endpoint directory fsync failure")
            );
            state.intended
        }
        other => panic!("unexpected fault classification: {other:?}"),
    };

    let reopened = CutoverJournalStore::new(root.path());
    assert_eq!(
        reopened.load().expect("reopen journal"),
        Some(intended),
        "restart recovery must observe the exact rebound projection"
    );
}

#[test]
fn endpoint_rebind_rejects_non_endpoint_drift_and_replacement_active() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    let network_retiring = store
        .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
        .expect("network retiring");
    let drifted = EngineSettings {
        mixed_port: network_retiring.replacement_settings.mixed_port + 1,
        enable_ipv6: !network_retiring.replacement_settings.enable_ipv6,
        ..network_retiring.replacement_settings.clone()
    };
    assert!(
        store
            .rebind_endpoint_request(
                &network_retiring,
                &request_with(10, "44".repeat(32), "55".repeat(32)),
                &drifted,
            )
            .is_err(),
        "endpoint recovery cannot change non-endpoint settings"
    );

    let legacy_retired = store
        .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
        .expect("legacy retired");
    let replacement_active = store
        .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
        .expect("replacement active");
    assert!(
        store
            .rebind_endpoint_request(
                &replacement_active,
                &request_with(10, "44".repeat(32), "55".repeat(32)),
                &EngineSettings {
                    controller_port: legacy_retired.replacement_settings.controller_port + 1,
                    ..legacy_retired.replacement_settings
                },
            )
            .is_err(),
        "ReplacementActive is immutable"
    );
}

#[test]
fn recovery_rebind_rotates_context_digests_but_not_replacement_active() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    store
        .advance(CutoverPhase::Prepared, CutoverPhase::NetworkRetiring)
        .expect("network retiring");

    let rotated = request_with(9, "44".repeat(32), "55".repeat(32));
    let rebound = store
        .rebind_recovery_request(
            CutoverPhase::NetworkRetiring,
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            &"33".repeat(32),
            &rotated,
            &EngineSettings::default(),
        )
        .expect("same-generation unused recovery projection can rotate process-bound digests");
    assert_eq!(rebound.context, rotated.system_proxy_request().context);
    assert_eq!(
        rebound.system_proxy_digest,
        rotated.system_proxy_request().config_digest
    );
    assert_eq!(
        rebound.tunnel_digest,
        rotated.tunnel_request().config_digest
    );

    store
        .advance(CutoverPhase::NetworkRetiring, CutoverPhase::LegacyRetired)
        .expect("legacy retired");
    store
        .advance(CutoverPhase::LegacyRetired, CutoverPhase::ReplacementActive)
        .expect("replacement active");
    assert!(
        store
            .rebind_recovery_request(
                CutoverPhase::ReplacementActive,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &"33".repeat(32),
                &request_with(10, "66".repeat(32), "77".repeat(32)),
                &EngineSettings::default(),
            )
            .is_err()
    );
}

#[test]
fn post_rename_directory_fsync_failure_is_bound_and_commit_uncertain() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");

    let failure = store
        .advance_with_directory_sync(
            CutoverPhase::Prepared,
            CutoverPhase::NetworkRetiring,
            |_| Err(std::io::Error::other("injected directory fsync failure")),
        )
        .expect_err("directory fsync must remain commit-uncertain");
    assert!(failure.commit_is_uncertain());
    match failure {
        JournalAdvanceError::CommitUncertain(state) => {
            assert_eq!(state.intended.phase, CutoverPhase::NetworkRetiring);
            assert_eq!(state.persisted, Ok(Some(state.intended.clone())));
            assert!(state.detail.contains("injected directory fsync failure"));
        }
        other => panic!("unexpected fault classification: {other:?}"),
    }
    assert_eq!(
        store.load().expect("load").expect("journal").phase,
        CutoverPhase::NetworkRetiring,
        "the lock-bound reread exposes the sealed phase for idempotent recovery"
    );
}

#[test]
fn pre_network_crash_states_converge_to_one_way_recovery_without_gui_relaunch() {
    for phase in [CutoverPhase::Prepared, CutoverPhase::GuiStopped] {
        let root = tempfile::tempdir().expect("temp");
        let store = CutoverJournalStore::new(root.path());
        let journal = CutoverJournal::prepared(
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "33".repeat(32),
            &request(),
            EngineSettings::default(),
            LegacyRuntimePlanKind::FreshInstall,
            LegacyNetworkJournalInput::default(),
            None,
        )
        .expect("journal");
        store.write_prepared(&journal).expect("write prepared");
        if phase == CutoverPhase::GuiStopped {
            store
                .advance(CutoverPhase::Prepared, CutoverPhase::GuiStopped)
                .expect("materialize old-schema GUI phase");
        }
        assert_eq!(
            store
                .advance(phase, CutoverPhase::NetworkRetiring)
                .expect("seal retry")
                .phase,
            CutoverPhase::NetworkRetiring
        );
    }
}

#[test]
fn malformed_or_writable_journal_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temp");
    let path = root.path().join(JOURNAL_FILE);
    fs::write(&path, b"{}").expect("write malformed");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
    assert!(CutoverJournalStore::new(root.path()).load().is_err());
}

#[test]
fn a_stored_journal_that_is_not_canonical_or_not_valid_fails_closed() {
    let root = tempfile::tempdir().expect("temp");
    let store = CutoverJournalStore::new(root.path());
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("journal");
    store.write_prepared(&journal).expect("write prepared");
    let path = root.path().join(JOURNAL_FILE);

    // The same journal, pretty-printed: it parses, but it is not the
    // encoding the store writes.
    fs::write(&path, serde_json::to_vec_pretty(&journal).expect("encode")).expect("rewrite");
    assert_eq!(
        store.load().expect_err("non-canonical journal"),
        "legacy cutover journal is not canonical JSON"
    );

    // A compact encoding of a journal whose identity is invalid.
    let mut invalid = journal.clone();
    invalid.schema_version = SCHEMA_VERSION - 1;
    fs::write(&path, serde_json::to_vec(&invalid).expect("encode")).expect("rewrite");
    assert_eq!(
        store.load().expect_err("invalid journal"),
        "legacy cutover journal identity is invalid"
    );

    fs::write(&path, serde_json::to_vec(&journal).expect("encode")).expect("restore");
    assert_eq!(store.load().expect("load").expect("journal"), journal);
}

#[test]
fn fresh_install_journal_has_no_invented_legacy_gui_identity() {
    let journal = CutoverJournal::prepared(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "33".repeat(32),
        &request(),
        EngineSettings::default(),
        LegacyRuntimePlanKind::FreshInstall,
        LegacyNetworkJournalInput::default(),
        None,
    )
    .expect("fresh journal");
    assert!(journal.legacy_gui.is_none());

    let mut inconsistent = journal;
    inconsistent.legacy_tunnel = Some(LegacyNetworkJournalIdentity {
        interface: "utun7".into(),
        route_digest: "11".repeat(32),
        route_count: 1,
        scoped_dns_resolvers: 0,
    });
    assert!(inconsistent.validate().is_err());
}
