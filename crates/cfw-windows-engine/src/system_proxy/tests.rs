use super::*;

#[test]
fn public_proxy_diagnostics_have_only_native_flags_without_private_strings() {
    let settings = record().before;
    assert_eq!(
        serde_json::to_value(settings.public_observation()).unwrap(),
        serde_json::json!({
            "manual_proxy_enabled": false, "auto_config_enabled": false, "auto_detect_enabled": true,
        })
    );
    let encoded = serde_json::to_string(&settings.public_observation()).unwrap();
    assert!(!encoded.contains("private") && !encoded.contains("pac_url"));
}

pub(super) fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: uuid::Uuid::new_v4().to_string(),
        config_epoch: 1,
        generation: 1,
    }
}

pub(super) fn record() -> Record {
    let before = ProxySettings {
        flags: PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT,
        server: vec![],
        bypass: vec![0xd800],
        pac_url: "https://private.invalid/pac?key=private"
            .encode_utf16()
            .collect(),
    };
    let endpoint = "127.0.0.1:12345".parse().unwrap();
    Record {
        version: 1,
        user_sid: "S-1-5-21-123-456-789-1000".into(),
        context: context(),
        config_digest: "a".repeat(64),
        process_id: 123,
        process_created_at: 456,
        endpoint,
        applied: before.for_endpoint(endpoint),
        before,
    }
}

#[test]
fn journal_binds_user_context_process_projection_and_exact_restore_values() {
    let record = record();
    let bytes = record.encode(&record.user_sid).unwrap();
    let restored: Record = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.encode(&record.user_sid).unwrap(), bytes);
    assert_eq!(restored.before, record.before);
    assert_eq!(restored.before.bypass, [0xd800]);
    assert!(!format!("{:?}", record.before).contains("private.invalid"));
    assert!(record.encode("S-1-5-18").is_err());
    for modify in [
        |value: &mut Record| value.version = 2,
        |value: &mut Record| value.context.generation = 0,
        |value: &mut Record| value.context.config_epoch = 0,
        |value: &mut Record| value.context.installation_id.clear(),
        |value: &mut Record| value.config_digest = "A".repeat(64),
        |value: &mut Record| value.process_id = 0,
        |value: &mut Record| value.process_created_at = 0,
        |value: &mut Record| value.endpoint = "192.0.2.1:80".parse().unwrap(),
        |value: &mut Record| value.applied.server = "foreign:80".encode_utf16().collect(),
    ] {
        let mut altered = record.clone();
        modify(&mut altered);
        assert!(altered.encode(&record.user_sid).is_err());
    }
}

#[test]
fn invalid_native_options_do_not_become_empty_or_direct_defaults() {
    let valid = record().before;
    for modify in [
        |value: &mut ProxySettings| value.flags = 0,
        |value: &mut ProxySettings| value.flags = u32::MAX,
        |value: &mut ProxySettings| value.flags |= PROXY_TYPE_PROXY,
        |value: &mut ProxySettings| value.server = vec![1; MAX_STRING_UNITS + 1],
        |value: &mut ProxySettings| value.bypass = vec![0],
    ] {
        let mut altered = valid.clone();
        modify(&mut altered);
        assert!(altered.validate().is_err());
    }
}

#[tokio::test]
async fn native_authorization_and_observation_do_not_modify_proxy_settings() {
    let temporary = tempfile::tempdir().unwrap();
    let authority = WindowsSystemProxy::new(&temporary.path().join("proxy")).unwrap();
    let before = authority.snapshot().unwrap();
    assert_eq!(
        authority.inspect().unwrap(),
        ProxyOwnershipObservation::NoJournal
    );
    authority.authorize_system_proxy(true).await.unwrap();
    let admission = authority.authorize_system_proxy(false).await;
    if before.explicit_proxy_enabled() {
        assert_eq!(
            admission.unwrap_err().kind,
            BackendErrorKind::ExistingSystemProxy
        );
    } else {
        admission.unwrap();
    }
    assert_eq!(authority.snapshot().unwrap(), before);
    assert!(matches!(
        authority.restore(&context()),
        Err(ProxyError::OwnershipMissing)
    ));
    assert_eq!(authority.snapshot().unwrap(), before);
}

#[test]
fn corrupt_journal_prevents_authorization_without_changing_native_settings() {
    let temporary = tempfile::tempdir().unwrap();
    let authority = WindowsSystemProxy::new(&temporary.path().join("proxy")).unwrap();
    let before = authority.snapshot().unwrap();
    authority
        .directory
        .write()
        .unwrap()
        .replace(JOURNAL, b"{}", MAX_JOURNAL_BYTES)
        .unwrap();
    assert!(matches!(
        authority.authorize(true),
        Err(ProxyError::InvalidJournal)
    ));
    assert!(matches!(
        authority.inspect(),
        Err(ProxyError::InvalidJournal)
    ));
    assert!(matches!(
        authority.restore(&context()),
        Err(ProxyError::InvalidJournal)
    ));
    assert_eq!(authority.snapshot().unwrap(), before);
}
