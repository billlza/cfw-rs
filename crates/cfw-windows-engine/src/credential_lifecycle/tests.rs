use super::{
    CredentialLifecycleError as Error,
    record::{self, Record},
};
use crate::{
    CheckedStartConfiguration,
    authority::AuthoritySnapshot,
    authority_journal::{JournalOperation, RecordedOwner},
};
use cfw_engine_api::{
    EngineCommandContext, EngineStartRequest,
    authority_v1::{AuthorityMode, AuthorityState},
};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use uuid::Uuid;

fn request() -> EngineStartRequest {
    let profile = ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#).unwrap();
    let p = profile
        .project(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .unwrap();
    EngineStartRequest {
        context: EngineCommandContext {
            installation_id: Uuid::from_u128(1).to_string(),
            config_epoch: 1,
            generation: 2,
        },
        mode: ProjectionMode::SystemProxy,
        credential_audience: p.credential_audience().clone(),
        config_json: p.as_json().into(),
        config_content_digest: p.configuration_digest().into(),
        config_digest: p.digest().into(),
        credential_slots: p.credential_slots().to_vec(),
        tunnel_options: None,
    }
}
fn record() -> Record {
    Record::new(
        &CheckedStartConfiguration::new(request()).unwrap(),
        Uuid::from_u128(2),
    )
    .unwrap()
}
fn owner() -> RecordedOwner {
    serde_json::from_value(
        serde_json::json!({"sid":[1,1,0,0,0,0,0,5,21,0,0,0],"authentication_id":91,"session_id":2}),
    )
    .unwrap()
}
fn operation(value: &Record) -> JournalOperation {
    JournalOperation::new(
        value.operation_id(),
        value.mode(),
        value.content_digest().unwrap(),
        value.identity_digest().unwrap(),
        Uuid::from_u128(3),
        owner(),
    )
    .unwrap()
}
fn snapshot(state: AuthorityState) -> AuthoritySnapshot {
    AuthoritySnapshot {
        state,
        revision: Some(5),
        root: Some(record().root().clone()),
    }
}

#[test]
fn persisted_binding_roundtrip_omits_template_controller_and_material() {
    let request = request();
    let template: serde_json::Value = serde_json::from_str(&request.config_json).unwrap();
    let controller = template["experimental"]["clash_api"]["secret"]
        .as_str()
        .unwrap();
    let value = Record::new(
        &CheckedStartConfiguration::new(request.clone()).unwrap(),
        Uuid::from_u128(2),
    )
    .unwrap();
    let bytes = value.encode().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains(controller));
    assert!(
        !text.contains("config_json")
            && !text.contains("secret")
            && !text.contains("proxy.example.com")
    );
    let decoded = Record::decode(&bytes).unwrap();
    let bindings = record::protected(
        &snapshot(AuthorityState::Active),
        Some(&operation(&decoded)),
        Some(&decoded),
    )
    .unwrap();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].audience(), &request.credential_audience);
    assert_eq!(
        bindings[0].reference(),
        request.credential_slots[0].reference()
    );
}

#[test]
fn preparing_active_stopping_and_recovery_keep_the_exact_old_audience() {
    let value = record();
    let operation = operation(&value);
    for phase in [
        AuthorityState::Preparing,
        AuthorityState::Starting,
        AuthorityState::Active,
        AuthorityState::Stopping,
        AuthorityState::Recovering,
        AuthorityState::Quarantined,
    ] {
        let protected =
            record::protected(&snapshot(phase), Some(&operation), Some(&value)).unwrap();
        assert_eq!(protected.len(), 1);
        assert_eq!(protected[0].audience(), &request().credential_audience);
    }
    assert!(
        record::protected(&snapshot(AuthorityState::Off), None, Some(&value))
            .unwrap()
            .is_empty()
    );
    assert!(
        record::protected(&snapshot(AuthorityState::Off), None, None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn unavailable_recovery_and_missing_bindings_never_become_an_empty_scope() {
    let value = record();
    let operation = operation(&value);
    for phase in [
        AuthorityState::Active,
        AuthorityState::Preparing,
        AuthorityState::Recovering,
        AuthorityState::Quarantined,
    ] {
        assert!(matches!(
            record::protected(&snapshot(phase), None, Some(&value)),
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            record::protected(&snapshot(phase), Some(&operation), None),
            Err(Error::Unavailable)
        ));
    }
    assert!(matches!(
        record::protected(
            &snapshot(AuthorityState::Off),
            Some(&operation),
            Some(&value)
        ),
        Err(Error::Identity)
    ));
    let mut unknown = snapshot(AuthorityState::Recovering);
    unknown.revision = None;
    assert!(matches!(
        record::protected(&unknown, Some(&operation), Some(&value)),
        Err(Error::Unavailable)
    ));
}

#[test]
fn a_replaced_record_cannot_protect_a_different_operation_or_digest() {
    let value = record();
    let original = operation(&value);
    let mut root = snapshot(AuthorityState::Active);
    root.root.as_mut().unwrap().generation += 1;
    assert!(matches!(
        record::protected(&root, Some(&original), Some(&value)),
        Err(Error::Identity)
    ));
    for change in 0..4 {
        let altered = JournalOperation::new(
            if change == 0 {
                Uuid::from_u128(5)
            } else {
                original.operation_id()
            },
            if change == 1 {
                AuthorityMode::LocalProxy
            } else {
                original.mode()
            },
            if change == 2 {
                [6; 32]
            } else {
                *original.config_sha256()
            },
            if change == 3 {
                [7; 32]
            } else {
                *original.identity_sha256()
            },
            original.lease_id(),
            owner(),
        )
        .unwrap();
        assert!(matches!(
            record::protected(
                &snapshot(AuthorityState::Active),
                Some(&altered),
                Some(&value)
            ),
            Err(Error::Identity)
        ));
    }
}

#[test]
fn binding_record_rejects_omissions_noncanonical_bytes_and_identity_tampering() {
    let bytes = record().encode().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in [
        "network_options",
        "slots",
        "audience",
        "identity_sha256",
        "configuration_sha256",
        "operation_id",
        "root",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(Record::decode(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    let mut spaced = bytes.clone();
    spaced.push(b' ');
    assert!(Record::decode(&spaced).is_err());
    let mut tampered = value.clone();
    tampered["slots"] = serde_json::json!([]);
    let tampered: Record = serde_json::from_value(tampered).unwrap();
    assert!(matches!(tampered.encode(), Err(Error::Identity)));
    let mut schema = value;
    schema["schema_version"] = serde_json::json!(2);
    let schema: Record = serde_json::from_value(schema).unwrap();
    assert!(matches!(schema.encode(), Err(Error::Schema)));
    assert!(Record::decode(&vec![b' '; record::MAX_BYTES + 1]).is_err());
}
