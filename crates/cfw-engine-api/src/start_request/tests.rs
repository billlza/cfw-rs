use super::*;
use crate::test_support::PROFILE_ID;

#[test]
fn engine_start_debug_redacts_the_configuration_template() {
    let request = EngineStartRequest {
        mode: cfw_singbox_config::ProjectionMode::SystemProxy,
        context: EngineCommandContext {
            installation_id: PROFILE_ID.into(),
            config_epoch: 1,
            generation: 2,
        },
        credential_audience: CredentialAudience::new(PROFILE_ID, "03".repeat(32))
            .expect("audience"),
        config_json: "never-print-this-config".into(),
        config_content_digest: "01".repeat(32),
        config_digest: "02".repeat(32),
        credential_slots: Vec::new(),
        tunnel_options: None,
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("never-print-this-config"));
    assert!(debug.contains("REDACTED CONFIG TEMPLATE"));

    let mut wire = serde_json::to_value(&request).expect("request wire");
    wire.as_object_mut()
        .expect("request object")
        .remove("credential_slots");
    assert!(serde_json::from_value::<EngineStartRequest>(wire).is_err());
}
