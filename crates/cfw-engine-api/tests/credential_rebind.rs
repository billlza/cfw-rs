use cfw_engine_api::{
    CredentialRebindRequest, EngineSettings, NativeBridgeCommand, ValidatedSingBoxProfile,
};
use serde_json::json;
const ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

#[test]
fn shared_native_rebind_fixture_uses_the_exact_closed_command_shape() {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/native-bridge-v10/credential-rebind-request.json"
    ))
    .unwrap();
    assert_eq!(
        value["schema_version"],
        cfw_engine_api::ENGINE_PROTOCOL_VERSION
    );
    let command: NativeBridgeCommand = serde_json::from_value(value["command"].clone()).unwrap();
    assert!(matches!(
        command,
        NativeBridgeCommand::RebindProfileCredentials { .. }
    ));
    assert_eq!(serde_json::to_value(command).unwrap(), value["command"]);
}

fn source() -> serde_json::Value {
    json!({"outbounds":[{"type":"trojan","tag":"proxy","server":"node.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"node.example.com"}},{"type":"direct","tag":"direct"}],"route":{"final":"proxy"}})
}

#[test]
fn routing_edits_rebind_an_unchanged_node_and_reject_changed_secret_destinations() {
    let original = source();
    let previous = ValidatedSingBoxProfile::parse(&original.to_string()).unwrap();
    let mut changed = original.clone();
    changed["route"]["rules"] =
        json!([{"type":"domain","value":"internal.example.com","outbound":"direct"}]);
    let candidate = ValidatedSingBoxProfile::parse(&changed.to_string()).unwrap();
    let request =
        CredentialRebindRequest::new(ID, &previous, &candidate, &EngineSettings::default())
            .unwrap();
    let wire =
        serde_json::to_value(NativeBridgeCommand::RebindProfileCredentials { request }).unwrap();
    let decoded: NativeBridgeCommand = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
    assert_eq!(
        wire["payload"]["request"]["audience"]["profile_digest"],
        candidate.digest()
    );
    changed["outbounds"][0]["server"] = json!("changed.example.com");
    let redirected = ValidatedSingBoxProfile::parse(&changed.to_string()).unwrap();
    assert!(
        CredentialRebindRequest::new(ID, &previous, &redirected, &EngineSettings::default())
            .is_err()
    );
    let mut crossed = wire;
    crossed["payload"]["request"]["audience"]["profile_id"] =
        json!("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    assert!(serde_json::from_value::<NativeBridgeCommand>(crossed).is_err());
}
