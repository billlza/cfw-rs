use cfw_engine_api::NativeBridgeCommand;

#[test]
fn profile_probe_policy_matches_the_native_envelope_fixture() {
    let value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../contracts/native-bridge-v10/profile-delay-request.json"
    ))
    .unwrap();
    assert_eq!(
        value["schema_version"],
        cfw_engine_api::ENGINE_PROTOCOL_VERSION
    );
    let command: NativeBridgeCommand = serde_json::from_value(value["command"].clone()).unwrap();
    assert!(matches!(
        command,
        NativeBridgeCommand::TestProfileDelays { .. }
    ));
    assert_eq!(serde_json::to_value(command).unwrap(), value["command"]);
}
