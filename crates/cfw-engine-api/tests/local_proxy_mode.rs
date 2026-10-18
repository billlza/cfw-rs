use cfw_engine_api::EngineMode;

#[test]
fn disabling_both_integrations_keeps_an_explicit_local_proxy_mode() {
    let mode = EngineMode::from_switches(false, false);
    assert_eq!(serde_json::to_value(mode).unwrap(), "local_proxy");
    assert!(!mode.system_proxy_enabled());
    assert!(!mode.tunnel_enabled());
    assert_eq!(serde_json::to_value(EngineMode::Off).unwrap(), "off");
}
