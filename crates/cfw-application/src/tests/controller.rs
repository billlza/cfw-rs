use cfw_singbox_config::{
    ConfigError, DEFAULT_CLASH_API_PORT, EngineSettings, MIN_CLASH_API_PORT, ProjectionMode,
    ValidatedSingBoxProfile,
};

use crate::EngineControllerAccess;

#[test]
fn controller_access_carries_the_loopback_endpoint_of_the_projection_it_starts() {
    let access =
        EngineControllerAccess::resolve(EngineSettings::default()).expect("default controller");
    assert!(access.address().is_loopback());
    assert_eq!(access.address().to_string(), "127.0.0.1");
    assert_eq!(access.port(), DEFAULT_CLASH_API_PORT);
    assert_eq!(access.settings(), &EngineSettings::default());

    let profile = ValidatedSingBoxProfile::direct();
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(mode, access.settings())
            .expect("projection");
        assert!(access.matches_projection(&projected));
        assert!(projected.as_json().contains(&format!(
            r#""external_controller":"127.0.0.1:{}""#,
            access.port()
        )));
    }

    let endpoint = access.client_endpoint();
    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(endpoint.port, DEFAULT_CLASH_API_PORT);
    let secret = endpoint.secret.clone().expect("per-run secret");
    assert_eq!(secret.len(), 64);
    assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        endpoint.base_url().expect("loopback base URL"),
        format!("http://127.0.0.1:{DEFAULT_CLASH_API_PORT}")
    );
    assert!(!format!("{access:?}").contains(&secret));
    assert!(format!("{access:?}").contains("[REDACTED]"));
}

#[test]
fn controller_access_refuses_an_unusable_controller_port_before_any_start() {
    for port in [
        0,
        MIN_CLASH_API_PORT - 1,
        EngineSettings::default().mixed_port,
    ] {
        let settings = EngineSettings {
            controller_port: port,
            ..EngineSettings::default()
        };
        assert_eq!(
            EngineControllerAccess::resolve(settings).expect_err("bounded controller port"),
            ConfigError::InvalidControllerPort(port)
        );
    }
}
