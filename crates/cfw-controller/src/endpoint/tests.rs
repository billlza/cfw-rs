use super::*;

#[test]
fn endpoint_rejects_every_non_product_controller_address() {
    for endpoint in [
        ControllerEndpoint::new("", 9090, None),
        ControllerEndpoint::new("localhost", 9090, None),
        ControllerEndpoint::new("::1", 9090, None),
        ControllerEndpoint::new("192.0.2.1", 9090, None),
        ControllerEndpoint::new("127.0.0.1", 0, None),
    ] {
        assert!(endpoint.base_url().is_err());
        assert!(endpoint.websocket_url("/logs", &[]).is_err());
    }
}

#[test]
fn endpoint_debug_redacts_the_controller_secret() {
    let endpoint = ControllerEndpoint::new("127.0.0.1", 9090, Some("app-owned".into()));
    let rendered = format!("{endpoint:?}");
    assert!(!rendered.contains("app-owned"));
    assert!(rendered.contains("[REDACTED]"));
    assert!(format!("{:?}", ControllerEndpoint::new("127.0.0.1", 9090, None)).contains("None"));
}

#[test]
fn endpoint_builds_clash_websocket_urls() {
    let endpoint = ControllerEndpoint::new("127.0.0.1", 9090, Some("secret value".into()));
    assert_eq!(
        endpoint
            .websocket_url("logs", &[("level", "info"), ("format", "structured")])
            .unwrap(),
        "ws://127.0.0.1:9090/logs?token=secret%20value&level=info&format=structured"
    );
}

#[test]
fn endpoint_urls_carry_no_token_without_a_secret() {
    for secret in [None, Some(String::new())] {
        let endpoint = ControllerEndpoint::new("127.0.0.1", 9090, secret);
        assert_eq!(endpoint.base_url().unwrap(), "http://127.0.0.1:9090");
        assert_eq!(
            endpoint.websocket_url("/connections", &[]).unwrap(),
            "ws://127.0.0.1:9090/connections"
        );
        assert_eq!(
            endpoint
                .websocket_url("/logs", &[("level", "debug info")])
                .unwrap(),
            "ws://127.0.0.1:9090/logs?level=debug%20info"
        );
    }
}
