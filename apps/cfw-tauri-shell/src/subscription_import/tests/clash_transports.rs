//! Clash transport options, and the transport builder every format shares: an
//! option mapping needs its own network, headers agree on one Host, a path has
//! one alternative, and options a transport cannot carry are refused.

use super::*;

/// A Clash VMess node with the given transport lines.
fn clash_vmess(transport: &str) -> String {
    format!(
        "proxies:\n  - name: Node\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n    cipher: auto\n{transport}"
    )
}

fn transport_of(transport: &str) -> Value {
    let imported =
        import_subscription_document(&clash_vmess(transport)).expect("the transport imports");
    imported_outbounds(&imported)[0]["transport"].clone()
}

fn refusal(transport: &str) -> String {
    import_subscription_document(&clash_vmess(transport)).expect_err("the transport is refused")
}

#[test]
fn every_option_mapping_requires_its_own_network() {
    for (transport, message) in [
        (
            "    network: tcp\n    ws-opts:\n      path: /ws\n",
            "declares ws-opts without network: ws",
        ),
        (
            "    network: ws\n    grpc-opts:\n      grpc-service-name: api\n",
            "declares grpc-opts without network: grpc",
        ),
        (
            "    network: ws\n    h2-opts:\n      path: /h2\n",
            "declares h2-opts without network: h2",
        ),
        (
            "    network: h2\n    http-opts:\n      path: /http\n",
            "declares http-opts without network: http",
        ),
        (
            "    network: ws\n    http-upgrade-opts:\n      path: /upgrade\n",
            "declares http-upgrade-opts without network: httpupgrade",
        ),
    ] {
        let error = refusal(transport);
        assert!(error.contains(message), "{transport:?}: {error}");
    }
}

#[test]
fn a_network_without_its_option_mapping_uses_the_defaults() {
    assert_eq!(
        transport_of("    network: ws\n"),
        json!({ "type": "ws", "path": "/" })
    );
    assert_eq!(
        transport_of("    network: h2\n"),
        json!({ "type": "http", "path": "/" })
    );
    assert_eq!(
        transport_of("    network: http-upgrade\n"),
        json!({ "type": "http_upgrade", "path": "/" })
    );
    let error = refusal("    network: grpc\n");
    assert!(
        error.contains("gRPC subscriptions require a non-empty serviceName"),
        "{error}"
    );
}

#[test]
fn http_takes_its_path_and_host_from_h2_opts_when_it_has_no_http_opts() {
    assert_eq!(
        transport_of(
            "    network: http\n    h2-opts:\n      path: /h2\n      host:\n        - a.example.com\n        - b.example.com\n"
        ),
        json!({
            "type": "http",
            "path": "/h2",
            "host": ["a.example.com", "b.example.com"],
            "method": "GET",
        })
    );
    assert_eq!(
        transport_of("    network: http\n"),
        json!({ "type": "http", "path": "/", "method": "GET" })
    );
    let error = refusal(
        "    network: http\n    http-opts:\n      path: /http\n    h2-opts:\n      path: /h2\n",
    );
    assert!(
        error.contains("declares both http-opts and h2-opts for network: http"),
        "{error}"
    );
}

#[test]
fn option_mappings_without_headers_have_no_host() {
    assert_eq!(
        transport_of("    network: http\n    http-opts:\n      path: /only\n"),
        json!({ "type": "http", "path": "/only", "method": "GET" })
    );
    assert_eq!(
        transport_of("    network: ws\n    ws-opts:\n      path: /only\n"),
        json!({ "type": "ws", "path": "/only" })
    );
}

#[test]
fn headers_must_agree_on_one_host() {
    for transport in [
        "    network: http\n    http-opts:\n      headers:\n        Host: a.example.com\n        host: b.example.com\n",
        "    network: ws\n    ws-opts:\n      headers:\n        Host: a.example.com\n        host: b.example.com\n",
    ] {
        let error = refusal(transport);
        assert!(
            error.contains("declares conflicting Host header values"),
            "{transport:?}: {error}"
        );
    }
    assert_eq!(
        transport_of(
            "    network: ws\n    ws-opts:\n      path: /ws\n      headers:\n        Host: a.example.com\n        host: a.example.com\n"
        ),
        json!({ "type": "ws", "path": "/ws", "headers": { "Host": "a.example.com" } })
    );
}

#[test]
fn a_transport_path_has_exactly_one_alternative() {
    let error = refusal("    network: h2\n    h2-opts:\n      path:\n        - /a\n        - /b\n");
    assert!(
        error.contains("h2-opts.path declares multiple alternatives"),
        "{error}"
    );
    assert_eq!(
        transport_of("    network: h2\n    h2-opts:\n      path: []\n"),
        json!({ "type": "http", "path": "/" })
    );
    assert_eq!(
        transport_of("    network: h2\n    h2-opts:\n      path:\n        - /single\n"),
        json!({ "type": "http", "path": "/single" })
    );
}

#[test]
fn an_unknown_network_is_unsupported_without_echoing_it() {
    let error = refusal("    network: secret-kcp-token\n");
    assert!(
        error.contains("subscription transport is unsupported: <redacted>"),
        "{error}"
    );
    assert!(!error.contains("secret-kcp-token"), "{error}");
}

#[test]
fn the_transport_builder_refuses_options_a_transport_cannot_carry() {
    let some = |value: &str| Some(value.to_owned());
    for (kind, path, host, service, method, message) in [
        (
            "tcp",
            some("/"),
            None,
            None,
            None,
            "TCP subscription transport declares unsupported options",
        ),
        (
            "h2",
            None,
            None,
            some("api"),
            None,
            "HTTP subscription transport declares a gRPC service name",
        ),
        (
            "ws",
            None,
            None,
            some("api"),
            None,
            "WebSocket subscription transport declares unsupported service or method options",
        ),
        (
            "ws",
            None,
            None,
            None,
            some("POST"),
            "WebSocket subscription transport declares unsupported service or method options",
        ),
        (
            "grpc",
            some("/"),
            None,
            some("api"),
            None,
            "gRPC subscription transport declares HTTP path or host options",
        ),
        (
            "quic",
            None,
            some("a.example.com"),
            None,
            None,
            "QUIC subscription transport declares unsupported options",
        ),
        (
            "httpupgrade",
            None,
            None,
            None,
            some("GET"),
            "HTTPUpgrade subscription transport declares unsupported service or method options",
        ),
    ] {
        assert_eq!(
            transport_from_parts(kind, path, host, service, method),
            Err(message.to_owned()),
            "{kind}"
        );
    }
    assert_eq!(
        transport_from_parts("none", None, None, None, None),
        Ok(None)
    );
    assert_eq!(
        transport_from_parts("QUIC", None, None, None, None),
        Ok(Some(json!({ "type": "quic" })))
    );
}
