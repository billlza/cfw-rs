//! Outbound shape checks that profiles reach through one outbound each:
//! credentials, tags, TLS pins, ALPN and ECH, V2Ray transports, Hysteria2
//! bounds and WireGuard routes.

use serde_json::{Value, json};

use crate::{ConfigError, CredentialKind, ValidatedSingBoxProfile};

fn reference(id: u8, kind: &str) -> Value {
    json!({"id": format!("{id:02x}{id:02x}{id:02x}{id:02x}-0000-4000-8000-000000000000"), "kind": kind})
}

fn parse(outbound: &Value) -> Result<ValidatedSingBoxProfile, ConfigError> {
    ValidatedSingBoxProfile::parse(&json!({ "outbounds": [outbound] }).to_string())
}

#[track_caller]
fn accepted(outbound: &Value) {
    if let Err(error) = parse(outbound) {
        panic!("{outbound} was rejected: {error:?}");
    }
}

#[track_caller]
fn rejected(outbound: &Value) -> (String, String) {
    match parse(outbound) {
        Err(ConfigError::UnsupportedPolicyShape { path, reason }) => (path, reason),
        Err(other) => panic!("{outbound}: unexpected error {other:?}"),
        Ok(_) => panic!("{outbound} was accepted"),
    }
}

#[track_caller]
fn reason(outbound: &Value) -> String {
    rejected(outbound).1
}

#[track_caller]
fn kind_mismatch(outbound: &Value) -> (String, CredentialKind) {
    match parse(outbound) {
        Err(ConfigError::CredentialKindMismatch { path, expected, .. }) => (path, expected),
        Err(other) => panic!("{outbound}: unexpected error {other:?}"),
        Ok(_) => panic!("{outbound} was accepted"),
    }
}

fn http_proxy() -> Value {
    json!({"type":"http","tag":"http","server":"proxy.example.com","server_port":8080,
        "authentication":{"username_credential_ref":reference(1, "http_proxy_username"),
                          "password_credential_ref":reference(2, "http_proxy_password")}})
}

fn trojan() -> Value {
    json!({"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,
        "credential_ref":reference(3, "trojan_password"),
        "tls":{"enabled":true,"server_name":"trojan.example.com"}})
}

fn hysteria2() -> Value {
    json!({"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,
        "credential_ref":reference(4, "hysteria2_password"),
        "tls":{"enabled":true,"server_name":"hy2.example.com"}})
}

fn wireguard() -> Value {
    json!({"type":"wireguard","tag":"wg","server":"vpn.example.com","server_port":51820,
        "local_addresses":["10.10.0.2/32","fd00::2/128"],"mtu":1420,"persistent_keepalive_seconds":25,
        "peer_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "private_key_credential_ref":reference(5, "wireguard_private_key")})
}

fn tuic() -> Value {
    json!({"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,
        "uuid_credential_ref":reference(6, "tuic_uuid"),
        "password_credential_ref":reference(7, "tuic_password"),
        "tls":{"enabled":true,"server_name":"tuic.example.com","alpn":["h3"]},
        "congestion_control":"bbr","udp_relay_mode":"quic"})
}

fn with(mut value: Value, pointer: &str, field: Value) -> Value {
    *value.pointer_mut(pointer).expect("fixture field") = field;
    value
}

fn set(mut value: Value, key: &str, field: Value) -> Value {
    value[key] = field;
    value
}

fn trojan_tls(key: &str, field: Value) -> Value {
    let mut outbound = trojan();
    outbound["tls"][key] = field;
    outbound
}

#[test]
fn http_proxy_credentials_have_their_own_kinds() {
    accepted(&http_proxy());
    let mut username_only = http_proxy();
    username_only["authentication"]
        .as_object_mut()
        .unwrap()
        .remove("password_credential_ref");
    accepted(&username_only);
    assert_eq!(
        kind_mismatch(&with(
            http_proxy(),
            "/authentication/username_credential_ref",
            reference(1, "socks5_username")
        )),
        (
            "$.outbounds[0].authentication.username_credential_ref".to_owned(),
            CredentialKind::HttpProxyUsername
        )
    );
    assert_eq!(
        kind_mismatch(&with(
            http_proxy(),
            "/authentication/password_credential_ref",
            reference(2, "socks5_password")
        )),
        (
            "$.outbounds[0].authentication.password_credential_ref".to_owned(),
            CredentialKind::HttpProxyPassword
        )
    );
}

#[test]
fn secondary_credentials_are_checked_by_kind() {
    assert_eq!(
        kind_mismatch(&set(
            wireguard(),
            "pre_shared_key_credential_ref",
            reference(8, "wireguard_private_key")
        ))
        .1,
        CredentialKind::WireGuardPreSharedKey
    );
    assert_eq!(
        kind_mismatch(&with(
            tuic(),
            "/password_credential_ref",
            reference(7, "tuic_uuid")
        ))
        .1,
        CredentialKind::TuicPassword
    );
    let mut obfuscated = hysteria2();
    obfuscated["obfs"] =
        json!({"type":"salamander","credential_ref":reference(9, "hysteria2_password")});
    assert_eq!(
        kind_mismatch(&obfuscated).1,
        CredentialKind::Hysteria2ObfsPassword
    );
}

#[test]
fn tags_are_bounded_unpadded_and_printable() {
    for tag in ["", " padded", "line\nbreak", &"t".repeat(129)] {
        assert_eq!(
            rejected(&with(trojan(), "/tag", json!(tag))),
            (
                "$.outbounds[0].tag".to_owned(),
                "tag is empty, too long, padded, or contains unsafe characters".to_owned()
            ),
            "{tag:?}"
        );
    }
    accepted(&with(trojan(), "/tag", json!("t".repeat(128))));
}

#[test]
fn tls_pins_are_up_to_eight_distinct_canonical_sha256_values() {
    let pin =
        |byte: u8| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [byte; 32]);
    let pins = |count: u8| (0..count).map(pin).collect::<Vec<_>>();
    accepted(&trojan_tls("certificate_sha256", json!(pins(8))));
    accepted(&trojan_tls("certificate_public_key_sha256", json!(pins(1))));
    let message = "TLS pins must be one to eight distinct SHA256 values in canonical base64";
    for invalid in [
        json!(pins(9)),
        json!([pin(1), pin(1)]),
        json!(["AAAA"]),
        json!([pin(1).trim_end_matches('=')]),
    ] {
        assert_eq!(
            reason(&trojan_tls("certificate_sha256", invalid.clone())),
            message,
            "{invalid}"
        );
    }
}

#[test]
fn alpn_lists_are_short_lists_of_printable_tokens() {
    accepted(&trojan_tls("alpn", json!(["h2", "http/1.1"])));
    let message = "ALPN list is oversized or contains an invalid token";
    for invalid in [
        json!(vec!["h2"; 9]),
        json!([""]),
        json!(["h 2"]),
        json!(["a".repeat(33)]),
    ] {
        assert_eq!(
            rejected(&trojan_tls("alpn", invalid.clone())),
            ("$.outbounds[0].tls.alpn".to_owned(), message.to_owned()),
            "{invalid}"
        );
    }
}

fn ech(lines: Value) -> Value {
    let mut outbound = trojan();
    outbound["tls"]["min_version"] = json!("1.3");
    outbound["tls"]["ech"] = json!({"enabled": true, "config": lines});
    outbound
}

#[test]
fn ech_requires_an_inline_bounded_well_formed_config_list() {
    // A two-byte length prefix and a four-byte list.
    let valid = [
        "-----BEGIN ECH CONFIGS-----",
        "AAT+DQAA",
        "-----END ECH CONFIGS-----",
    ];
    accepted(&ech(json!(valid)));

    let pem = |payload: &str| {
        json!([
            "-----BEGIN ECH CONFIGS-----",
            payload,
            "-----END ECH CONFIGS-----"
        ])
    };
    for (lines, message) in [
        (
            json!(["AAT+DQAA"]),
            "ECH requires an inline ECH CONFIGS PEM block",
        ),
        (pem("not base64!"), "ECH config contains invalid base64"),
        (pem("AAU+DQAA"), "ECHConfigList length is invalid"),
        (pem("AAH+"), "ECHConfigList length is invalid"),
    ] {
        assert_eq!(reason(&ech(lines.clone())), message, "{lines}");
    }
    let mut long = vec!["AAT+DQAA"; 255];
    long.insert(0, "-----BEGIN ECH CONFIGS-----");
    long.push("-----END ECH CONFIGS-----");
    assert_eq!(
        reason(&ech(json!(long))),
        "ECH config exceeds its size bound"
    );

    let requirement = "ECH must be enabled with TLS 1.3 and cannot be combined with Reality";
    let mut disabled = ech(json!(valid));
    disabled["tls"]["ech"]["enabled"] = json!(false);
    assert_eq!(reason(&disabled), requirement);
    let mut tls12 = ech(json!(valid));
    tls12["tls"]["min_version"] = json!("1.2");
    assert_eq!(reason(&tls12), requirement);
}

#[test]
fn protocols_that_need_tls_refuse_it_disabled() {
    let mut plain = trojan();
    plain["tls"] = json!({"enabled": false, "server_name": "trojan.example.com"});
    assert_eq!(
        rejected(&plain),
        (
            "$.outbounds[0].tls.enabled".to_owned(),
            "this protocol requires enabled TLS".to_owned()
        )
    );
}

fn transport(transport: Value) -> Value {
    let mut outbound = trojan();
    outbound["transport"] = transport;
    outbound
}

#[test]
fn http_transports_bound_their_path_and_host_list() {
    accepted(&transport(
        json!({"type":"http","path":"/tunnel","host":["cdn.example.com","[2606:4700::1111]:8443"]}),
    ));
    accepted(&transport(json!({"type":"http"})));
    assert_eq!(
        rejected(&transport(json!({"type":"http","path":"relative"}))),
        (
            "$.outbounds[0].transport.path".to_owned(),
            "V2Ray transport path must be a bounded absolute path".to_owned()
        )
    );
    assert_eq!(
        rejected(&transport(
            json!({"type":"http","host":vec!["cdn.example.com"; 17]})
        )),
        (
            "$.outbounds[0].transport.host".to_owned(),
            "HTTP transport accepts at most 16 host authorities".to_owned()
        )
    );
    assert_eq!(
        rejected(&transport(
            json!({"type":"http","host":["ok.example.com","bad host"]})
        ))
        .0,
        "$.outbounds[0].transport.host[1]"
    );
}

#[test]
fn grpc_and_http_upgrade_transports_bound_their_names() {
    accepted(&transport(json!({"type":"grpc","service_name":"tunnel"})));
    accepted(&transport(
        json!({"type":"grpc","service_name":"a service"}),
    ));
    let long = "s".repeat(257);
    for name in ["", "line\nbreak", long.as_str()] {
        assert_eq!(
            rejected(&transport(json!({"type":"grpc","service_name":name}))),
            (
                "$.outbounds[0].transport.service_name".to_owned(),
                "gRPC service_name is invalid".to_owned()
            ),
            "{name:?}"
        );
    }
    accepted(&transport(
        json!({"type":"http_upgrade","path":"/upgrade","host":"cdn.example.com:8443"}),
    ));
    accepted(&transport(json!({"type":"http_upgrade"})));
    assert_eq!(
        rejected(&transport(
            json!({"type":"http_upgrade","path":"/upgrade","host":"cdn.example.com:0"})
        ))
        .0,
        "$.outbounds[0].transport.host"
    );
    assert_eq!(
        rejected(&transport(json!({"type":"http_upgrade","path":"upgrade"}))).0,
        "$.outbounds[0].transport.path"
    );
}

#[test]
fn host_authorities_are_names_or_addresses_with_an_optional_nonzero_port() {
    let message =
        "WebSocket Host must be a bounded DNS name or IP address with an optional nonzero port";
    let upgrade =
        |host: &str| transport(json!({"type":"http_upgrade","path":"/upgrade","host":host}));
    for host in [
        "cdn.example.com",
        "cdn.example.com:443",
        "[2606:4700::1111]",
        "[2606:4700::1111]:443",
        "1.1.1.1:80",
        "2606:4700::1111",
    ] {
        accepted(&upgrade(host));
    }
    for host in [
        "",
        " cdn.example.com",
        "cdn.example.com/path",
        "user@cdn.example.com",
        "[2606:4700::1111",
        "[2606:4700::1111]443",
        "[not-v6]:443",
        "cdn.example.com:http",
        "cdn.example.com:0",
    ] {
        assert_eq!(reason(&upgrade(host)), message, "{host:?}");
    }
}

#[test]
fn hysteria2_port_lists_and_bandwidth_are_bounded() {
    let ports = |ports: Value| {
        let mut outbound = hysteria2();
        outbound["server_ports"] = ports;
        outbound["hop_interval_seconds"] = json!(30);
        outbound
    };
    let items = "server_ports must contain between 1 and 64 canonical items";
    assert_eq!(
        rejected(&ports(json!([]))),
        ("$.outbounds[0].server_ports".to_owned(), items.to_owned())
    );
    let many = (1_000..1_065)
        .map(|port| port.to_string())
        .collect::<Vec<_>>();
    assert_eq!(reason(&ports(json!(many))), items);
    accepted(&ports(json!(many[..64])));
    for port in ["0", "0443", "abc"] {
        assert_eq!(
            rejected(&ports(json!(["443", port]))),
            (
                "$.outbounds[0].server_ports[1]".to_owned(),
                "port must be a canonical nonzero decimal integer".to_owned()
            ),
            "{port}"
        );
    }
    for (field, value) in [("up_mbps", 0), ("down_mbps", 1_000_001)] {
        let mut outbound = hysteria2();
        outbound[field] = json!(value);
        assert_eq!(
            rejected(&outbound),
            (
                format!("$.outbounds[0].{field}"),
                "bandwidth must be between 1 and 1000000 Mbps".to_owned()
            )
        );
    }
    let mut fastest = hysteria2();
    fastest["up_mbps"] = json!(1_000_000);
    fastest["down_mbps"] = json!(1);
    accepted(&fastest);
}

#[test]
fn wireguard_peers_route_each_default_prefix_at_most_once() {
    accepted(&wireguard());
    accepted(&set(wireguard(), "peer_allowed_ips", json!(["::/0"])));
    for routes in [
        json!([]),
        json!(["0.0.0.0/0", "::/0", "0.0.0.0/0"]),
        json!(["10.0.0.0/8"]),
        json!(["0.0.0.0/0", "0.0.0.0/0"]),
    ] {
        assert_eq!(
            reason(&set(wireguard(), "peer_allowed_ips", routes.clone())),
            "WireGuard peer requires unique IPv4 and/or IPv6 default routes",
            "{routes}"
        );
    }
}
