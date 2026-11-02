//! Clash and Mihomo nodes: every supported type, transports, HTTP options,
//! Reality, WireGuard, conversion failures, and certificate pins.

use super::*;

#[test]
fn empty_clash_routing_rules_remain_explicit_errors() {
    for scalar in ["", "~", "''", "!!str"] {
        let document = format!(
            "proxies:\n  - {{name: Node, type: socks5, server: node.example.com, port: 1080}}\nrules:\n  - {scalar}\n"
        );
        let error = import_subscription_document(&document).expect_err("empty routing rule");
        assert!(
            error.contains("rules[0] has an unsupported rule shape"),
            "{error}"
        );
    }
}

#[test]
fn imports_clash_h2_httpupgrade_and_quic_transport_matrix() {
    let document = r#"
proxies:
  - name: H2
    type: vless
    server: v.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    network: h2
    h2-opts:
      path: /h2
      host: [one.example, two.example]
  - name: Upgrade
    type: trojan
    server: t.example
    port: 443
    password: TopSecretValue!
    network: httpupgrade
    http-upgrade-opts:
      path: /up
      host: edge.example
  - name: QUIC
    type: vmess
    server: q.example
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    alterId: 0
    network: quic
    tls: true
    servername: q.example
"#;
    let imported = import_subscription_document(document).expect("Clash transport matrix");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical Clash transports");
    assert_eq!(profile["outbounds"][0]["transport"]["type"], "http");
    assert_eq!(profile["outbounds"][1]["transport"]["type"], "http_upgrade");
    assert_eq!(profile["outbounds"][2]["transport"]["type"], "quic");
    assert!(!imported.profile.as_json().contains("TopSecretValue!"));
}

#[test]
fn imports_mihomo_vmess_http_options_and_closed_framing_flags() {
    let document = r#"
proxies:
  - name: HTTP
    type: vmess
    server: vm.example
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    global-padding: false
    authenticated-length: false
    network: http
    http-opts:
      method: GET
      path: [/tunnel]
      headers:
        Host: [edge.example]
"#;
    let imported = import_subscription_document(document).expect("Mihomo VMess HTTP options");
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical Mihomo profile");
    let transport = &profile["outbounds"][0]["transport"];
    assert_eq!(transport["type"], "http");
    assert_eq!(transport["method"], "GET");
    assert_eq!(transport["path"], "/tunnel");
    assert_eq!(transport["host"], json!(["edge.example"]));

    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("Mihomo HTTP runtime projection");
    let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime Mihomo profile");
    assert_eq!(runtime["outbounds"][0]["transport"]["method"], "GET");

    for flag in ["global-padding", "authenticated-length"] {
        let rejected = document.replace(&format!("{flag}: false"), &format!("{flag}: true"));
        let error = import_subscription_document(&rejected).expect_err("active VMess framing");
        assert!(error.contains("not represented by the pinned runtime schema"));
    }

    let secret_header = document.replace(
        "Host: [edge.example]",
        "TopSecretValue123: [TopSecretValue123]",
    );
    let error =
        import_subscription_document(&secret_header).expect_err("unsupported custom header");
    assert!(error.contains("unsupported keys"));
    assert!(!error.contains("TopSecretValue123"));
}

#[test]
fn imports_clash_meta_yaml_across_all_supported_types() {
    let document = r#"
mixed-port: 7890
dns:
  enable: true
  nameserver: [https://1.1.1.1/dns-query]
proxies:
  - name: "SS Tokyo"
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: "0123"
    udp: true
  - name: VMess Edge
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: vmess.example.com
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
  - name: Reality
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    flow: xtls-rprx-vision
    encryption: ""
    packet-encoding: xudp
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: Work
    type: trojan
    server: trojan.example.com
    port: 443
    password: hunter2
    sni: trojan.example.com
    alpn:
      - h2
      - http/1.1
    network: grpc
    grpc-opts:
      grpc-service-name: tunnel
  - name: Work-2
    type: hysteria2
    server: hy2.example.com
    port: 8443
    password: supersecret
    sni: hy2.example.com
    up: "100 Mbps"
    down: "200"
    obfs: salamander
    obfs-password: mask
  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: anytls-secret
    tls: true
    sni: front.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0
      short-id: 0123456789abcdef
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 10443
    uuid: 33333333-3333-4333-8333-333333333333
    password: tuic-secret
    sni: tuic.example.com
    alpn: [h3]
    congestion-controller: new_reno
    udp-relay-mode: quic
    reduce-rtt: false
    udp-over-stream: false
    disable-sni: false
proxy-groups:
  - name: PROXY
    type: select
    proxies: [SS Tokyo, VMess Edge]
rules:
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(document).expect("Clash Meta YAML");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds array");
    assert_eq!(outbounds.len(), 8);
    assert_eq!(outbounds[7]["type"], "selector");
    assert_eq!(outbounds[7]["tag"], "PROXY");
    assert_eq!(outbounds[7]["outbounds"], json!(["SS Tokyo", "VMess Edge"]));
    assert_eq!(profile["route"]["final"], "PROXY");

    assert_eq!(profile["dns"]["servers"][0]["type"], "https");

    assert_eq!(outbounds[0]["type"], "shadowsocks");
    assert_eq!(outbounds[0]["tag"], "SS Tokyo");
    assert_eq!(outbounds[0]["method"], "aes-256-gcm");

    assert_eq!(outbounds[1]["type"], "vmess");
    assert_eq!(outbounds[1]["tls"]["server_name"], "vmess.example.com");
    assert_eq!(outbounds[1]["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(outbounds[1]["transport"]["type"], "ws");
    assert_eq!(outbounds[1]["transport"]["path"], "/ws");
    assert_eq!(
        outbounds[1]["transport"]["headers"]["Host"],
        "edge.example.com"
    );
    assert!(
        outbounds[1].get("security").is_none(),
        "auto is the default"
    );

    assert_eq!(outbounds[2]["type"], "vless");
    assert_eq!(outbounds[2]["flow"], "xtls-rprx-vision");
    assert_eq!(outbounds[2]["packet_encoding"], "xudp");
    assert_eq!(outbounds[2]["tls"]["server_name"], "www.example.com");
    assert_eq!(outbounds[2]["tls"]["reality"]["enabled"], true);
    assert_eq!(
        outbounds[2]["tls"]["reality"]["public_key"],
        "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
    );
    assert_eq!(
        outbounds[2]["tls"]["reality"]["short_id"],
        "0123456789abcdef"
    );

    assert_eq!(outbounds[3]["type"], "trojan");
    assert_eq!(outbounds[3]["tag"], "Work");
    assert_eq!(outbounds[3]["tls"]["alpn"][0], "h2");
    assert_eq!(outbounds[3]["transport"]["type"], "grpc");
    assert_eq!(outbounds[3]["transport"]["service_name"], "tunnel");

    assert_eq!(outbounds[4]["type"], "hysteria2");
    assert_eq!(
        outbounds[4]["tag"], "Work-2",
        "duplicate names get suffixes"
    );
    assert_eq!(outbounds[4]["up_mbps"], 100);
    assert_eq!(outbounds[4]["down_mbps"], 200);
    assert_eq!(outbounds[4]["obfs"]["type"], "salamander");

    assert_eq!(outbounds[5]["type"], "anytls");
    assert_eq!(outbounds[5]["tls"]["server_name"], "front.example.com");
    assert_eq!(outbounds[5]["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(outbounds[5]["tls"]["reality"]["enabled"], true);

    assert_eq!(outbounds[6]["type"], "tuic");
    assert_eq!(outbounds[6]["congestion_control"], "new_reno");
    assert_eq!(outbounds[6]["udp_relay_mode"], "quic");
    assert_eq!(outbounds[6]["tls"]["alpn"], json!(["h3"]));

    let secrets: Vec<&str> = imported
        .credentials
        .iter()
        .map(|credential| credential.secret.as_str())
        .collect();
    assert_eq!(
        secrets,
        [
            "0123",
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "hunter2",
            "supersecret",
            "mask",
            "anytls-secret",
            "33333333-3333-4333-8333-333333333333",
            "tuic-secret",
        ],
        "secrets keep exact source bytes, including leading zeros"
    );
    assert_eq!(
        imported.credentials[5].reference.kind(),
        CredentialKind::Hysteria2ObfsPassword
    );
    assert_eq!(
        imported.credentials[6].reference.kind(),
        CredentialKind::AnyTlsPassword
    );
    assert_eq!(
        imported.credentials[7].reference.kind(),
        CredentialKind::TuicUuid
    );
    assert_eq!(
        imported.credentials[8].reference.kind(),
        CredentialKind::TuicPassword
    );
    let stored = imported.profile.as_json();
    for secret in [
        "hunter2",
        "supersecret",
        "mask",
        "anytls-secret",
        "33333333-3333-4333-8333-333333333333",
        "tuic-secret",
    ] {
        assert!(
            !stored.contains(secret),
            "stored profile must not embed secrets"
        );
    }
}

#[test]
fn clash_wireguard_import_keeps_keys_only_in_the_vault_batch() {
    let key = STANDARD.encode([1u8; 32]);
    let source = format!(
        "proxies:\n  - {{name: VPN, type: wireguard, server: edge.example.com, port: 51820, ip: 10.1.0.2, private-key: '{key}', public-key: '{key}', pre-shared-key: '{key}'}}\n"
    );
    let imported = import_subscription_document(&source).expect("WireGuard import");
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::WireGuardPrivateKey
    );
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::WireGuardPreSharedKey
    );
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(
        profile["outbounds"][0]["local_addresses"],
        json!(["10.1.0.2/32"])
    );
    assert!(profile["outbounds"][0].get("private-key").is_none());
    assert!(profile["outbounds"][0].get("private_key").is_none());
    assert!(profile["outbounds"][0].get("pre_shared_key").is_none());
}

#[test]
fn clash_yaml_conversion_fails_closed_without_echoing_secrets() {
    let unsupported_type = "proxies:\n  - name: node\n    type: wireguard\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n";
    let error = import_subscription_document(unsupported_type).expect_err("unsupported proxy type");
    assert!(error.contains("proxies[0]"), "{error}");
    assert!(!error.contains("wireguard"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let insecure = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    skip-cert-verify: true\n";
    let error = import_subscription_document(insecure).expect_err("skip-cert-verify");
    assert!(
        error.contains("disabling TLS certificate verification"),
        "{error}"
    );
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let multiplexed = "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    smux:\n      enabled: true\n";
    let error = import_subscription_document(multiplexed).expect_err("smux");
    assert!(
        error.contains("uses stream multiplexing (smux), which is not supported"),
        "{error}"
    );
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let unknown_key = "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    TopSecretValue123: 5\n";
    let error = import_subscription_document(unknown_key).expect_err("unknown key");
    assert!(error.contains("unsupported keys"), "{error}");
    assert!(!error.contains("TopSecretValue123"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    let alias_bomb = "proxies: &a\n  - name: node\nmore: *a\n";
    let error = import_subscription_document(alias_bomb).expect_err("aliases rejected");
    assert!(error.contains("anchors are not supported"), "{error}");

    let missing_proxies = "mixed-port: 7890\n";
    let error = import_subscription_document(missing_proxies).expect_err("no proxies");
    assert!(error.contains("no proxies list"), "{error}");

    let overlapping_ports = "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    ports: 20000-30000,25000-31000\n";
    let error =
        import_subscription_document(overlapping_ports).expect_err("overlapping port ranges");
    assert!(error.contains("overlapping"), "{error}");
    assert!(!error.contains("TopSecretValue!"), "{error}");

    for (label, document, expected) in [
        (
            "TUIC 0-RTT",
            "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    reduce-rtt: true\n",
            "0-RTT",
        ),
        (
            "TUIC uTLS",
            "proxies:\n  - name: node\n    type: tuic\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
            "does not support uTLS",
        ),
        (
            "Hysteria2 uTLS",
            "proxies:\n  - name: node\n    type: hysteria2\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    client-fingerprint: chrome\n",
            "does not support uTLS",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}

/// Mihomo verifies a node that carries a `fingerprint` against the pin alone,
/// whatever `skip-cert-verify` says, so a redundant `skip-cert-verify: true`
/// beside a pin imports as the pin, as `insecure=1` beside `pinSHA256` does
/// for share links. Without a usable pin it still fails closed.
#[test]
fn clash_skip_cert_verify_beside_a_pin_imports_as_the_pin() {
    let colons = ASCENDING_PIN_HEX
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("ASCII hex"))
        .collect::<Vec<_>>()
        .join(":");
    let hysteria2 = |extra: &str| {
        format!(
            "proxies:\n  - name: node\n    type: hysteria2\n    server: hy2.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: hy2.example.com\n{extra}"
        )
    };
    let trojan = |extra: &str| {
        format!(
            "proxies:\n  - name: node\n    type: trojan\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: a.example.com\n{extra}"
        )
    };
    for (label, document, server_name) in [
        (
            "hysteria2",
            hysteria2(&format!(
                "    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            )),
            "hy2.example.com",
        ),
        (
            "hysteria2, pin first",
            hysteria2(&format!(
                "    fingerprint: \"{colons}\"\n    skip-cert-verify: true\n"
            )),
            "hy2.example.com",
        ),
        (
            "trojan",
            trojan(&format!(
                "    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            )),
            "a.example.com",
        ),
    ] {
        let imported = import_subscription_document(&document)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        let tls = &imported_outbounds(&imported)[0]["tls"];
        assert_eq!(
            tls["certificate_sha256"],
            json!([ASCENDING_PIN_BASE64]),
            "{label}"
        );
        assert_eq!(tls["server_name"], server_name, "{label}");
        assert!(tls.get("insecure").is_none(), "{label}");
        let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
        assert!(
            runtime["outbounds"][0]["tls"].get("insecure").is_none(),
            "{label}"
        );
    }
    for (label, document, reason) in [
        (
            "no pin",
            hysteria2("    skip-cert-verify: true\n"),
            "disabling TLS certificate verification",
        ),
        (
            "an empty pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: \"\"\n"),
            "disabling TLS certificate verification",
        ),
        (
            "a null pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: null\n"),
            "disabling TLS certificate verification",
        ),
        (
            "a malformed pin",
            hysteria2("    skip-cert-verify: true\n    fingerprint: not-a-pin\n"),
            "TLS certificate fingerprint must be a SHA256 hex value",
        ),
        (
            "a pin without TLS",
            format!(
                "proxies:\n  - name: node\n    type: vmess\n    server: a.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    alterId: 0\n    cipher: auto\n    tls: false\n    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            ),
            "certificate pin requires TLS",
        ),
        (
            "a type without TLS",
            format!(
                "proxies:\n  - name: node\n    type: ss\n    server: a.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n    skip-cert-verify: true\n    fingerprint: {ASCENDING_PIN_HEX}\n"
            ),
            "unsupported keys",
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(error.contains(reason), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }
}
