//! The Clash global client fingerprint and the TLS parts certificate pins.

use super::*;

#[test]
fn clash_global_client_fingerprint_is_written_onto_tls_stream_nodes_without_their_own() {
    let explicit = import_with_stable_references(&clash_tls_stream_proxies(
        "    client-fingerprint: chrome\n",
    ));
    for (label, document) in [
        (
            "absent per-node value",
            format!(
                "{}global-client-fingerprint: Chrome\n",
                clash_tls_stream_proxies("")
            ),
        ),
        (
            "empty per-node value",
            format!(
                "global-client-fingerprint: chrome\n{}",
                clash_tls_stream_proxies("    client-fingerprint: \"\"\n")
            ),
        ),
        (
            "null per-node value",
            format!(
                "global-client-fingerprint: chrome\n{}",
                clash_tls_stream_proxies("    client-fingerprint: ~\n")
            ),
        ),
    ] {
        let inherited = import_with_stable_references(&document);
        let outbounds = imported_outbounds(&inherited);
        assert_eq!(outbounds.len(), 5, "{label}");
        for outbound in &outbounds {
            assert_eq!(
                outbound["tls"]["utls"],
                json!({"enabled": true, "fingerprint": "chrome"}),
                "{label}: {}",
                outbound["tag"]
            );
        }
        assert_eq!(outbounds[2]["tls"]["reality"]["enabled"], true, "{label}");
        assert_eq!(
            inherited.profile.as_json(),
            explicit.profile.as_json(),
            "{label}: the stored profile equals one that names chrome on every node"
        );
        assert_eq!(
            projected_json(&inherited),
            projected_json(&explicit),
            "{label}: the runtime projection is byte-identical"
        );
    }
}

#[test]
fn clash_node_client_fingerprint_takes_precedence_over_the_global_one() {
    let trojan = |name: &str, fingerprint: &str| {
        format!(
            "  - name: {name}\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TopSecretValue!\n{fingerprint}"
        )
    };
    let document = format!(
        "global-client-fingerprint: chrome\nproxies:\n{}{}{}{}",
        trojan("own", "    client-fingerprint: firefox\n"),
        trojan("none", "    client-fingerprint: none\n"),
        trojan("upper-none", "    client-fingerprint: NONE\n"),
        trojan("inherits", ""),
    );
    let outbounds = imported_outbounds(&import_with_stable_references(&document));
    assert_eq!(
        outbounds[0]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "firefox"})
    );
    for outbound in &outbounds[1..3] {
        assert_eq!(outbound["tls"]["enabled"], true, "{}", outbound["tag"]);
        assert!(
            outbound["tls"].get("utls").is_none(),
            "`none` keeps standard TLS for {}",
            outbound["tag"]
        );
    }
    assert_eq!(
        outbounds[3]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "chrome"})
    );

    let standalone_none = import_with_stable_references(&format!(
        "proxies:\n{}",
        trojan("none", "    client-fingerprint: none\n")
    ));
    assert!(
        imported_outbounds(&standalone_none)[0]["tls"]
            .get("utls")
            .is_none()
    );

    let reality_with_none = "global-client-fingerprint: chrome\nproxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    client-fingerprint: none\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n";
    assert_eq!(
        import_subscription_document(reality_with_none).expect_err("Reality over standard TLS"),
        "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
    );
}

#[test]
fn clash_global_client_fingerprint_none_empty_or_null_sets_no_default() {
    let trojan = "proxies:\n  - name: Trojan\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TopSecretValue!\n";
    let reality = "proxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n";
    let without_key = import_with_stable_references(trojan);
    for global in [
        "global-client-fingerprint: none\n",
        "global-client-fingerprint: None\n",
        "global-client-fingerprint: \"\"\n",
        "global-client-fingerprint: ~\n",
        "global-client-fingerprint:\n",
    ] {
        let imported = import_with_stable_references(&format!("{global}{trojan}"));
        assert_eq!(
            imported.profile.as_json(),
            without_key.profile.as_json(),
            "{global}"
        );
        assert_eq!(
            import_subscription_document(&format!("{global}{reality}")).expect_err(global),
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS"
        );
    }
}

#[test]
fn clash_global_client_fingerprint_rejects_unsupported_and_non_scalar_values() {
    // Only a Shadowsocks node: the value is refused even where it would apply
    // to nothing, because the document names a fingerprint this app lacks.
    let shadowsocks = "proxies:\n  - name: SS\n    type: ss\n    server: ss.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue!\n";
    for (global, expected) in [
        (
            "chrome120",
            "Clash profile.global-client-fingerprint: uTLS fingerprint is unsupported: <redacted>",
        ),
        (
            "TopSecretValue!",
            "Clash profile.global-client-fingerprint: uTLS fingerprint is unsupported: <redacted>",
        ),
        (
            "[chrome]",
            "Clash profile.global-client-fingerprint must be a scalar value",
        ),
        (
            "{name: chrome}",
            "Clash profile.global-client-fingerprint must be a scalar value",
        ),
    ] {
        let error = import_subscription_document(&format!(
            "global-client-fingerprint: {global}\n{shadowsocks}"
        ))
        .expect_err(global);
        assert_eq!(error, expected, "{global}");
    }
}

#[test]
fn clash_global_client_fingerprint_skips_types_mihomo_never_gave_it() {
    let document = "global-client-fingerprint: chrome
proxies:
  - name: HTTPS
    type: http
    server: http.example.com
    port: 443
    tls: true
  - name: HTTPS own
    type: http
    server: http.example.com
    port: 443
    tls: true
    client-fingerprint: firefox
  - name: Hysteria2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: TopSecretValue!
  - name: TUIC
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: TopSecretValue!
  - name: VMess plain
    type: vmess
    server: vmess.example.com
    port: 80
    uuid: 22222222-2222-4222-8222-222222222222
  - name: VMess tls false
    type: vmess
    server: vmess.example.com
    port: 80
    uuid: 33333333-3333-4333-8333-333333333333
    tls: false
  - name: VLESS plain
    type: vless
    server: vless.example.com
    port: 80
    uuid: 44444444-4444-4444-8444-444444444444
";
    let outbounds = imported_outbounds(&import_with_stable_references(document));
    assert_eq!(outbounds.len(), 7);
    assert_eq!(
        outbounds[1]["tls"]["utls"],
        json!({"enabled": true, "fingerprint": "firefox"})
    );
    for outbound in [&outbounds[0], &outbounds[2], &outbounds[3]] {
        assert_eq!(outbound["tls"]["enabled"], true, "{}", outbound["tag"]);
        assert!(
            outbound["tls"].get("utls").is_none(),
            "{} keeps standard TLS",
            outbound["tag"]
        );
    }
    for outbound in &outbounds[4..] {
        assert!(
            outbound.get("tls").is_none(),
            "{} gains no TLS",
            outbound["tag"]
        );
    }

    // A V2Ray QUIC transport cannot carry uTLS. Mihomo has no such transport
    // and gave these nodes the global value over TCP, so the request fails
    // closed exactly like a per-node client-fingerprint does.
    let quic = |global: &str, fingerprint: &str| {
        format!(
            "{global}proxies:\n  - name: QUIC\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: 11111111-1111-4111-8111-111111111111\n    tls: true\n    network: quic\n{fingerprint}"
        )
    };
    for document in [
        quic("global-client-fingerprint: chrome\n", ""),
        quic("", "    client-fingerprint: chrome\n"),
    ] {
        let error = import_subscription_document(&document).expect_err("uTLS over V2Ray QUIC");
        assert!(error.contains("uTLS is unavailable for QUIC"), "{error}");
    }
    import_subscription_document(&quic("global-client-fingerprint: none\n", ""))
        .expect("standard TLS over V2Ray QUIC");
}

#[test]
fn none_fingerprint_stays_unsupported_outside_clash_documents() {
    let uri = "vless://22222222-2222-4222-8222-222222222222@vless.example.com:443?security=tls&sni=vless.example.com&fp=none&encryption=none#TLS";
    let sing_box = json!({"outbounds": [{
        "type": "vless", "tag": "TLS", "server": "vless.example.com", "server_port": 443,
        "uuid": "22222222-2222-4222-8222-222222222222",
        "tls": {"enabled": true, "server_name": "vless.example.com",
                "utls": {"enabled": true, "fingerprint": "none"}},
    }]})
    .to_string();
    for document in [uri.to_owned(), sing_box] {
        assert_eq!(
            import_subscription_document(&document).expect_err("`none` is Clash-only"),
            "uTLS fingerprint is unsupported: <redacted>"
        );
    }
}

#[test]
fn tls_parts_emit_certificate_sha256_only_when_present() {
    let parts = || build_tls_parts(true, "pinned.example.com".into(), Vec::new(), None, None);
    assert_eq!(
        tls_json(parts()),
        json!({"enabled":true,"server_name":"pinned.example.com"})
    );
    let pinned = tls_json(TlsParts {
        certificate_sha256: vec!["first".into(), "second".into()],
        ..parts()
    });
    assert_eq!(
        pinned,
        json!({"enabled":true,"server_name":"pinned.example.com","certificate_sha256":["first","second"]})
    );
}
