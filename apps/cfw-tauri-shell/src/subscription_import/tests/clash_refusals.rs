//! Clash documents the import refuses: a malformed document or proxy list,
//! proxy and TLS options the profile cannot carry, field shapes it cannot read,
//! and DNS policy it cannot represent.

use super::*;

const SOCKS: &str =
    "  - name: Node\n    type: socks5\n    server: node.example.com\n    port: 1080\n";

fn refusal(document: &str) -> String {
    import_subscription_document(document).expect_err("the document is refused")
}

fn assert_refused(document: &str, message: &str) {
    let error = refusal(document);
    assert!(error.contains(message), "{document:?}: {error}");
}

fn proxy(lines: &str) -> String {
    format!("proxies:\n  - name: Node\n{lines}")
}

#[test]
fn a_nul_character_refuses_the_document_instead_of_importing_what_precedes_it() {
    // Read as the end of input, the NUL would drop the second proxy without
    // a word and import the first.
    let document = format!(
        "proxies:\n{SOCKS}\0  - name: Second\n    type: socks5\n    server: b.example.com\n    port: 1080\n"
    );
    assert_refused(&document, "subscription YAML is invalid");
}

#[test]
fn a_document_needs_a_mapping_root_and_a_bounded_list_of_uniquely_named_mappings() {
    assert_eq!(
        clash::import_clash_document("- not\n- a mapping\n", OutboundCollector::default())
            .map(|_| ()),
        Err("Clash subscription document must be a YAML mapping".into())
    );
    assert_refused("proxies: none\n", "Clash proxies must be a YAML sequence");
    assert_refused(
        "proxies:\n  - just-a-name\n",
        "proxies[0] must be a YAML mapping",
    );
    for names in [("Node", "Node"), ("Node", "DIRECT")] {
        let document = format!(
            "proxies:\n  - {{name: {}, type: socks5, server: a.example.com, port: 1080}}\n  - {{name: {}, type: socks5, server: b.example.com, port: 1080}}\n",
            names.0, names.1
        );
        assert_refused(
            &document,
            "Clash proxy names must be unique and cannot use DIRECT or REJECT",
        );
    }
    let mut oversized = String::from("proxies:\n");
    for index in 0..=cfw_singbox_config::MAX_OUTBOUNDS {
        writeln!(
            oversized,
            "  - {{name: N{index}, type: socks5, server: n.example.com, port: 1080}}"
        )
        .expect("write");
    }
    assert_refused(
        &oversized,
        &format!(
            "Clash subscription document has {} proxies; at most {} are supported",
            cfw_singbox_config::MAX_OUTBOUNDS + 1,
            cfw_singbox_config::MAX_OUTBOUNDS
        ),
    );
}

#[test]
fn proxy_options_the_profile_cannot_carry_are_refused() {
    for (lines, message) in [
        (
            "    type: http\n    server: p.example.com\n    port: 8080\n    udp: true\n",
            "HTTP CONNECT proxies cannot carry UDP",
        ),
        (
            "    type: ss\n    server: s.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue123\n    plugin: obfs\n",
            "uses a Shadowsocks plugin, which is unsupported in subscription imports",
        ),
        (
            "    type: ss\n    server: s.example.com\n    port: 8388\n    cipher: aes-256-gcm\n    password: TopSecretValue123\n    udp-over-tcp: true\n",
            "requires udp-over-tcp, which is not supported",
        ),
        (
            "    type: vless\n    server: v.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    encryption: aes-128-gcm\n",
            "uses unsupported VLESS encryption: <redacted>",
        ),
        (
            "    type: hysteria2\n    server: h.example.com\n    port: 443\n    password: TopSecretValue!\n    ports: 1000-2000\n    mport: 3000-4000\n",
            "repeats Hysteria2 port hopping with ports and mport",
        ),
        (
            "    type: hysteria2\n    server: h.example.com\n    port: 443\n    password: TopSecretValue!\n    obfs: gecko\n    obfs-password: TopSecretValue!\n    obfs-min-packet-size: '0128'\n",
            "obfs-min-packet-size must be a canonical packet size",
        ),
        (
            "    type: hysteria2\n    server: h.example.com\n    port: 443\n    password: TopSecretValue!\n    obfs: invented\n",
            "Hysteria2 obfs mode is unsupported: <redacted>",
        ),
    ] {
        assert_refused(&proxy(lines), message);
    }
}

#[test]
fn optional_proxy_settings_are_kept() {
    let imported = import_subscription_document(&proxy(&format!(
        "    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n    cipher: aes-128-gcm\n    packet-encoding: xudp\n"
    )))
    .expect("VMess import");
    let outbound = &imported_outbounds(&imported)[0];
    assert_eq!(outbound["security"], "aes-128-gcm");
    assert_eq!(outbound["packet_encoding"], "xudp");

    let key = STANDARD.encode([1u8; 32]);
    let imported = import_subscription_document(&format!(
        "proxies:\n  - {{name: VPN, type: wireguard, server: edge.example.com, port: 51820, ip: 10.1.0.2/24, private-key: '{key}', public-key: '{key}'}}\n"
    ))
    .expect("WireGuard import");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert!(
        profile.to_string().contains("10.1.0.2/24"),
        "a prefixed address keeps its prefix: {profile}"
    );
}

#[test]
fn tls_options_the_proxy_type_cannot_carry_are_refused() {
    for (lines, message) in [
        (
            "    type: trojan\n    server: t.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: a.example.com\n    servername: b.example.com\n",
            "declares conflicting servername and sni values",
        ),
        (
            &format!(
                "    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n    cipher: auto\n    tls: true\n    reality-opts:\n      public-key: key\n"
            ),
            "does not support Reality",
        ),
        (
            "    type: vless\n    server: v.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    reality-opts:\n      public-key: key\n",
            "declares reality-opts without tls: true",
        ),
        (
            "    type: trojan\n    server: t.example.com\n    port: 443\n    password: TopSecretValue!\n    reality-opts:\n      public-key: key\n",
            "does not support Reality",
        ),
        (
            "    type: trojan\n    server: t.example.com\n    port: 443\n    password: TopSecretValue!\n    tls: false\n",
            "declares tls: false for an always-TLS proxy type",
        ),
        (
            "    type: anytls\n    server: a.example.com\n    port: 443\n    password: TopSecretValue!\n    tls: false\n",
            "declares tls: false for an always-TLS proxy type",
        ),
    ] {
        assert_refused(&proxy(lines), message);
    }
}

#[test]
fn field_shapes_are_read_only_as_declared() {
    let vmess = |lines: &str| {
        proxy(&format!(
            "    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n    cipher: auto\n{lines}"
        ))
    };
    for (lines, message) in [
        (
            "    network: ws\n    ws-opts: plain\n",
            "proxies[0].ws-opts must be a YAML mapping",
        ),
        (
            "    tls: true\n    alpn:\n      - [h2]\n",
            "proxies[0].alpn entries must be scalar values",
        ),
        (
            "    tls: true\n    alpn:\n      h2: true\n",
            "proxies[0].alpn must be a YAML sequence",
        ),
        (
            "    network: h2\n    h2-opts:\n      host:\n        - [a.example.com]\n",
            "h2-opts.host entries must be scalar values",
        ),
        (
            "    network: h2\n    h2-opts:\n      host:\n        name: a.example.com\n",
            "h2-opts.host must be a scalar or YAML sequence",
        ),
    ] {
        assert_refused(&vmess(lines), message);
    }
    let imported =
        import_subscription_document(&vmess("    network: h2\n    h2-opts:\n      host: ~\n"))
            .expect("a null host is no host");
    assert!(
        imported_outbounds(&imported)[0]["transport"]
            .get("host")
            .is_none()
    );
}

#[test]
fn dns_policy_the_profile_cannot_represent_is_refused() {
    let with_dns =
        |dns: &str| format!("proxies:\n{SOCKS}dns:\n  nameserver:\n    - 1.1.1.1\n{dns}");
    for (dns, message) in [
        (
            "  default-nameserver:\n    - tls://dns.example.com\n",
            "Clash default-nameserver transports require numeric endpoints to avoid a bootstrap cycle",
        ),
        (
            "  fallback:\n    - 8.8.8.8\n  fallback-filter:\n    geoip: true\n    invented: true\n",
            "Clash DNS fallback-filter contains an unsupported field",
        ),
        (
            "  enhanced-mode: fake-ip\n  fake-ip-filter-mode: whitelist\n",
            "Clash fake-IP import currently supports blacklist filters",
        ),
        (
            "  enhanced-mode: mapping\n",
            "Clash dns.enhanced-mode is unsupported",
        ),
        (
            "  fallback:\n    - ftp://9.9.9.9\n",
            "Clash nameserver transport is unsupported",
        ),
        (
            "  fallback:\n    - tls://9.9.9.9/resolve\n",
            "Clash nameserver transport does not accept a URL path",
        ),
    ] {
        assert_refused(&with_dns(dns), message);
    }
    assert_refused(
        &format!("proxies:\n{SOCKS}hosts:\n  Example.com: 1.1.1.1\n  example.com: 1.1.1.2\n"),
        "Clash hosts names must be unique regardless of case",
    );
    let imported = import_subscription_document(&with_dns("  fallback:\n    - https://1.1.1.1\n"))
        .expect("DNS over HTTPS without a path");
    assert!(
        imported.profile.as_json().contains("/dns-query"),
        "DNS over HTTPS defaults to /dns-query"
    );
    let imported = import_subscription_document(&with_dns(
        "  default-nameserver:\n    - 9.9.9.9\n    - tls://1.0.0.1\n",
    ))
    .expect("numeric bootstrap endpoints");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    let bootstrap = &profile["dns"]["bootstrap_servers"];
    assert_eq!(bootstrap[0], "9.9.9.9");
    assert_eq!(bootstrap[1]["server"], "1.0.0.1");
}
