//! The helpers every adapter shares: strict share-link parsing, protocol
//! option normalization and Hysteria2 port sets. Each refuses what it cannot
//! represent and never echoes the refused value.

use reqwest::Url;

use super::*;

fn url(text: &str) -> Url {
    Url::parse(text).expect("test URL")
}

fn query(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn a_query_parameter_appears_once_under_one_name() {
    assert_eq!(
        split_query_strict("trojan://host?sni=a&sni=b", "trojan").map(|(_, query)| query),
        Err("trojan URI repeats query parameter <redacted>".into())
    );
    assert_eq!(
        strict_query_map(&url("vless://id@host:443?flow=a&flow=b"), "vless"),
        Err("vless URI repeats query parameter <redacted>".into())
    );
    let mut aliases = query(&[("sni", "a.example.com"), ("peer", "a.example.com")]);
    assert_eq!(
        take_query_alias(&mut aliases, &["sni", "peer"], "trojan", "SNI"),
        Err("trojan URI repeats SNI using multiple aliases".into())
    );
}

#[test]
fn credentials_in_a_share_link_must_be_present() {
    assert_eq!(
        required_url_username(&url("vless://@host:443"), "VLESS UUID"),
        Err("VLESS UUID is missing".into())
    );
    assert_eq!(
        required_url_password(&url("ss://user@host:443"), "Shadowsocks password"),
        Err("Shadowsocks password is missing".into())
    );
}

#[test]
fn tls_markers_and_booleans_accept_only_their_spellings() {
    let mut security = query(&[("security", "reality")]);
    assert_eq!(
        consume_required_tls_marker(&mut security, "trojan"),
        Err("trojan URI security mode is unsupported: <redacted>".into())
    );
    let mut empty = query(&[("security", "")]);
    assert_eq!(consume_required_tls_marker(&mut empty, "trojan"), Ok(()));
    assert_eq!(
        parse_uri_boolean("maybe", "AnyTLS", "insecure"),
        Err("AnyTLS URI parameter <redacted> must be a boolean".into())
    );
}

#[test]
fn an_explicit_port_of_zero_or_a_missing_one_without_a_default_is_refused() {
    assert_eq!(
        port_from_url_or_default(&url("tcp://host:0"), 443),
        Err("subscription endpoint port is invalid".into())
    );
    assert_eq!(
        port_from_url_or_default(&url("tcp://host"), 0),
        Err("subscription endpoint port is missing".into())
    );
    assert_eq!(port_from_url_or_default(&url("tcp://host"), 443), Ok(443));
    assert_eq!(
        parse_port_value(&json!(true)),
        Err("vmess port is invalid".into())
    );
}

#[test]
fn protocol_options_normalize_or_are_refused_without_echoing_them() {
    assert_eq!(
        normalize_shadowsocks_method_and_password("rc4-md5", "secret"),
        Err("Shadowsocks method is unsupported: <redacted>".into())
    );
    assert_eq!(
        canonical_uuid_credential("00000000-0000-0000-0000-000000000000".into(), "VLESS UUID"),
        Err("VLESS UUID must not be the nil UUID".into())
    );
    assert_eq!(normalize_vmess_security("AUTO"), Ok(None));
    assert_eq!(
        normalize_vmess_security("ChaCha20-Poly1305"),
        Ok(Some("chacha20-poly1305".into()))
    );
    assert_eq!(
        normalize_vmess_security("rc4"),
        Err("vmess security is unsupported: <redacted>".into())
    );
    assert_eq!(
        normalize_vless_flow("xtls-rprx-direct"),
        Err("VLESS flow is unsupported: <redacted>".into())
    );
    assert_eq!(
        normalize_v2ray_http_method("CONNECT", "HTTP method"),
        Err("HTTP method is unsupported: <redacted>".into())
    );
}

#[test]
fn a_hysteria2_share_link_brackets_ipv6_and_states_one_port_form() {
    for (link, message) in [
        ("hysteria2", "subscription Hysteria2 URI is invalid"),
        ("tuic://host:443", "subscription Hysteria2 URI is invalid"),
        (
            "hysteria2://pass@[2001:db8::1",
            "subscription Hysteria2 URI is invalid",
        ),
        (
            "hysteria2://pass@[2001:db8::1]x443",
            "subscription Hysteria2 URI is invalid",
        ),
        (
            "hysteria2://pass@2001:db8::1:443",
            "subscription Hysteria2 IPv6 host must be bracketed",
        ),
    ] {
        assert_eq!(
            parse_hysteria2_share_url(link).map(|_| ()),
            Err(message.into()),
            "{link}"
        );
    }
    let (parsed, ports) =
        parse_hysteria2_share_url("hysteria2://pass@[2001:db8::1]").expect("bracketed host");
    assert_eq!(parsed.host_str(), Some("[2001:db8::1]"));
    assert_eq!(ports, None);
    let (parsed, ports) = parse_hysteria2_share_url("hy2://pass@[2001:db8::1]:443,8443-8450")
        .expect("bracketed host with a port set");
    assert_eq!(parsed.port(), Some(443));
    assert_eq!(ports, Some(vec!["443".into(), "8443:8450".into()]));
}

#[test]
fn a_hysteria2_port_set_is_bounded_ordered_and_unambiguous() {
    let label = "Hysteria2 ports";
    let too_many = (1..=65)
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    for (ports, message) in [
        (
            too_many.as_str(),
            "Hysteria2 ports has an invalid item count",
        ),
        ("443,,444", "Hysteria2 ports has an invalid item count"),
        ("1000-2000:3000", "Hysteria2 ports has an invalid range"),
        ("2000-1000", "Hysteria2 ports has an invalid range"),
        ("0443", "Hysteria2 ports has an invalid port"),
        ("1000-2000,1500", "Hysteria2 ports has overlapping items"),
    ] {
        assert_eq!(
            normalize_hysteria2_server_ports(ports, label),
            Err(message.into()),
            "{ports}"
        );
    }
    assert_eq!(
        parse_hysteria2_hop_interval_range("10-10", "hop interval"),
        Ok((10, None))
    );
}
