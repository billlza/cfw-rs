//! Byte-identity goldens for representative projections with the default
//! settings. They were captured from the 0.5 line before GEOSITE rules and the
//! mainland China direct switch existed, so every later change to routing, DNS
//! or dataset resources must leave these bytes unchanged while the switch is
//! off. A mismatch writes the actual output to `target/tmp/projection-goldens/`
//! and fails; the goldens are never rewritten automatically.

use std::path::PathBuf;

use serde_json::{Value, json};

use crate::{EngineSettings, LanProxySettings, ProjectionMode, ValidatedSingBoxProfile};

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECRET_PLACEHOLDER: &str = "<CLASH-API-SECRET>";

struct Case {
    name: &'static str,
    profile: ValidatedSingBoxProfile,
    mode: ProjectionMode,
    settings: EngineSettings,
}

fn parse(value: &Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&value.to_string()).expect("golden profile")
}

fn shadowsocks() -> Value {
    json!({"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"ss.example.com","server_port":443,
        "method":"aes-256-gcm","credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"shadowsocks_password"}}],
        "route":{"final":"proxy"}})
}

/// The shape of a Mooring export: only outbounds, REALITY first, then
/// Hysteria2 with a DER certificate pin, so CFM injects its own selector.
fn outbound_only_pair() -> Value {
    json!({"outbounds":[
        {"type":"vless","tag":"lon1-reality","server":"45.67.89.10","server_port":443,
         "credential_ref":{"id":"22222222-2222-4222-8222-222222222222","kind":"vless_uuid"},"flow":"xtls-rprx-vision",
         "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
                "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}},
        {"type":"hysteria2","tag":"lon1-hy2","server":"45.67.89.10","server_port":61000,
         "credential_ref":{"id":"33333333-3333-4333-8333-333333333333","kind":"hysteria2_password"},
         "tls":{"enabled":true,"server_name":"n0123456789abcdef.internal",
                "certificate_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]},
         "obfs":{"type":"salamander","credential_ref":{"id":"44444444-4444-4444-8444-444444444444","kind":"hysteria2_obfs_password"}}}
    ]})
}

fn public_key_pinned_trojan() -> Value {
    json!({"outbounds":[{"type":"trojan","tag":"pinned","server":"trojan.example.com","server_port":443,
        "credential_ref":{"id":"55555555-5555-4555-8555-555555555555","kind":"trojan_password"},
        "tls":{"enabled":true,"server_name":"trojan.example.com",
               "certificate_public_key_sha256":["//////////////////////////////////////////8="]}}],
        "route":{"final":"pinned"}})
}

fn policy() -> Value {
    json!({"outbounds":[
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":["Node","DIRECT"]}],
        "route":{"final":"PROXY","rules":[
            {"type":"process_name","value":"Example Helper","outbound":"PROXY"},
            {"type":"domain_suffix","value":"example.com","outbound":"PROXY"},
            {"type":"ip_cidr","value":"192.0.2.1/32","outbound":"DIRECT","no_resolve":true},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT"},
            {"type":"geo_ip","value":"LAN","outbound":"DIRECT"}]}})
}

fn rule_provider() -> Value {
    json!({"outbounds":[
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"}],
        "route":{"final":"Node","rules":[
            {"type":"rule_set","value":"lists","outbound":"DIRECT"},
            {"type":"geo_ip","value":"JP","outbound":"Node","no_resolve":true}]},
        "providers":{"rules":[{"name":"lists","source":{"interval_seconds":86400},"format":"yaml","behavior":"classical","rules":[
            {"type":"domain_suffix","value":"cn.example"},
            {"type":"geo_ip","value":"CN"},
            {"type":"ip_cidr","value":"198.51.100.0/24"}]}]}})
}

fn profile_dns() -> Value {
    json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},{"type":"direct","tag":"direct"}],
        "route":{"final":"proxy","rules":[{"type":"domain","value":"direct.example.com","outbound":"direct"}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53},{"type":"tcp","server":"8.8.8.8","server_port":53}],
            "bootstrap_servers":["223.5.5.5"],
            "nameserver_policy":[{"domain":"+.example.org","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]}],
            "proxy_servers":[{"type":"tcp","server":"180.76.76.76","server_port":53}],
            "direct_servers":[{"type":"tcp","server":"114.114.114.114","server_port":53}]}})
}

fn profile_dns_datasets() -> Value {
    let mut source = profile_dns();
    source["dns"]["nameserver_policy"] = json!([
        {"domain":"+.example.org","servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}]},
        {"domain":"geosite:cn","servers":[{"type":"tcp","server":"223.5.5.5","server_port":53}]}]);
    source["dns"]["fallback_servers"] = json!([{"type":"udp","server":"8.8.4.4","server_port":53}]);
    source["dns"]["fallback_filter"] = json!({"geoip_code":"cn","geosite":["geolocation-!cn"]});
    source["dns"]["fake_ip"] = json!({"exclude":["geosite:cn"]});
    source
}

fn automatic() -> Value {
    json!({"outbounds":[
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
            {"type":"urltest","tag":"automatic","outbounds":["first","second"],
             "url":"https://www.gstatic.com/generate_204","interval_seconds":300,
             "tolerance_ms":50,"idle_timeout_seconds":1800},
            {"type":"selector","tag":"PROXY","outbounds":["automatic","second"]}],
        "route":{"final":"PROXY"}})
}

fn wireguard() -> Value {
    json!({"outbounds":[{"type":"wireguard","tag":"wg","server":"vpn.example.com","server_port":51820,
        "local_addresses":["10.10.0.2/32","fd00::2/128"],"mtu":1420,"persistent_keepalive_seconds":25,
        "peer_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "private_key_credential_ref":{"id":"66666666-6666-4666-8666-666666666666","kind":"wireguard_private_key"}}],
        "route":{"final":"wg"}})
}

fn lan_settings() -> EngineSettings {
    EngineSettings {
        lan_proxy: Some(LanProxySettings {
            listen: "0.0.0.0".parse().expect("LAN address"),
            port: 8891,
            allowed_source_cidrs: vec!["192.168.0.0/16".into()],
        }),
        ..EngineSettings::default()
    }
}

fn cases() -> Vec<Case> {
    let default = EngineSettings::default;
    let case = |name, profile: &Value, mode, settings| Case {
        name,
        profile: parse(profile),
        mode,
        settings,
    };
    let mut cases = vec![
        Case {
            name: "direct-system-proxy",
            profile: ValidatedSingBoxProfile::direct(),
            mode: ProjectionMode::SystemProxy,
            settings: default(),
        },
        Case {
            name: "direct-tunnel",
            profile: ValidatedSingBoxProfile::direct(),
            mode: ProjectionMode::Tunnel,
            settings: default(),
        },
        case(
            "shadowsocks-system-proxy",
            &shadowsocks(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "shadowsocks-tunnel",
            &shadowsocks(),
            ProjectionMode::Tunnel,
            default(),
        ),
        case(
            "shadowsocks-system-proxy-ipv4-dns",
            &shadowsocks(),
            ProjectionMode::SystemProxy,
            EngineSettings {
                ipv6_dns_enabled: Some(false),
                ..default()
            },
        ),
        case(
            "shadowsocks-tunnel-system-proxy-lan",
            &shadowsocks(),
            ProjectionMode::TunnelSystemProxy,
            lan_settings(),
        ),
        case(
            "outbound-only-pair-system-proxy",
            &outbound_only_pair(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "outbound-only-pair-tunnel",
            &outbound_only_pair(),
            ProjectionMode::Tunnel,
            default(),
        ),
        case(
            "public-key-pin-system-proxy",
            &public_key_pinned_trojan(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "policy-system-proxy",
            &policy(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "policy-tunnel-system-proxy",
            &policy(),
            ProjectionMode::TunnelSystemProxy,
            default(),
        ),
        case(
            "rule-provider-system-proxy",
            &rule_provider(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "profile-dns-local-proxy",
            &profile_dns(),
            ProjectionMode::LocalProxy,
            default(),
        ),
        case(
            "profile-dns-datasets-tunnel",
            &profile_dns_datasets(),
            ProjectionMode::Tunnel,
            default(),
        ),
        case(
            "automatic-system-proxy",
            &automatic(),
            ProjectionMode::SystemProxy,
            default(),
        ),
        case(
            "wireguard-system-proxy",
            &wireguard(),
            ProjectionMode::SystemProxy,
            default(),
        ),
    ];
    cases.sort_by_key(|case| case.name);
    cases
}

fn golden_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/goldens")
}

fn actual_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/projection-goldens")
}

/// The projection with its per-process controller secret replaced, in the
/// canonical serialisation, together with the parts of the identity that are
/// not in the JSON.
fn snapshot(case: &Case) -> String {
    let projected = case
        .profile
        .project(PROFILE_ID, case.mode, &case.settings)
        .expect("golden projection");
    let secret = projected.clash_api().expose_secret();
    assert_eq!(
        projected.as_json().matches(secret).count(),
        1,
        "{}",
        case.name
    );
    let config: Value =
        serde_json::from_str(&projected.as_json().replace(secret, SECRET_PLACEHOLDER))
            .expect("projected JSON");
    let probe: Value =
        serde_json::from_str(&projected.proxy_probe_json().expect("probe")).expect("probe JSON");
    let document = json!({
        "config": config,
        "credential_slots": projected.credential_slots(),
        "direct_ipv4_hosts": format!("{:?}", projected.direct_ipv4_hosts()),
        "mode": format!("{:?}", projected.mode()),
        "probe": probe,
    });
    let mut text = serde_json::to_string_pretty(&document).expect("golden text");
    text.push('\n');
    text
}

#[test]
fn switch_off_projections_match_the_goldens_captured_before_geosite_and_mainland_direct() {
    let cases = cases();
    let mut mismatched = Vec::new();
    for case in &cases {
        let actual = snapshot(case);
        let path = golden_directory().join(format!("{}.json", case.name));
        if std::fs::read_to_string(&path).ok().as_deref() != Some(actual.as_str()) {
            let output = actual_directory();
            std::fs::create_dir_all(&output).expect("actual output directory");
            std::fs::write(output.join(format!("{}.json", case.name)), &actual)
                .expect("actual output");
            mismatched.push(case.name);
        }
    }
    let mut stored = std::fs::read_dir(golden_directory())
        .map(|entries| {
            entries
                .map(|entry| {
                    entry
                        .expect("golden entry")
                        .file_name()
                        .into_string()
                        .expect("UTF-8 golden name")
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    stored.sort();
    let mut expected = cases
        .iter()
        .map(|case| format!("{}.json", case.name))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(stored, expected, "no stray or missing golden");
    assert!(
        mismatched.is_empty(),
        "projections differ from the goldens: {mismatched:?}; actual output in {}",
        actual_directory().display()
    );
}
