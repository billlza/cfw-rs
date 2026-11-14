//! Fixtures shared by the tests of the Tunnel-only switches: DNS leak
//! protection and WebRTC leak protection.

use serde_json::{Value, json};

use crate::validation::DnsProjection;
use crate::{
    EngineSettings, ProjectionMode, ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase,
    ValidatedSingBoxProfile,
};

pub(super) const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SECRET_PLACEHOLDER: &str = "<CLASH-API-SECRET>";

/// The plain DNS hijack every Tunnel projection starts with.
pub(super) fn hijack() -> Value {
    json!({"port":53,"action":"hijack-dns"})
}

fn parse(value: &Value) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&value.to_string()).expect("switch test profile")
}

pub(super) fn shadowsocks() -> ValidatedSingBoxProfile {
    parse(
        &json!({"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"ss.example.com","server_port":443,
        "method":"aes-256-gcm","credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"shadowsocks_password"}}],
        "route":{"final":"proxy"}}),
    )
}

/// A profile with rules of its own whose final group is set to DIRECT: the
/// switches do not depend on the route, unlike mainland China direct.
fn policy_selected_direct() -> ValidatedSingBoxProfile {
    parse(&json!({"outbounds":[
            {"type":"socks5","tag":"Node","server":"proxy.example.com","server_port":1080},
            {"type":"direct","tag":"DIRECT"},
            {"type":"selector","tag":"PROXY","outbounds":["Node","DIRECT"]}],
        "route":{"final":"PROXY","rules":[
            {"type":"domain_suffix","value":"example.com","outbound":"PROXY"},
            {"type":"geo_ip","value":"LAN","outbound":"DIRECT"}]}}))
    .with_selected_outbound("PROXY", "DIRECT")
    .expect("DIRECT selection")
}

pub(super) fn profiles() -> Vec<(&'static str, ValidatedSingBoxProfile)> {
    vec![
        ("built-in direct", ValidatedSingBoxProfile::direct()),
        ("shadowsocks", shadowsocks()),
        ("selector set to DIRECT", policy_selected_direct()),
    ]
}

/// The projected runtime with its per-process controller secret replaced,
/// so two projections of one profile compare equal everywhere else.
pub(super) fn runtime(
    profile: &ValidatedSingBoxProfile,
    mode: ProjectionMode,
    settings: &EngineSettings,
) -> Value {
    let projected = profile
        .project(PROFILE_ID, mode, settings)
        .expect("projection");
    serde_json::from_str(
        &projected
            .as_json()
            .replace(projected.clash_api().expose_secret(), SECRET_PLACEHOLDER),
    )
    .expect("runtime JSON")
}

pub(super) fn without_route_rules(mut value: Value) -> Value {
    value["route"]
        .as_object_mut()
        .expect("route object")
        .remove("rules");
    value
}

/// Whether any leaf of the document equals `leaf`. Leaves compare whole: a
/// text search would also match the per-process controller secret, 64 random
/// hex characters, whenever it happens to contain the digits of a port.
pub(super) fn carries(value: &Value, leaf: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| carries(item, leaf)),
        Value::Object(fields) => fields.values().any(|field| carries(field, leaf)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value == leaf,
    }
}

#[test]
fn carries_compares_whole_leaves() {
    let secret = format!("853{}", "0".repeat(61));
    let document = json!({
        "route": {"rules": [{"port": 853, "action": "reject"}]},
        "experimental": {"clash_api": {"secret": secret}}
    });
    assert!(carries(&document, &json!(853)));
    assert!(carries(&document, &json!("reject")));
    assert!(carries(&document, &json!(secret.as_str())));
    assert!(!carries(&document, &json!("853")));
    assert!(!carries(&document, &json!(53)));
    let secret_only = json!({"experimental": {"clash_api": {"secret": secret}}});
    assert!(!carries(&secret_only, &json!(853)));
    assert!(!carries(&secret_only, &json!("853")));
}

/// The projections no Tunnel-only switch may change: the proxy modes of every
/// profile, and every release evidence projection.
pub(super) fn switch_free_projections()
-> Vec<(&'static str, ValidatedSingBoxProfile, ProjectionMode)> {
    let mut cases = Vec::new();
    for (label, profile) in profiles() {
        for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
            cases.push((label, profile.clone(), mode));
        }
    }
    for case in [
        ReleaseDnsEvidenceCase::PrimaryIpv4,
        ReleaseDnsEvidenceCase::PrimaryIpv6,
        ReleaseDnsEvidenceCase::SecondaryIpv4,
        ReleaseDnsEvidenceCase::SecondaryIpv6,
    ] {
        cases.push((
            "release DNS evidence",
            ValidatedSingBoxProfile::release_dns_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    for case in ReleasePacketEvidenceCase::ALL {
        cases.push((
            "release packet evidence",
            ValidatedSingBoxProfile::release_packet_evidence(case),
            ProjectionMode::Tunnel,
        ));
    }
    // Evidence projections of a profile that routes through a proxy, as the
    // mainland switch's test covers them.
    let mut dns_evidence = shadowsocks();
    dns_evidence.dns_projection =
        DnsProjection::ReleaseEvidence(ReleaseDnsEvidenceCase::PrimaryIpv4);
    cases.push(("proxied DNS evidence", dns_evidence, ProjectionMode::Tunnel));
    let mut packet_evidence = shadowsocks();
    packet_evidence.release_packet_evidence_case = Some(ReleasePacketEvidenceCase::TcpIpv4);
    cases.push((
        "proxied packet evidence",
        packet_evidence,
        ProjectionMode::Tunnel,
    ));
    cases
}
