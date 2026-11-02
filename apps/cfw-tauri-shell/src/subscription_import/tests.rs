use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use cfw_singbox_config::{CredentialKind, EngineSettings, ProjectionMode};
use serde_json::json;

use super::collector::credential_kind_discriminant;
use super::*;

const SYNTHETIC_VM_UUID: &str = "00000000-0000-4000-8000-000000000001";
const SYNTHETIC_PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn vmess_uri_with_aid(aid: Option<Value>) -> String {
    let mut payload = json!({
        "ps": "Synthetic VMess",
        "add": "vmess.example.com",
        "port": 443,
        "id": SYNTHETIC_VM_UUID,
    });
    if let Some(aid) = aid {
        payload
            .as_object_mut()
            .expect("VMess fixture payload must be an object")
            .insert("aid".into(), aid);
    }
    format!("vmess://{}", STANDARD.encode(payload.to_string()))
}

fn clash_vmess_with_alter_id(value: Option<&str>) -> String {
    let alter_id = value
        .map(|value| format!("    alterId: {value}\n"))
        .unwrap_or_default();
    format!(
        "proxies:\n  - name: Synthetic VMess\n    type: vmess\n    server: vmess.example.com\n    port: 443\n    uuid: {SYNTHETIC_VM_UUID}\n{alter_id}"
    )
}

fn assert_single_vmess_alter_id(document: &str, expected: u8) {
    let imported = import_subscription_document(document).expect("valid VMess fixture");
    assert_eq!(imported.credentials.len(), 1);
    let profile: Value =
        serde_json::from_str(imported.profile.as_json()).expect("canonical profile JSON");
    let outbound = &profile["outbounds"][0];
    assert_eq!(outbound["type"], "vmess");
    if expected == 0 {
        assert!(
            outbound.get("alter_id").is_none(),
            "AEAD alter_id must remain the omitted canonical default"
        );
    } else {
        assert_eq!(outbound["alter_id"], expected);
    }

    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("runtime VMess projection");
    let runtime: Value =
        serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
    let runtime_vmess = runtime["outbounds"]
        .as_array()
        .expect("runtime outbounds")
        .iter()
        .find(|outbound| outbound["type"] == "vmess")
        .expect("runtime VMess outbound");
    if expected == 0 {
        assert!(
            runtime_vmess.get("alter_id").is_none(),
            "AEAD runtime alter_id must remain omitted"
        );
    } else {
        assert_eq!(runtime_vmess["alter_id"], expected);
    }
}

fn synthetic_46_node_clash_fixture() -> String {
    let mut document = String::from("proxies:\n");
    for index in 0..34_u16 {
        writeln!(
            document,
            "  - name: SS-{index:02}\n    type: ss\n    server: ss-{index:02}.example.com\n    port: {}\n    cipher: aes-256-gcm\n    password: synthetic-ss-secret-{index:02}",
            10_000 + index
        )
        .expect("write synthetic Shadowsocks fixture");
    }
    for index in 0..12_u16 {
        writeln!(
            document,
            "  - name: VMess-{index:02}\n    type: vmess\n    server: vmess-{index:02}.example.com\n    port: 443\n    uuid: 00000000-0000-4000-8000-{index:012x}\n    alterId: 1\n    cipher: auto"
        )
        .expect("write synthetic VMess fixture");
    }
    document
}

const GLOBAL_FINGERPRINT_NAMESPACE: &str = "cccccccc-cccc-5ccc-8ccc-cccccccccccc";

/// One Clash proxy of every type Mihomo before v1.19.27 gave its
/// `global-client-fingerprint`: TLS VMess, VLESS with and without Reality,
/// Trojan and AnyTLS. `fingerprint` is inserted into each entry verbatim.
fn clash_tls_stream_proxies(fingerprint: &str) -> String {
    const PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
    format!(
        "proxies:
  - name: VMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    network: ws
{fingerprint}  - name: VLESS
    type: vless
    server: vless.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    tls: true
{fingerprint}  - name: Reality
    type: vless
    server: reality.example.com
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    tls: true
    servername: www.example.com
{fingerprint}    reality-opts:
      public-key: {PUBLIC_KEY}
      short-id: 0123456789abcdef
  - name: Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: TopSecretValue!
{fingerprint}  - name: AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: TopSecretValue!
{fingerprint}"
    )
}

fn import_with_stable_references(document: &str) -> ImportedSubscription {
    import_subscription_document_with_credential_namespace(
        document,
        GLOBAL_FINGERPRINT_NAMESPACE.parse().expect("namespace"),
    )
    .expect("Clash import")
}

fn imported_outbounds(imported: &ImportedSubscription) -> Vec<Value> {
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    profile["outbounds"].as_array().expect("outbounds").clone()
}

fn projected_json(imported: &ImportedSubscription) -> String {
    imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::SystemProxy,
            &EngineSettings::default(),
        )
        .expect("runtime projection")
        .as_json()
        .to_owned()
}

const ASCENDING_PIN_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ASCENDING_PIN_BASE64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

mod clash_nodes;
mod clash_refusals;
mod clash_routing;
mod clash_transports;
mod client_fingerprints;
mod credential_references;
mod documents;
mod hysteria2_links;
mod shadowsocks_links;
mod share_links;
mod shared_helpers;
mod sing_box_lists;
mod sing_box_options;
mod vmess_links;
