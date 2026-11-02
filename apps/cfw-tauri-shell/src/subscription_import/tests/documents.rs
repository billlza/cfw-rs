//! How a document is recognized, URI bundles with their limits and unique
//! tags, unsupported schemes, errors that never echo content, and the golden
//! conversions.

use super::*;

#[test]
fn document_classification_is_structural_and_bom_tolerant() {
    assert!(looks_like_clash_yaml("proxies:\n  - name: node\n"));
    assert!(looks_like_clash_yaml("mixed-port: 7890\n"));
    assert!(!looks_like_clash_yaml("# proxies:\nnot-a-document\n"));
    assert!(!looks_like_clash_yaml("metadata:\n  proxies: nested\n"));
    assert!(!looks_like_clash_yaml("note: proxies: is only a value\n"));

    let upstream_json = json!({
        "outbounds": [{
            "type": "shadowsocks",
            "tag": "proxies:",
            "server": "ss.example.com",
            "server_port": 8388,
            "method": "aes-256-gcm",
            "password": "json-secret"
        }]
    });
    let imported = import_subscription_document(&upstream_json.to_string())
        .expect("JSON string containing a Clash marker");
    assert_eq!(imported.credentials[0].secret, "json-secret");

    let uri = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#BOM";
    let imported =
        import_subscription_document(&format!("\u{feff}{uri}")).expect("plain URI bundle with BOM");
    assert_eq!(imported.credentials[0].secret, "secret");

    let encoded = STANDARD.encode(format!("\u{feff}{uri}\n"));
    let imported = import_subscription_document(&encoded).expect("base64 bundle with BOM");
    assert_eq!(imported.credentials[0].secret, "secret");

    let error = import_subscription_document(r#"{"note":"proxies:""#)
        .expect_err("malformed JSON must not fall through to YAML");
    assert_eq!(error, "subscription JSON document is malformed");
}

#[test]
fn imports_base64_uri_bundle_with_shadowsocks_and_trojan() {
    let bundle = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Tokyo\ntrojan://hunter2@trojan.example.com:443?type=grpc&serviceName=tunnel&sni=trojan.example.com#Work";
    let encoded = STANDARD.encode(bundle.as_bytes());
    let imported = import_subscription_document(&encoded).expect("base64 URI bundle");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "shadowsocks");
    assert_eq!(profile["outbounds"][1]["type"], "trojan");
    assert_eq!(imported.credentials.len(), 2);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::ShadowsocksPassword
    );
    assert_eq!(imported.credentials[0].secret, "secret");
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::TrojanPassword
    );
    assert_eq!(imported.credentials[1].secret, "hunter2");
}

#[test]
fn imports_url_safe_padded_base64_uri_bundle() {
    let bundle = "trojan://hunter2@trojan.example.com:443?sni=trojan.example.com#测试\n";
    let encoded = URL_SAFE.encode(bundle.as_bytes());
    assert!(
        encoded.contains('-') || encoded.contains('_'),
        "fixture must exercise the URL-safe alphabet"
    );
    assert!(encoded.ends_with('='), "fixture must exercise padding");

    let imported = import_subscription_document(&encoded).expect("URL-safe padded bundle");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "trojan");
    assert_eq!(profile["outbounds"][0]["tag"], "测试");
    assert_eq!(imported.credentials[0].secret, "hunter2");
}

#[test]
fn uri_bundle_enforces_the_outbound_limit_before_conversion() {
    let entry = "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#Repeated";
    let at_limit = std::iter::repeat_n(entry, cfw_singbox_config::MAX_PROXY_NODES)
        .collect::<Vec<_>>()
        .join("\n");
    let imported = import_subscription_document(&at_limit).expect("URI bundle at limit");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds array");
    assert_eq!(outbounds.len(), cfw_singbox_config::MAX_PROXY_NODES);
    assert_eq!(outbounds[0]["tag"], "Repeated");
    assert_eq!(
        outbounds[cfw_singbox_config::MAX_PROXY_NODES - 1]["tag"],
        format!("Repeated-{}", cfw_singbox_config::MAX_PROXY_NODES)
    );

    let over_limit = format!("{at_limit}\n{entry}");
    let error = import_subscription_document(&over_limit).expect_err("129th URI must fail");
    assert_eq!(
        error,
        format!(
            "subscription URI bundle has more than {} entries",
            cfw_singbox_config::MAX_PROXY_NODES
        )
    );
}

#[test]
fn rejects_unsupported_uri_schemes() {
    let error = import_subscription_document("shadowtls://token@example.com:443#ShadowTLS")
        .expect_err("unsupported scheme");
    assert!(error.contains("unsupported"));
    // The collector refuses on its own what the bundle reader lets through.
    assert_eq!(
        OutboundCollector::default().push_entry("TopSecretValue123://host:443", 0),
        Err("subscription URI scheme is unsupported: <redacted>".into())
    );
}

#[test]
fn a_taken_tag_suffix_is_skipped_and_the_tag_space_is_bounded() {
    let mut collector = OutboundCollector::default();
    assert_eq!(
        collector.unique_tag("Node-2".into()).as_deref(),
        Ok("Node-2")
    );
    assert_eq!(collector.unique_tag("Node".into()).as_deref(), Ok("Node"));
    assert_eq!(collector.unique_tag("Node".into()).as_deref(), Ok("Node-3"));

    let mut collector = OutboundCollector::default();
    for _ in 0..cfw_singbox_config::MAX_OUTBOUNDS {
        collector
            .unique_tag("Node".into())
            .expect("a tag within the limit");
    }
    assert_eq!(
        collector.unique_tag("Node".into()),
        Err(format!(
            "subscription cannot assign a unique outbound tag within the {}-entry limit",
            cfw_singbox_config::MAX_OUTBOUNDS
        ))
    );
}

#[test]
fn uri_bundle_errors_never_echo_line_content() {
    let error = import_subscription_document("not json and not a uri TopSecretValue!")
        .expect_err("unrecognized document");
    assert!(!error.contains("TopSecretValue!"), "{error}");
    assert!(error.contains("subscription line 1"), "{error}");
}

#[test]
fn a_json_document_selects_exactly_one_importer_by_its_root_keys() {
    let clash = import_subscription_document(
        r#"{"proxies":[{"name":"Node","type":"socks5","server":"a.example.com","port":1080}]}"#,
    )
    .expect("Clash in JSON syntax");
    assert_eq!(imported_outbounds(&clash)[0]["tag"], "Node");
    for (document, expected) in [
        (
            r#"{"proxies":[],"outbounds":[]}"#,
            "subscription JSON has ambiguous profile formats",
        ),
        (
            r#"{"proxy-providers":{},"servers":[]}"#,
            "subscription JSON has ambiguous profile formats",
        ),
        (
            r#"{"outbounds":[],"version":1}"#,
            "subscription JSON ambiguously declares sing-box and SIP008 roots",
        ),
        (
            r#"{"metadata":{}}"#,
            "subscription JSON is neither a supported sing-box node list nor SIP008",
        ),
    ] {
        assert_eq!(
            import_subscription_document(document).map(|_| ()),
            Err(expected.into()),
            "{document}"
        );
    }
}

#[test]
fn blank_lines_separate_uri_entries_and_a_blank_document_is_refused() {
    let imported = import_subscription_document(
        "socks5://a.example.com:1080#A\n\n  \nsocks5://b.example.com:1080#B\n",
    )
    .expect("two entries around blank lines");
    assert_eq!(imported_outbounds(&imported).len(), 2);
    assert_eq!(
        import_subscription_document("\n  \n").map(|_| ()),
        Err(
            "subscription document is not a supported sing-box JSON document or supported node URI bundle"
                .into()
        )
    );
}

/// Byte-identity goldens for stored imports, captured on the 0.5 line before
/// Hysteria2 links accepted `pinSHA256` and before every importer emitted its
/// certificate pins through `TlsParts`. A mismatch writes the actual output to
/// `target/tmp/import-goldens/` and fails; the goldens are never rewritten
/// automatically. Secrets appear only as SHA-256 digests.
mod import_goldens {
    use std::path::PathBuf;

    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};

    use super::import_with_stable_references;

    const CASES: &[(&str, &str)] = &[
        (
            "clash-mooring-shape",
            r#"proxies:
  - name: "lon1-reality"
    type: "vless"
    server: "45.67.89.10"
    port: 443
    uuid: "6d6f6f72-0101-4001-8000-000000010101"
    flow: "xtls-rprx-vision"
    packet-encoding: "xudp"
    tls: true
    servername: "www.example.com"
    client-fingerprint: "chrome"
    reality-opts:
      public-key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
      short-id: "0123456789abcdef"
  - name: "lon1-hy2"
    type: "hysteria2"
    server: "45.67.89.10"
    port: 61000
    ports: "61000-62999"
    hop-interval: 30
    password: "Hy2PasswordValue1"
    obfs: "salamander"
    obfs-password: "ObfsPasswordValue1"
    sni: "n0123456789abcdef.internal"
    fingerprint: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
"#,
        ),
        (
            "clash-trojan-colon-fingerprint",
            "proxies:\n  - name: trojan-pinned\n    type: trojan\n    server: trojan.example.com\n    port: 443\n    password: TrojanPasswordValue1\n    sni: trojan.example.com\n    fingerprint: \"FF:FE:FD:FC:FB:FA:F9:F8:F7:F6:F5:F4:F3:F2:F1:F0:EF:EE:ED:EC:EB:EA:E9:E8:E7:E6:E5:E4:E3:E2:E1:E0\"\n",
        ),
        (
            "sing-box-mooring-shape",
            r#"{"outbounds":[
  {"type":"vless","tag":"lon1-reality","server":"45.67.89.10","server_port":443,
   "uuid":"6d6f6f72-0101-4001-8000-000000010101","flow":"xtls-rprx-vision","packet_encoding":"xudp",
   "tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},
          "reality":{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}},
  {"type":"hysteria2","tag":"lon1-hy2","server":"45.67.89.10","server_ports":["61000:62999"],"hop_interval":"30s",
   "password":"Hy2PasswordValue1","obfs":{"type":"salamander","password":"ObfsPasswordValue1"},
   "tls":{"enabled":true,"server_name":"n0123456789abcdef.internal",
          "certificate_public_key_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}}]}"#,
        ),
        (
            "sing-box-der-pins",
            r#"{"outbounds":[
  {"type":"hysteria2","tag":"hy2-pinned","server":"hy2.example.com","server_port":443,"password":"Hy2PasswordValue2",
   "tls":{"enabled":true,"server_name":"hy2.example.com",
          "certificate_sha256":["//////////////////////////////////////////8=","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}},
  {"type":"trojan","tag":"trojan-pinned","server":"trojan.example.com","server_port":443,"password":"TrojanPasswordValue2",
   "tls":{"enabled":true,"server_name":"trojan.example.com",
          "certificate_sha256":["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}}]}"#,
        ),
        (
            "uri-bundle",
            "hy2://Hy2PasswordValue3@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=ObfsPasswordValue3#HY2\n\
hysteria2://Hy2PasswordValue4@hop.example.com:443,5000-5002?sni=hop.example.com&hop-interval=30#HOP\n\
vless://6d6f6f72-0101-4001-8000-000000010102@vless.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&flow=xtls-rprx-vision&type=tcp#VLESS\n\
trojan://TrojanPasswordValue3@trojan.example.com:443?sni=trojan.example.com#TROJAN\n",
        ),
    ];

    fn golden_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/subscription_import/goldens")
    }

    fn actual_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/import-goldens")
    }

    fn snapshot(document: &str) -> String {
        let imported = import_with_stable_references(document);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("stored profile");
        let credentials = imported
            .credentials
            .iter()
            .map(|credential| {
                json!({
                    "id": credential.reference.id(),
                    "kind": credential.reference.kind(),
                    "secret_sha256": Sha256::digest(credential.secret.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                })
            })
            .collect::<Vec<_>>();
        let mut text = serde_json::to_string_pretty(&json!({
            "credentials": credentials,
            "digest": imported.profile.digest(),
            "profile": profile,
        }))
        .expect("golden text");
        text.push('\n');
        text
    }

    #[test]
    fn stored_imports_match_the_goldens_captured_before_link_pins() {
        let mut mismatched = Vec::new();
        for (name, document) in CASES {
            let actual = snapshot(document);
            let path = golden_directory().join(format!("{name}.json"));
            if std::fs::read_to_string(&path).ok().as_deref() != Some(actual.as_str()) {
                let output = actual_directory();
                std::fs::create_dir_all(&output).expect("actual output directory");
                std::fs::write(output.join(format!("{name}.json")), &actual)
                    .expect("actual output");
                mismatched.push(*name);
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
        let mut expected = CASES
            .iter()
            .map(|(name, _)| format!("{name}.json"))
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(stored, expected, "no stray or missing golden");
        assert!(
            mismatched.is_empty(),
            "stored imports differ from the goldens: {mismatched:?}; actual output in {}",
            actual_directory().display()
        );
    }
}
