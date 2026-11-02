//! Clash groups and rules: process, GeoIP and GeoSite rules, automatic
//! groups, detours, and fallback order.

use super::*;

#[test]
fn clash_import_preserves_groups_process_geoip_and_ordered_rules() {
    let source = r#"
proxies:
  - {name: Node A, type: socks5, server: edge.example.com, port: 1080}
  - {name: Node B, type: socks5, server: backup.example.com, port: 1080}
proxy-groups:
  - {name: PROXY, type: select, proxies: [Node A, Node B, DIRECT]}
rules:
  - PROCESS-NAME,Example Client,PROXY
  - DOMAIN-SUFFIX,example.com,PROXY
  - IP-CIDR,192.0.2.1/32,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(source).expect("complete Clash policy");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(profile["outbounds"][3]["tag"], "PROXY");
    assert_eq!(
        profile["outbounds"][3]["outbounds"],
        json!(["Node A", "Node B", "DIRECT"])
    );
    assert_eq!(profile["route"]["final"], "PROXY");
    assert_eq!(
        profile["route"]["rules"].as_array().expect("rules").len(),
        4
    );
    assert_eq!(profile["route"]["rules"][0]["type"], "process_name");
    assert_eq!(profile["route"]["rules"][2]["no_resolve"], true);
    assert_eq!(profile["route"]["rules"][3]["type"], "geo_ip");
    for broken in [
        source.replace("[Node A, Node B, DIRECT]", "[Node A, absent]"),
        source.replace("[Node A, Node B, DIRECT]", "[PROXY]"),
        source.replace("GEOIP,CN,DIRECT", "UNKNOWN,CN,DIRECT"),
        source.replace("type: select", "type: unsupported"),
    ] {
        assert!(
            import_subscription_document(&broken).is_err(),
            "invalid policy cannot become nodes-only import"
        );
    }
}

#[test]
fn clash_automatic_groups_and_detours_keep_their_source_semantics() {
    let source = "proxies:\n  - {name: Entry, type: socks5, server: entry.example.com, port: 1080}\n  - {name: Exit, type: socks5, server: exit.example.com, port: 1080, dialer-proxy: Entry}\nproxy-groups:\n  - {name: Auto, type: url-test, proxies: [Exit, Entry], url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 150}\nrules:\n  - MATCH,Auto\n";
    let imported = import_subscription_document(source).expect("automatic and multihop");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(profile["outbounds"][2]["type"], "urltest");
    assert_eq!(profile["outbounds"][2]["tolerance_ms"], 150);
    assert_eq!(profile["outbounds"][2]["interval_seconds"], 300);
    assert_eq!(profile["detours"]["Exit"], "Entry");
    for bad in [
        source.replace("interval: 300", "interval: 0"),
        source.replace("dialer-proxy: Entry", "dialer-proxy: Auto"),
        source.replace("type: url-test", "type: fallback"),
    ] {
        assert!(import_subscription_document(&bad).is_err());
    }
}

#[test]
fn clash_fallback_preserves_order_and_rejects_latency_selection_fields() {
    let source = "proxies:\n  - {name: Primary, type: socks5, server: primary.example.com, port: 1080}\n  - {name: Backup, type: socks5, server: backup.example.com, port: 1080}\nproxy-groups:\n  - {name: Failover, type: fallback, proxies: [Primary, Backup], url: 'https://example.com/probe', interval: 300}\nrules:\n  - MATCH,Failover\n";
    let imported = import_subscription_document(source).unwrap();
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert_eq!(profile["outbounds"][2]["type"], "fallback");
    assert_eq!(
        profile["outbounds"][2]["outbounds"],
        json!(["Primary", "Backup"])
    );
    assert!(profile["outbounds"][2].get("tolerance_ms").is_none());
    assert!(
        import_subscription_document(
            &source.replace("interval: 300", "interval: 300, tolerance: 50")
        )
        .is_err()
    );
    assert!(
        import_subscription_document(&source.replace("[Primary, Backup]", "[Failover]")).is_err()
    );
}

#[test]
fn clash_geosite_rules_import_as_lowercase_dataset_rules() {
    let source = r#"
proxies:
  - {name: Node A, type: socks5, server: edge.example.com, port: 1080}
proxy-groups:
  - {name: PROXY, type: select, proxies: [Node A, DIRECT]}
rules:
  - GEOSITE,Geolocation-!CN,PROXY
  - GEOSITE,CN,DIRECT
  - GEOSITE,google@!cn,PROXY
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"#;
    let imported = import_subscription_document(source).expect("GEOSITE policy");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(
        profile["route"]["rules"],
        json!([
            {"type":"geo_site","value":"geolocation-!cn","outbound":"PROXY","no_resolve":false},
            {"type":"geo_site","value":"cn","outbound":"DIRECT","no_resolve":false},
            {"type":"geo_site","value":"google@!cn","outbound":"PROXY","no_resolve":false},
            {"type":"geo_ip","value":"CN","outbound":"DIRECT","no_resolve":false}
        ])
    );
    let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
    assert_eq!(
        runtime["route"]["rule_set"]
            .as_array()
            .expect("rule sets")
            .iter()
            .map(|resource| resource["tag"].clone())
            .collect::<Vec<_>>(),
        [
            json!("cfw-geoip-cn"),
            json!("cfw-geosite-cn"),
            json!("cfw-geosite-geolocation-!cn"),
            json!("cfw-geosite-google@!cn")
        ]
    );
    for (broken, expected) in [
        ("GEOSITE,CN,DIRECT,no-resolve", "no_resolve is only valid"),
        (
            "GEOSITE,../cn,DIRECT",
            "rule value does not match its declared type",
        ),
        (
            "GEOSITE,a@b@c,DIRECT",
            "rule value does not match its declared type",
        ),
    ] {
        let error = import_subscription_document(&source.replace("GEOSITE,CN,DIRECT", broken))
            .expect_err(broken);
        assert!(error.contains(expected), "{broken}: {error}");
    }
}
