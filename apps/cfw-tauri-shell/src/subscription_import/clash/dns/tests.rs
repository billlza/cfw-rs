use super::resolver;
use crate::subscription_import::import_subscription_document;
use serde_json::{Value, json};

const SOURCE: &str = r#"
proxies:
  - {name: example, type: socks5, server: node.example.com, port: 1080}
hosts:
  node.example.com: 9.9.9.9
dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: ['+.lan', '*.local', localhost, '+.example.com']
  default-nameserver: [8.8.8.8, 1.1.1.1]
  nameserver: [https://8.8.8.8/dns-query, https://1.1.1.1/dns-query]
"#;

#[test]
fn cfw_dns_hosts_and_fake_ip_policy_survive_import() {
    let imported = import_subscription_document(SOURCE).expect("Clash import");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile JSON");
    assert_eq!(profile["hosts"], json!({"node.example.com":["9.9.9.9"]}));
    assert_eq!(profile["dns"]["ipv6"], false);
    assert_eq!(
        profile["dns"]["bootstrap_servers"],
        json!(["8.8.8.8", "1.1.1.1"])
    );
    assert_eq!(
        profile["dns"]["servers"][0]["tls"]["server_name"],
        "8.8.8.8"
    );
    assert_eq!(
        profile["dns"]["fake_ip"]["exclude"],
        json!(["+.lan", "*.local", "localhost", "+.example.com"])
    );
    assert!(imported.credentials.is_empty());
}

#[test]
fn clash_routed_and_direct_dns_compose_without_changing_bootstrap() {
    let text = format!(
        "{SOURCE}\n  respect-rules: true\n  proxy-server-nameserver: [223.5.5.5]\n  direct-nameserver: [119.29.29.29]\n  direct-nameserver-follow-policy: true\n  nameserver-policy: {{'+.example.org': 1.1.1.1}}\n"
    );
    let imported = import_subscription_document(&text).unwrap();
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert_eq!(profile["dns"]["servers"][0]["route"], "rules");
    assert_eq!(profile["dns"]["direct_servers"][0]["route"], "rules");
    assert_eq!(profile["dns"]["proxy_servers"][0]["route"], "direct");
    assert_eq!(
        profile["dns"]["nameserver_policy"][0]["servers"][0]["route"],
        "rules"
    );
    assert_eq!(profile["dns"]["direct_follow_policy"], true);
    assert!(
        import_subscription_document(&text.replace("  proxy-server-nameserver: [223.5.5.5]\n", ""))
            .is_err()
    );
    assert_eq!(
        super::resolver_with_route("https://1.1.1.1/dns-query#DIRECT", true).unwrap()["route"],
        "direct"
    );
}

#[test]
fn disabled_profile_hosts_do_not_reject_ignored_entries() {
    let source = SOURCE.replace(
        "node.example.com: 9.9.9.9",
        "node.example.com: {ignored: true}",
    );
    let imported = import_subscription_document(&format!(
        "{source}\n  use-hosts: false\n  use-system-hosts: true\n"
    ))
    .unwrap();
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert!(profile.get("hosts").is_none());
    assert_eq!(profile["dns"]["use_system_hosts"], true);
}

#[test]
fn dns_policy_is_never_silently_dropped() {
    for extra in [
        "  nameserver-policy: {'geosite:../cn': 1.1.1.1}",
        "  prefer-h3: true",
    ] {
        assert!(import_subscription_document(&format!("{SOURCE}\n{extra}\n")).is_err());
    }
    for (old, new) in [
        ("enable: true", "enable: false"),
        ("198.18.0.1/16", "10.0.0.0/8"),
        (
            "https://8.8.8.8/dns-query",
            "https://user:secret@8.8.8.8/dns-query",
        ),
    ] {
        assert!(import_subscription_document(&SOURCE.replace(old, new)).is_err());
    }
}
#[test]
fn domain_dns_and_separate_roles_are_imported_with_explicit_bootstrap() {
    let source = SOURCE.replace("default-nameserver: [8.8.8.8, 1.1.1.1]", "default-nameserver: [8.8.8.8]")
        .replace("nameserver: [https://8.8.8.8/dns-query, https://1.1.1.1/dns-query]", "nameserver: [https://dns.example.com/dns-query, tls://one.example.com, quic://two.example.com, h3://three.example.com/dns-query]");
    let source = format!(
        "{source}\n  nameserver-policy: {{'+.internal.example': '10.0.0.53', 'exact.example': [1.1.1.1, 8.8.8.8, 9.9.9.9]}}\n  proxy-server-nameserver: [223.5.5.5]\n  direct-nameserver: [119.29.29.29]\n"
    );
    let imported = import_subscription_document(&source).expect("DNS roles");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert_eq!(profile["dns"]["servers"][0]["server"], "dns.example.com");
    assert_eq!(
        profile["dns"]["servers"][0]["tls"]["server_name"],
        "dns.example.com"
    );
    assert_eq!(
        profile["dns"]["nameserver_policy"][1]["servers"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(profile["dns"]["proxy_servers"][0]["server"], "223.5.5.5");
    assert_eq!(
        profile["dns"]["direct_servers"][0]["server"],
        "119.29.29.29"
    );
    assert!(
        import_subscription_document(&source.replace("  default-nameserver: [8.8.8.8]\n", ""))
            .is_err()
    );
    assert!(
        import_subscription_document(&source.replace(
            "default-nameserver: [8.8.8.8]",
            "default-nameserver: [dns.example.com]"
        ))
        .is_err()
    );
}

#[test]
fn clash_fallback_filter_semantics_are_retained_or_explicitly_rejected() {
    let source = format!(
        "{SOURCE}\n  fallback: [8.8.4.4]\n  fallback-filter:\n    geoip: false\n    domain: ['+.fallback.example']\n    ipcidr: ['240.0.0.0/4']\n"
    );
    let imported = import_subscription_document(&source).expect("explicit supported filter");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
    assert_eq!(
        profile["dns"]["fallback_filter"]["ip_cidr"],
        json!(["240.0.0.0/4"])
    );
    let geoip =
        import_subscription_document(&source.replace("geoip: false", "geoip: true")).unwrap();
    let geoip: Value = serde_json::from_str(geoip.profile.as_json()).unwrap();
    assert_eq!(geoip["dns"]["fallback_filter"]["geoip_code"], "cn");
    let implicit =
        import_subscription_document(&format!("{SOURCE}\n  fallback: [8.8.4.4]\n")).unwrap();
    let implicit: Value = serde_json::from_str(implicit.profile.as_json()).unwrap();
    assert_eq!(implicit["dns"]["fallback_filter"]["geoip_code"], "cn");
    let geosite = import_subscription_document(&format!("{source}    geosite: [cn]\n")).unwrap();
    let geosite: Value = serde_json::from_str(geosite.profile.as_json()).unwrap();
    assert_eq!(geosite["dns"]["fallback_filter"]["geosite"], json!(["cn"]));
    for suffix in ["#skip-cert-verify", "#proxy", "?insecure=true"] {
        assert!(resolver(&format!("https://dns.example.com/dns-query{suffix}")).is_err());
    }
}
