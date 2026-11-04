//! Resolvers: encrypted bootstrap, domain-named resolvers, TLS reports and
//! resource bounds.

use super::*;

#[test]
fn encrypted_bootstrap_remains_encrypted_and_cannot_depend_on_itself_or_a_proxy() {
    let mut input = source();
    input["dns"]["bootstrap_servers"] = json!([{"type":"https","server":"1.1.1.1","server_port":443,"path":"/dns-query","tls":{"enabled":true,"server_name":"cloudflare-dns.com"}}]);
    let output = project(&input, ProjectionMode::LocalProxy);
    let bootstrap = &output["dns"]["servers"][0];
    assert_eq!(bootstrap["type"], "https");
    assert_eq!(bootstrap["tls"]["server_name"], "cloudflare-dns.com");
    assert!(bootstrap.get("detour").is_none());
    assert!(bootstrap.get("domain_resolver").is_none());
    assert_eq!(
        output["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|server| server["tag"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("cfw-bootstrap")))
            .count(),
        1
    );
    input["dns"]["bootstrap_servers"][0]["server"] = json!("cloudflare-dns.com");
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    input["dns"]["bootstrap_servers"][0]["server"] = json!("1.1.1.1");
    input["dns"]["bootstrap_servers"][0]["route"] = json!("selected");
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
}

#[test]
fn domain_named_resolvers_have_explicit_acyclic_bootstrap_and_authenticated_tls() {
    for kind in ["tls", "quic", "https", "h3"] {
        let mut input = source();
        let mut resolver = json!({"type":kind,"server":"dns.example.org","server_port":853,"tls":{"enabled":true,"server_name":"dns.example.org"}});
        if matches!(kind, "https" | "h3") {
            resolver["path"] = json!("/dns-query");
        }
        input["dns"]["servers"] = json!([resolver]);
        let projected = project(&input, ProjectionMode::LocalProxy);
        let resolver = projected["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|server| server["tag"] == "cfw-profile-dns-0")
            .unwrap();
        assert_eq!(resolver["server"], "dns.example.org");
        assert_eq!(
            resolver["domain_resolver"],
            json!({"server":"cfw-bootstrap-dns-0"})
        );
        assert_eq!(resolver["tls"]["server_name"], "dns.example.org");
        assert!(resolver["tls"].get("insecure").is_none());
        input["dns"]
            .as_object_mut()
            .unwrap()
            .remove("bootstrap_servers");
        assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
        input["dns"]["bootstrap_servers"] = json!(["dns.example.org"]);
        assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
        input["dns"]["bootstrap_servers"] = json!(["1.1.1.1"]);
        input["dns"]["servers"][0]["tls"]["insecure"] = json!(true);
        assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    }
}

#[test]
fn encrypted_dns_reports_standard_tls_before_utls_or_reality_details() {
    let utls = json!({"enabled":true,"fingerprint":"chrome"});
    let reality = json!({"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"});
    for kind in ["tls", "quic", "https", "h3"] {
        for extensions in [
            vec![("utls", &utls)],
            vec![("reality", &reality)],
            vec![("utls", &utls), ("reality", &reality)],
        ] {
            let mut input = source();
            let mut resolver = json!({"type":kind,"server":"1.1.1.1","server_port":853,"tls":{"enabled":true,"server_name":"cloudflare-dns.com"}});
            if matches!(kind, "https" | "h3") {
                resolver["path"] = json!("/dns-query");
            }
            for (key, value) in &extensions {
                resolver["tls"][key] = (*value).clone();
            }
            input["dns"]["servers"] = json!([resolver]);
            assert_eq!(
                ValidatedSingBoxProfile::parse(&input.to_string()),
                Err(ConfigError::UnsupportedPolicyShape {
                    path: "$.dns".into(),
                    reason: "encrypted DNS requires authenticated standard TLS".into(),
                }),
                "{kind} with {extensions:?}"
            );
        }
    }
}

#[test]
fn dns_filters_and_resource_bounds_are_enforced_without_discarding_resolvers() {
    let mut input = source();
    input["dns"]["fallback_servers"] = json!([{"type":"tcp","server":"8.8.4.4","server_port":53}]);
    input["dns"]["fallback_filter"] =
        json!({"domain":["+.fallback.example"],"ip_cidr":["240.0.0.0/4"]});
    input["dns"]["servers"].as_array_mut().unwrap().truncate(1);
    let projected = project(&input, ProjectionMode::LocalProxy);
    if let Ok(directory) = std::env::var("CFW_DNS_PROJECTED_FIXTURE_DIR") {
        std::fs::create_dir_all(&directory).expect("fixture directory");
        std::fs::write(
            std::path::Path::new(&directory).join("filter.json"),
            serde_json::to_vec_pretty(&projected).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(projected["dns"]["final"], "cfw-fallback-dns-0");
    let filter = projected["dns"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["server"] == "cfw-profile-dns-0" && rule.get("response_filter").is_some())
        .unwrap();
    assert_eq!(filter["action"], "evaluate");
    assert_eq!(filter["response_ip_accept_all"], true);
    assert_eq!(
        filter["response_filter"]["rules"][1],
        json!({"ip_cidr":["240.0.0.0/4"],"invert":true})
    );
    input["dns"]["fallback_filter"]["ip_cidr"] = json!(["1.1.1.1/99"]);
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    input = source();
    input["dns"]["bootstrap_servers"] = json!([]);
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    input["dns"]["bootstrap_servers"] = json!(["1.1.1.1", "1.1.1.1"]);
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
    input["dns"]["bootstrap_servers"] = json!([
        "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7", "8.8.8.8",
        "9.9.9.9"
    ]);
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
}
