use crate::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use serde_json::{Value, json};
const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn source() -> Value {
    json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080},{"type":"direct","tag":"direct"}],
        "route":{"final":"proxy","rules":[{"type":"domain","value":"direct.example.com","outbound":"direct"}]},
        "dns":{"servers":[{"type":"tcp","server":"1.1.1.1","server_port":53},{"type":"tcp","server":"8.8.8.8","server_port":53},{"type":"tcp","server":"9.9.9.9","server_port":53}],
        "bootstrap_servers":["223.5.5.5"],
        "nameserver_policy":[{"domain":"+.example.org","servers":[{"type":"tcp","server":"223.6.6.6","server_port":53}]},{"domain":"special.example.org","servers":[{"type":"tcp","server":"119.29.29.29","server_port":53}]}],
        "proxy_servers":[{"type":"tcp","server":"180.76.76.76","server_port":53}],
        "direct_servers":[{"type":"tcp","server":"114.114.114.114","server_port":53}]}})
}
fn project(value: &Value, mode: ProjectionMode) -> Value {
    let profile =
        ValidatedSingBoxProfile::parse(&value.to_string()).expect("validated DNS profile");
    serde_json::from_str(
        profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("projected DNS policy")
            .as_json(),
    )
    .expect("JSON")
}

#[test]
fn named_dns_roles_preserve_policy_precedence_and_transport_routing() {
    let mut input = source();
    input["dns"]["direct_follow_policy"] = json!(true);
    input["dns"]["proxy_server_policy"] = json!([{"domain":"+.node.example","servers":[{"type":"udp","server":"223.6.6.6","server_port":53,"route":"direct"}]}]);
    input["dns"]["servers"][0]["route"] = json!("rules");
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(
        output["outbounds"][0]["domain_resolver"],
        json!({"policy":"cfw-proxy-endpoint"})
    );
    assert_eq!(
        output["outbounds"][1]["domain_resolver"],
        json!({"policy":"cfw-direct"})
    );
    let policies = output["dns"]["policies"].as_array().unwrap();
    let direct = policies
        .iter()
        .find(|policy| policy["tag"] == "cfw-direct")
        .unwrap();
    assert_eq!(direct["rules"][0]["domain"], "special.example.org");
    assert_eq!(direct["rules"][1]["domain_suffix"], "example.org");
    assert_eq!(
        direct["rules"].as_array().unwrap().last().unwrap()["server"],
        "cfw-direct-dns-0"
    );
    let routed = output["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|server| server["tag"] == "cfw-profile-dns-0")
        .unwrap();
    assert_eq!(routed["respect_rules"], true);
    assert!(routed.get("detour").is_none());
    if let Ok(directory) = std::env::var("CFW_DNS_PROJECTED_FIXTURE_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        input["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"domain","value":"direct.example.org","outbound":"direct"}));
        let fixture = project(&input, ProjectionMode::LocalProxy);
        std::fs::write(
            std::path::Path::new(&directory).join("named.json"),
            serde_json::to_vec_pretty(&fixture).unwrap(),
        )
        .unwrap();
    }
    input["dns"]
        .as_object_mut()
        .unwrap()
        .remove("proxy_servers");
    input["dns"]
        .as_object_mut()
        .unwrap()
        .remove("proxy_server_policy");
    assert!(
        ValidatedSingBoxProfile::parse(&input.to_string())
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
}

#[test]
fn dns_dataset_selectors_project_shared_resources_and_keep_source_order() {
    let mut input = source();
    input["dns"]["nameserver_policy"] = json!([
        {"domain":"+.example.org","servers":[{"type":"tcp","server":"1.1.1.1","server_port":53}]},
        {"domain":"geosite:cn","servers":[{"type":"tcp","server":"223.5.5.5","server_port":53}]},
        {"domain":"special.example.org","servers":[{"type":"tcp","server":"9.9.9.9","server_port":53}]}
    ]);
    input["dns"]["fallback_servers"] = json!([{"type":"udp","server":"8.8.4.4","server_port":53}]);
    input["dns"]["fallback_filter"] = json!({"geoip_code":"cn","geosite":["geolocation-!cn"]});
    input["dns"]["fake_ip"] = json!({"exclude":["geosite:cn"]});
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(output["dns"]["rules"][0]["domain_suffix"], "example.org");
    assert_eq!(
        output["dns"]["rules"][1]["rule_set"],
        json!(["cfw-geosite-cn"])
    );
    assert_eq!(output["dns"]["rules"][2]["domain"], "special.example.org");
    let resources = output["route"]["rule_set"].as_array().unwrap();
    assert_eq!(resources.len(), 3);
    assert_eq!(
        resources
            .iter()
            .filter(|resource| resource["tag"] == "cfw-geosite-cn")
            .count(),
        1
    );
    assert!(
        output["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["response_ip_accept_all"] == true)
    );
    assert!(output["experimental"]["cache_file"]["enabled"] == true);
    input["dns"]["fallback_filter"]["geoip_code"] = json!("../cn");
    assert!(ValidatedSingBoxProfile::parse(&input.to_string()).is_err());
}

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
fn dns_pools_and_policies_keep_distinct_runtime_roles_for_every_entry_point() {
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let value = project(&source(), mode);
        assert_eq!(
            value["route"]["default_domain_resolver"],
            json!({"policy":"default"})
        );
        assert_eq!(
            value["outbounds"][0]["domain_resolver"],
            json!({"server":"cfw-proxy-server-dns-0"})
        );
        assert_eq!(
            value["outbounds"][1]["domain_resolver"],
            json!({"server":"cfw-direct-dns-0"})
        );
        assert_eq!(value["dns"]["rules"][0]["domain"], "special.example.org");
        assert_eq!(value["dns"]["rules"][1]["domain_suffix"], "example.org");
        for resolver in value["dns"]["servers"].as_array().expect("DNS servers") {
            let tag = resolver["tag"].as_str().expect("DNS tag");
            if tag.starts_with("cfw-profile-dns") || tag.starts_with("cfw-policy-dns") {
                assert_eq!(resolver["detour"], "proxy");
            } else {
                assert!(resolver.get("detour").is_none());
            }
        }
        let rules = value["route"]["rules"].as_array().expect("route rules");
        let direct = rules
            .iter()
            .position(|rule| rule["domain"] == "direct.example.com")
            .expect("direct domain route");
        assert_eq!(rules[direct]["outbound"], "direct");
        assert_eq!(rules.last().expect("policy resolver")["action"], "resolve");
        if let Ok(directory) = std::env::var("CFW_DNS_PROJECTED_FIXTURE_DIR") {
            std::fs::create_dir_all(&directory).expect("fixture directory");
            let name = if mode == ProjectionMode::LocalProxy {
                "mixed.json"
            } else if mode == ProjectionMode::Tunnel {
                "tunnel.json"
            } else {
                continue;
            };
            std::fs::write(
                std::path::Path::new(&directory).join(name),
                serde_json::to_vec_pretty(&value).expect("fixture JSON"),
            )
            .expect("fixture write");
        }
    }
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
        .find(|rule| rule["server"] == "cfw-profile-dns-0" && rule["type"] == "logical")
        .unwrap();
    assert_eq!(
        filter["rules"][1],
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

#[test]
fn dns_role_route_cycles_are_rejected_and_explicit_direct_policy_is_preserved() {
    let mut input = source();
    input["dns"]["proxy_servers"][0]["route"] = json!("selected");
    assert!(
        ValidatedSingBoxProfile::parse(&input.to_string())
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
    input = source();
    input["dns"]["direct_servers"][0]["route"] = json!("selected");
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(
        output["dns"]["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|server| server["tag"] == "cfw-direct-dns-0")
            .unwrap()["detour"],
        "proxy"
    );
    input = source();
    input["dns"]["nameserver_policy"][0]["servers"][0]["route"] = json!("direct");
    let output = project(&input, ProjectionMode::LocalProxy);
    let server = output["dns"]["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|server| server["tag"] == "cfw-policy-dns-0-0")
        .unwrap();
    assert!(server.get("detour").is_none());
    assert!(server.get("route").is_none());
}

#[test]
fn imported_direct_dns_policy_can_bootstrap_proxy_without_using_the_proxy_itself() {
    let mut input = source();
    input["dns"]
        .as_object_mut()
        .unwrap()
        .remove("proxy_servers");
    for server in input["dns"]["servers"].as_array_mut().unwrap() {
        server["route"] = json!("direct");
    }
    input["dns"]["nameserver_policy"] = json!([{"domain":"+.example.com","servers":[{"type":"tcp","server":"114.114.114.114","server_port":53,"route":"direct"}]}]);
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(
        output["outbounds"][0]["domain_resolver"],
        json!({"policy":"default"})
    );
    input["dns"]["nameserver_policy"][0]["servers"][0]["route"] = json!("selected");
    let profile = ValidatedSingBoxProfile::parse(&input.to_string()).unwrap();
    assert!(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::LocalProxy,
                &EngineSettings::default()
            )
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
    input["dns"]["nameserver_policy"] = json!([]);
    input["dns"]["fallback_servers"] =
        json!([{"type":"tcp","server":"8.8.4.4","server_port":53,"route":"direct"}]);
    input["dns"]["fallback_filter"] = json!({"ip_cidr":["240.0.0.0/4"]});
    let output = project(&input, ProjectionMode::LocalProxy);
    assert_eq!(
        output["outbounds"][0]["domain_resolver"],
        json!({"policy":"default"})
    );
    assert!(
        output["dns"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|rule| rule["response_ip_accept_all"] == true)
    );
    input["dns"]["proxy_servers"] =
        json!([{"type":"tcp","server":"223.5.5.5","server_port":53,"route":"direct"}]);
    project(&input, ProjectionMode::LocalProxy);
}
