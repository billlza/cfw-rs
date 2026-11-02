//! Named DNS roles, pools and policies: precedence, routing, cycles and the
//! explicit direct policy.

use super::*;

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
