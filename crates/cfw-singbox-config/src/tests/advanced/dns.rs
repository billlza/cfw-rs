//! Hosts, fake IP, the selected DNS transports and explicit DNS fallback.

use super::*;

#[test]
fn hosts_bootstrap_and_fake_ip_have_distinct_runtime_roles() {
    let source = json!({"outbounds":[{"type":"socks5","tag":"proxy","server":"node.example.com","server_port":1080}],
        "hosts":{"node.example.com":["9.9.9.9"]},
        "dns":{"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],
            "bootstrap_servers":["8.8.8.8","1.1.1.1"],"ipv6":false,
            "fake_ip":{"exclude":["+.lan","*.local","localhost"]}}});
    let profile = ValidatedSingBoxProfile::parse(&source.to_string()).expect("DNS and hosts");
    for mode in [
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let runtime: Value = serde_json::from_str(
            profile
                .project(PROFILE_ID, mode, &EngineSettings::default())
                .expect("project")
                .as_json(),
        )
        .expect("runtime");
        assert_eq!(runtime["dns"]["servers"][0]["server"], "8.8.8.8");
        assert_eq!(
            runtime["outbounds"][0]["domain_resolver"],
            json!({"server":"cfw-profile-hosts"})
        );
        assert_eq!(
            runtime["dns"]["rules"][0],
            json!({"query_type":["AAAA"],"action":"predefined","rcode":"NOERROR"})
        );
        let fake = runtime["dns"]["servers"]
            .as_array()
            .expect("servers")
            .iter()
            .find(|server| server["type"] == "fakeip");
        assert_eq!(fake.is_some(), mode.has_tunnel());
        if let Some(fake) = fake {
            assert_eq!(fake["inet4_range"], "198.19.0.0/16");
            assert!(fake.get("inet6_range").is_none());
            assert_eq!(runtime["experimental"]["cache_file"]["store_fakeip"], true);
        }
    }
    for (key, invalid) in [
        ("hosts", json!({"*.example.com":["9.9.9.9"]})),
        ("hosts", json!({"node.example.com":["9.9.9.9","9.9.9.9"]})),
        (
            "dns",
            json!({"servers":[{"type":"udp","server":"1.1.1.1","server_port":53}],"fake_ip":{"exclude":["bad[regex].test"]}}),
        ),
    ] {
        let mut bad = source.clone();
        bad[key] = invalid;
        assert!(ValidatedSingBoxProfile::parse(&bad.to_string()).is_err());
    }
}

#[test]
fn selected_dns_transports_keep_authentication_and_stay_on_the_selected_route() {
    for kind in ["udp", "tcp", "tls", "quic", "https", "h3"] {
        let mut server = json!({"type":kind,"server":"1.1.1.1","server_port":853});
        if !matches!(kind, "udp" | "tcp") {
            server["tls"] =
                json!({"enabled":true,"server_name":"cloudflare-dns.com","min_version":"1.3"});
        }
        if matches!(kind, "https" | "h3") {
            server["path"] = json!("/dns-query");
            server["server_port"] = json!(443);
        }
        let value = json!({"outbounds":[wireguard()],"dns":{"servers":[server.clone()]}});
        let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("DNS policy");
        let runtime: Value = serde_json::from_str(
            profile
                .project(
                    PROFILE_ID,
                    ProjectionMode::SystemProxy,
                    &EngineSettings::default(),
                )
                .expect("projection")
                .as_json(),
        )
        .expect("runtime");
        let servers = runtime["dns"]["servers"].as_array().expect("servers");
        let selected_servers = servers
            .iter()
            .filter(|server| server["tag"] == "cfw-profile-dns-0")
            .collect::<Vec<_>>();
        assert_eq!(selected_servers.len(), 1);
        let projected = selected_servers[0];
        assert_eq!(projected["type"], kind);
        assert_eq!(projected["server"], "1.1.1.1");
        assert_eq!(projected["detour"], "wg");
        assert_eq!(runtime["dns"]["final"], "cfw-profile-dns-0");
        assert_eq!(
            runtime["route"]["default_domain_resolver"],
            json!({"policy":"default"})
        );
        assert_eq!(
            servers.len(),
            if matches!(kind, "udp" | "tcp") { 3 } else { 2 }
        );
        if !matches!(kind, "udp" | "tcp") {
            assert_eq!(projected["tls"]["server_name"], "cloudflare-dns.com");
            assert!(projected["tls"].get("insecure").is_none());
        }
        let mut invalid = value.clone();
        invalid["dns"]["servers"][0]["server_port"] = json!(0);
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
        invalid = value.clone();
        invalid["dns"]["servers"][0]["server"] = json!("127.0.0.1");
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
        invalid = value;
        invalid["dns"]["servers"] = json!([server.clone(), server]);
        assert!(ValidatedSingBoxProfile::parse(&invalid.to_string()).is_err());
    }
}

#[test]
fn dns_fallback_is_explicit_and_ipv6_resolver_cannot_override_disabled_ipv6() {
    let value = json!({"outbounds":[wireguard()],"dns":{"servers":[
        {"type":"udp","server":"10.64.0.1","server_port":53},
        {"type":"udp","server":"2606:4700:4700::1111","server_port":53}
    ]}});
    let profile = ValidatedSingBoxProfile::parse(&value.to_string()).expect("DNS pair");
    assert!(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings {
                    enable_ipv6: false,
                    ..EngineSettings::default()
                }
            )
            .is_err()
    );
    let runtime: Value = serde_json::from_str(
        profile
            .project(
                PROFILE_ID,
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .expect("projection")
            .as_json(),
    )
    .expect("runtime");
    assert_eq!(runtime["dns"]["final"], "cfw-profile-dns-1");
    assert_eq!(
        runtime["route"]["default_domain_resolver"],
        json!({"policy":"default"})
    );
}
