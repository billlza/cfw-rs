//! Engine DNS servers in every mode, and release DNS evidence.

use super::*;

#[test]
fn engine_dns_rejects_duplicate_virtual_local_and_disabled_ipv6_endpoints_in_both_modes() {
    let profile = ValidatedSingBoxProfile::direct();
    for endpoints in [
        [
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        ],
        [
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        ],
        [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        ],
    ] {
        let settings = EngineSettings {
            bootstrap_dns_servers: endpoints,
            ..EngineSettings::default()
        };
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            assert!(profile.project(PROFILE_ID, mode, &settings).is_err());
        }
    }

    let settings = EngineSettings {
        enable_ipv6: false,
        bootstrap_dns_servers: [
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(profile.project(PROFILE_ID, mode, &settings).is_err());
    }

    let duplicate_authenticated = EngineSettings {
        authenticated_dns_servers: [
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                server_name: "doh.pub".to_owned(),
            },
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)),
                server_name: "other.example.com".to_owned(),
            },
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(
            profile
                .project(PROFILE_ID, mode, &duplicate_authenticated)
                .is_err()
        );
    }

    let invalid_tls_name = EngineSettings {
        authenticated_dns_servers: [
            AuthenticatedDnsServer {
                address: IpAddr::V4(Ipv4Addr::new(120, 53, 53, 53)),
                server_name: "120.53.53.53".to_owned(),
            },
            EngineSettings::default().authenticated_dns_servers[1].clone(),
        ],
        ..EngineSettings::default()
    };
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        assert!(
            profile
                .project(PROFILE_ID, mode, &invalid_tls_name)
                .is_err()
        );
    }
}

#[test]
fn ordinary_dns_is_authenticated_and_detoured_in_both_modes_while_bootstrap_is_endpoint_only() {
    let profile = shadowsocks_profile(SS_ID);
    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        let projected = profile
            .project(PROFILE_ID, mode, &EngineSettings::default())
            .expect("remote projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        assert_eq!(
            config["outbounds"][0]["domain_resolver"],
            serde_json::json!({
                "server": "cfw-bootstrap-dns-0",
                "fallback_server": "cfw-bootstrap-dns-1",
            })
        );
        let dns = &config["dns"];
        assert!(
            dns["final"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
        );
        let rules = dns["rules"].as_array().expect("DNS rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["action"], "evaluate");
        assert!(
            rules[0]["server"]
                .as_str()
                .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
        );
        assert_eq!(rules[1]["action"], "respond");
        assert_eq!(
            rules[1]["rules"][0],
            serde_json::json!({"domain_regex":".*"})
        );
        assert!(dns.get("independent_cache").is_none());
        for key in ["server", "fallback_server"] {
            assert!(
                config["route"]["default_domain_resolver"][key]
                    .as_str()
                    .is_some_and(|tag| tag.starts_with("cfw-authenticated-dns-"))
            );
        }
        for server in dns["servers"].as_array().expect("DNS servers") {
            let tag = server["tag"].as_str().expect("DNS tag");
            if tag.starts_with("cfw-bootstrap-dns-") {
                assert_eq!(server["type"], "udp");
                assert!(server.get("detour").is_none());
            } else {
                assert!(tag.starts_with("cfw-authenticated-dns-"));
                assert_eq!(server["type"], "https");
                assert_eq!(server["detour"], "proxy");
            }
        }
    }
}

#[test]
fn release_dns_evidence_is_a_closed_udp53_tunnel_projection() {
    let cases = [
        (
            ReleaseDnsEvidenceCase::PrimaryIpv4,
            "34.80.107.183",
            "cfw-release-dns-primary-ipv4",
        ),
        (
            ReleaseDnsEvidenceCase::PrimaryIpv6,
            "2600:1900:4030:5afb:0:1::",
            "cfw-release-dns-primary-ipv6",
        ),
        (
            ReleaseDnsEvidenceCase::SecondaryIpv4,
            "35.200.12.109",
            "cfw-release-dns-secondary-ipv4",
        ),
        (
            ReleaseDnsEvidenceCase::SecondaryIpv6,
            "2600:1900:4050:8de::",
            "cfw-release-dns-secondary-ipv6",
        ),
    ];
    let mut digests = std::collections::BTreeSet::new();
    for (case, address, tag) in cases {
        let profile = ValidatedSingBoxProfile::release_dns_evidence(case);
        assert_eq!(
            profile.as_json(),
            ValidatedSingBoxProfile::direct().as_json()
        );
        assert_eq!(
            profile
                .project(
                    PROFILE_ID,
                    ProjectionMode::SystemProxy,
                    &EngineSettings::default(),
                )
                .expect_err("evidence projection is never a system proxy"),
            ConfigError::InvalidReleaseDnsEvidenceMode
        );
        let projected = profile
            .project(
                PROFILE_ID,
                ProjectionMode::Tunnel,
                &EngineSettings::default(),
            )
            .expect("fixed release DNS projection");
        let config: serde_json::Value =
            serde_json::from_str(projected.as_json()).expect("projected config");
        let servers = config["dns"]["servers"].as_array().expect("DNS servers");
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["type"], "udp");
        assert_eq!(servers[0]["server"], address);
        assert_eq!(servers[0]["server_port"], 53);
        assert_eq!(servers[0]["tag"], tag);
        assert!(
            servers[0].get("detour").is_none(),
            "explicit DIRECT uses the normal dialer"
        );
        assert!(servers[0].get("path").is_none());
        assert!(servers[0].get("tls").is_none());
        assert_eq!(config["dns"]["rules"][0]["server"], tag);
        assert_eq!(config["dns"]["final"], tag);
        assert_eq!(
            config["route"]["default_domain_resolver"],
            serde_json::json!({ "server": tag })
        );
        assert!(!projected.as_json().contains("cfw-bootstrap-dns"));
        assert!(!projected.as_json().contains("cfw-authenticated-dns"));
        assert!(digests.insert(projected.digest().to_owned()));
    }
    assert_eq!(digests.len(), 4);
}

#[test]
fn release_dns_evidence_rejects_ipv6_disabled_settings_for_every_case() {
    let settings = EngineSettings {
        enable_ipv6: false,
        ..EngineSettings::default()
    };
    for case in [
        ReleaseDnsEvidenceCase::PrimaryIpv4,
        ReleaseDnsEvidenceCase::PrimaryIpv6,
        ReleaseDnsEvidenceCase::SecondaryIpv4,
        ReleaseDnsEvidenceCase::SecondaryIpv6,
    ] {
        assert_eq!(
            ValidatedSingBoxProfile::release_dns_evidence(case)
                .project(PROFILE_ID, ProjectionMode::Tunnel, &settings)
                .expect_err("release DNS evidence keeps the active IPv6 matrix exact"),
            ConfigError::InvalidReleaseDnsEvidenceMode
        );
    }
}
