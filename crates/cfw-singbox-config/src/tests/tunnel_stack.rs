use crate::{EngineSettings, ProjectionMode, TunnelStack, ValidatedSingBoxProfile, sha256_hex};
use serde_json::Value;

#[test]
fn packet_stack_is_bound_before_hashing_and_preserves_every_other_projected_field() {
    let sources = [
        r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#,
        r#"{"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"node.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"shadowsocks_password"}}]}"#,
    ];
    for source in sources {
        let profile = ValidatedSingBoxProfile::parse(source).unwrap();
        for mode in [
            ProjectionMode::LocalProxy,
            ProjectionMode::SystemProxy,
            ProjectionMode::Tunnel,
            ProjectionMode::TunnelSystemProxy,
        ] {
            for mtu in [1280, 1500, 9000] {
                for ipv6 in [false, true] {
                    let settings = EngineSettings {
                        tunnel_mtu: mtu,
                        enable_ipv6: ipv6,
                        ..EngineSettings::default()
                    };
                    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
                    let original = profile.project(id, mode, &settings).unwrap();
                    let system = profile
                        .project_with_tunnel_stack(id, mode, &settings, TunnelStack::System)
                        .unwrap();
                    let packet = profile
                        .project_with_tunnel_stack(id, mode, &settings, TunnelStack::Gvisor)
                        .unwrap();
                    assert_eq!(
                        system, original,
                        "CFM template and identity must not change"
                    );
                    assert_eq!(packet.credential_slots(), system.credential_slots());
                    assert_eq!(packet.credential_audience(), system.credential_audience());
                    assert_eq!(packet.clash_api(), system.clash_api());
                    assert_eq!(packet.direct_ipv4_hosts(), system.direct_ipv4_hosts());
                    assert_eq!(
                        packet.configuration_digest(),
                        sha256_hex(packet.as_json().as_bytes())
                    );
                    if mode.has_tunnel() {
                        let mut expected: Value = serde_json::from_str(system.as_json()).unwrap();
                        let actual: Value = serde_json::from_str(packet.as_json()).unwrap();
                        assert_eq!(expected["inbounds"][0]["stack"], "system");
                        assert_eq!(actual["inbounds"][0]["stack"], "gvisor");
                        assert_eq!(actual["inbounds"][0]["auto_route"], false);
                        assert_eq!(actual["inbounds"][0]["mtu"], mtu);
                        assert_eq!(
                            actual["inbounds"][0]["address"].as_array().unwrap().len(),
                            1 + usize::from(ipv6)
                        );
                        expected["inbounds"][0]["stack"] = "gvisor".into();
                        assert_eq!(actual, expected);
                        assert_ne!(packet.configuration_digest(), system.configuration_digest());
                        assert_ne!(packet.digest(), system.digest());
                    } else {
                        assert_eq!(packet, system);
                    }
                }
            }
        }
    }
}
