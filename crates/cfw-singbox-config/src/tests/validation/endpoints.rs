//! Remote endpoint literals and remote-outbound admission.

use super::*;

#[test]
fn typed_remote_endpoints_reject_non_routable_and_tunnel_reserved_literals() {
    for server in [
        "0.0.0.0",
        "127.0.0.1",
        "169.254.169.254",
        "198.18.0.2",
        "198.18.64.2",
        "203.0.113.10",
        "::1",
        "fe80::1",
        "2001:db8::2",
        "2001:2:0:64::2",
        // An IPv4-mapped IPv6 literal is dialled as its IPv4 address.
        "::ffff:0.0.0.0",
        "::ffff:127.0.0.1",
        "::ffff:7f00:1",
        "::ffff:169.254.169.254",
        "::ffff:198.18.0.2",
        "::ffff:203.0.113.10",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"{server}","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
        );
        assert!(ValidatedSingBoxProfile::parse(&input).is_err(), "{server}");
    }
}

#[test]
fn an_ipv4_mapped_literal_of_a_public_address_stays_admitted() {
    for server in ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"{server}","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
        );
        ValidatedSingBoxProfile::parse(&input).unwrap_or_else(|error| panic!("{server}: {error}"));
    }
}

#[test]
fn remote_outbound_admission_distinguishes_real_replacements_from_local_only_profiles() {
    let direct = ValidatedSingBoxProfile::direct();
    assert!(!direct.routes_through_remote());

    let remote = ValidatedSingBoxProfile::parse(
        r#"{
          "outbounds": [
            {
              "type": "shadowsocks",
              "tag": "remote",
              "server": "example.com",
              "server_port": 443,
              "method": "aes-128-gcm",
              "credential_ref": {
                "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "kind": "shadowsocks_password"
              }
            }
          ]
        }"#,
    )
    .expect("remote profile");
    assert!(remote.routes_through_remote());

    let unused_remote = ValidatedSingBoxProfile::parse(&format!(
        r#"{{
              "outbounds": [
                {{"type":"direct","tag":"direct"}},
                {{
                  "type":"shadowsocks",
                  "tag":"unused-remote",
                  "server":"example.com",
                  "server_port":443,
                  "method":"aes-128-gcm",
                  "credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}
                }}
              ],
              "route":{{"final":"direct"}}
            }}"#
    ))
    .expect("unused remote profile remains valid for local testing");
    assert!(!unused_remote.routes_through_remote());

    let implicit_first_direct = ValidatedSingBoxProfile::parse(&format!(
        r#"{{
              "outbounds": [
                {{"type":"direct","tag":"direct"}},
                {{
                  "type":"shadowsocks",
                  "tag":"unused-remote",
                  "server":"example.com",
                  "server_port":443,
                  "method":"aes-128-gcm",
                  "credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}
                }}
              ]
            }}"#
    ))
    .expect("implicit direct final profile");
    assert!(!implicit_first_direct.routes_through_remote());
}
