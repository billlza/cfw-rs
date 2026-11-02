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
    ] {
        let input = format!(
            r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"{server}","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}}]}}"#
        );
        assert!(ValidatedSingBoxProfile::parse(&input).is_err(), "{server}");
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
