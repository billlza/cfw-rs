use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    AuthenticatedDnsServer, CONFIGURATION_IDENTITY_SCHEMA_VERSION, ConfigError, CredentialSlot,
    DEFAULT_CLASH_API_PORT, DirectIpv4HostRoutes, EngineSettings, MIN_CLASH_API_PORT,
    MINIMUM_REMOTE_TLS_VERSION, ProjectionMode, RELEASE_PACKET_TRANSPORT_IPV4,
    ReleaseDnsEvidenceCase, ReleasePacketEvidenceCase, TUNNEL_ADDRESS_PLAN,
    ValidatedSingBoxProfile,
};

const SS_ID: &str = "11111111-1111-4111-8111-111111111111";

mod bootstrap;
mod dns;
mod identity;
mod listeners;
mod outbounds;

const SS_ID_2: &str = "77777777-7777-4777-8777-777777777777";
const VMESS_ID: &str = "22222222-2222-4222-8222-222222222222";
const VLESS_ID: &str = "33333333-3333-4333-8333-333333333333";
const TROJAN_ID: &str = "44444444-4444-4444-8444-444444444444";
const HYSTERIA_ID: &str = "55555555-5555-4555-8555-555555555555";
const HYSTERIA_OBFS_ID: &str = "66666666-6666-4666-8666-666666666666";
const ANYTLS_ID: &str = "88888888-8888-4888-8888-888888888888";
const TUIC_UUID_ID: &str = "99999999-9999-4999-8999-999999999999";
const TUIC_PASSWORD_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaab";
const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn shadowsocks_profile(credential_id: &str) -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{"outbounds":[{{"type":"shadowsocks","tag":"proxy","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{credential_id}","kind":"shadowsocks_password"}}}}],"route":{{"final":"proxy"}}}}"#
    ))
    .expect("typed Shadowsocks profile")
}

fn remote_protocol_matrix_profile() -> ValidatedSingBoxProfile {
    ValidatedSingBoxProfile::parse(&format!(
        r#"{{
          "outbounds": [
            {{"type":"socks5","tag":"socks5","server":"socks5.example.com","server_port":1080}},
            {{"type":"shadowsocks","tag":"ss","server":"ss.example.com","server_port":443,"method":"aes-256-gcm","credential_ref":{{"id":"{SS_ID}","kind":"shadowsocks_password"}}}},
            {{"type":"vmess","tag":"vmess","server":"vmess.example.com","server_port":443,"credential_ref":{{"id":"{VMESS_ID}","kind":"vmess_uuid"}},"security":"auto","tls":{{"enabled":true,"server_name":"vmess.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}}}},"transport":{{"type":"ws","path":"/ws","headers":{{"Host":"vmess.example.com"}}}}}},
            {{"type":"vless","tag":"vless","server":"vless.example.com","server_port":443,"credential_ref":{{"id":"{VLESS_ID}","kind":"vless_uuid"}},"flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"}}}}}},
            {{"type":"trojan","tag":"trojan","server":"trojan.example.com","server_port":443,"credential_ref":{{"id":"{TROJAN_ID}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"trojan.example.com"}},"transport":{{"type":"grpc","service_name":"tunnel"}}}},
            {{"type":"hysteria2","tag":"hy2","server":"hy2.example.com","server_port":443,"credential_ref":{{"id":"{HYSTERIA_ID}","kind":"hysteria2_password"}},"tls":{{"enabled":true,"server_name":"hy2.example.com"}},"up_mbps":100,"down_mbps":200,"obfs":{{"type":"salamander","credential_ref":{{"id":"{HYSTERIA_OBFS_ID}","kind":"hysteria2_obfs_password"}}}}}},
            {{"type":"anytls","tag":"anytls","server":"anytls.example.com","server_port":443,"credential_ref":{{"id":"{ANYTLS_ID}","kind":"anytls_password"}},"tls":{{"enabled":true,"server_name":"anytls.example.com"}}}},
            {{"type":"tuic","tag":"tuic","server":"tuic.example.com","server_port":443,"uuid_credential_ref":{{"id":"{TUIC_UUID_ID}","kind":"tuic_uuid"}},"password_credential_ref":{{"id":"{TUIC_PASSWORD_ID}","kind":"tuic_password"}},"tls":{{"enabled":true,"server_name":"tuic.example.com"}},"congestion_control":"bbr","udp_relay_mode":"native"}}
          ],
          "route": {{"final":"ss"}}
        }}"#
    ))
    .expect("typed remote protocol matrix")
}
