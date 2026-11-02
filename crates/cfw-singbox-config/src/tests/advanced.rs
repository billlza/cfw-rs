use serde_json::{Value, json};

use crate::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};

mod dns;
mod endpoints;
mod groups;
mod tls;

const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn automatic_profile() -> Value {
    json!({
        "outbounds": [
            {"type":"socks5","tag":"first","server":"first.example.com","server_port":1080},
            {"type":"socks5","tag":"second","server":"second.example.com","server_port":1080},
            {"type":"urltest","tag":"automatic","outbounds":["first","second"],
             "url":"https://www.gstatic.com/generate_204","interval_seconds":300,
             "tolerance_ms":50,"idle_timeout_seconds":1800},
            {"type":"selector","tag":"PROXY","outbounds":["automatic","second"]}
        ],
        "route":{"final":"PROXY"}
    })
}

fn tls_profile(tls: Value) -> Value {
    json!({"outbounds":[{"type":"trojan","tag":"secure","server":"proxy.example.com","server_port":443,
        "credential_ref":{"id":PROFILE_ID,"kind":"trojan_password"},"tls":tls}]})
}

fn wireguard() -> Value {
    json!({"type":"wireguard","tag":"wg","server":"vpn.example.com","server_port":51820,
        "local_addresses":["10.10.0.2/32","fd00::2/128"],"mtu":1420,"persistent_keepalive_seconds":25,
        "peer_public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "private_key_credential_ref":{"id":PROFILE_ID,"kind":"wireguard_private_key"},
        "pre_shared_key_credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"wireguard_pre_shared_key"}})
}

fn tailscale() -> Value {
    json!({"type":"tailscale","tag":"ts","exit_node":"exit-mac",
        "auth_key_credential_ref":{"id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd","kind":"tailscale_auth_key"}})
}
