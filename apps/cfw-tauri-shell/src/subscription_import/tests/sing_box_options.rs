//! sing-box node-list options: the transports and TLS settings that convert,
//! and the outbound, TLS and transport semantics the profile cannot carry.

use super::*;

/// `base` with every key of `extra` set over it.
fn merged(mut base: Value, extra: Value) -> Value {
    for (key, value) in extra.as_object().expect("extra keys") {
        base[key] = value.clone();
    }
    base
}

fn vmess(extra: Value) -> Value {
    merged(
        json!({
            "type": "vmess",
            "tag": "V",
            "server": "v.example.com",
            "server_port": 443,
            "uuid": SYNTHETIC_VM_UUID,
        }),
        extra,
    )
}

fn trojan(extra: Value) -> Value {
    merged(
        json!({
            "type": "trojan",
            "tag": "T",
            "server": "t.example.com",
            "server_port": 443,
            "password": "TopSecretValue!",
            "tls": { "enabled": true, "server_name": "t.example.com" },
        }),
        extra,
    )
}

fn hysteria2(extra: Value) -> Value {
    merged(
        json!({
            "type": "hysteria2",
            "tag": "H",
            "server": "h.example.com",
            "server_port": 443,
            "password": "TopSecretValue!",
            "tls": { "enabled": true, "server_name": "h.example.com" },
        }),
        extra,
    )
}

fn tuic(extra: Value) -> Value {
    merged(
        json!({
            "type": "tuic",
            "tag": "Q",
            "server": "q.example.com",
            "server_port": 443,
            "uuid": "33333333-3333-4333-8333-333333333333",
            "password": "TopSecretValue!",
            "tls": { "enabled": true, "server_name": "q.example.com" },
        }),
        extra,
    )
}

fn node_list(outbounds: Vec<Value>) -> String {
    json!({ "outbounds": outbounds }).to_string()
}

fn imported(outbound: Value) -> Value {
    let imported = import_subscription_document(&node_list(vec![outbound])).expect("imports");
    imported_outbounds(&imported)[0].clone()
}

fn refusal(outbound: Value) -> String {
    import_subscription_document(&node_list(vec![outbound])).expect_err("is refused")
}

fn assert_refused(outbound: Value, message: &str) {
    let error = refusal(outbound.clone());
    assert!(error.contains(message), "{outbound}: {error}");
}

#[test]
fn transports_convert_with_their_default_path_and_one_host() {
    assert_eq!(
        imported(vmess(json!({
            "transport": { "type": "http", "headers": { "Host": "h.example.com" }, "method": "post" }
        })))["transport"],
        json!({ "type": "http", "path": "/", "host": ["h.example.com"], "method": "POST" })
    );
    assert_eq!(
        imported(vmess(json!({
            "transport": { "type": "http", "host": ["a.example.com"], "headers": { "host": "a.example.com" } }
        })))["transport"],
        json!({ "type": "http", "path": "/", "host": ["a.example.com"] })
    );
    assert_eq!(
        imported(vmess(json!({
            "transport": { "type": "ws", "headers": { "host": "w.example.com" } }
        })))["transport"],
        json!({ "type": "ws", "path": "/", "headers": { "Host": "w.example.com" } })
    );
    assert_eq!(
        imported(vmess(json!({
            "transport": { "type": "quic" },
            "tls": { "enabled": true, "server_name": "v.example.com" },
        })))["transport"],
        json!({ "type": "quic" })
    );
    assert_eq!(
        imported(vmess(json!({
            "transport": { "type": "httpupgrade", "host": "u.example.com" }
        })))["transport"],
        json!({ "type": "http_upgrade", "path": "/", "host": "u.example.com" })
    );
    assert_eq!(
        imported(vmess(json!({ "transport": { "type": "httpupgrade" } })))["transport"],
        json!({ "type": "http_upgrade", "path": "/" })
    );
}

#[test]
fn transport_headers_beyond_one_host_are_refused() {
    for (transport, message) in [
        (
            json!({ "type": "http", "headers": { "Host": "a.example.com", "host": "b.example.com" } }),
            "sing-box HTTP transport declares conflicting Host headers",
        ),
        (
            json!({ "type": "http", "headers": { "X-Token": "secret" } }),
            "sing-box HTTP headers other than Host are unsupported",
        ),
        (
            json!({ "type": "http", "host": ["a.example.com"], "headers": { "Host": "b.example.com" } }),
            "sing-box HTTP transport declares conflicting host authorities",
        ),
        (
            json!({ "type": "http", "method": "CONNECT" }),
            "sing-box HTTP method is unsupported",
        ),
        (
            json!({ "type": "ws", "headers": { "X-Token": "secret" } }),
            "sing-box WebSocket headers other than Host are unsupported",
        ),
        (
            json!({ "type": "httpupgrade", "headers": { "X-Token": "secret" } }),
            "sing-box HTTPUpgrade custom headers are unsupported",
        ),
    ] {
        assert_refused(vmess(json!({ "transport": transport })), message);
    }
}

#[test]
fn tls_settings_the_profile_cannot_carry_are_refused() {
    for (outbound, message) in [
        (
            trojan(json!({ "tls": { "enabled": false } })),
            "sing-box outbound requires enabled TLS",
        ),
        (
            trojan(json!({ "tls": { "enabled": true, "disable_sni": true } })),
            "sing-box outbound disables SNI, which is unsupported",
        ),
        (
            trojan(json!({ "tls": { "enabled": true, "min_version": "1.1" } })),
            "sing-box TLS min_version cannot be represented exactly",
        ),
        (
            trojan(
                json!({ "tls": { "enabled": true, "utls": { "enabled": false, "fingerprint": "chrome" } } }),
            ),
            "disabled sing-box uTLS contains active options",
        ),
        (
            trojan(
                json!({ "tls": { "enabled": true, "reality": { "enabled": false, "public_key": "key" } } }),
            ),
            "disabled sing-box Reality contains active options",
        ),
        (
            vmess(json!({ "tls": { "enabled": false, "server_name": "v.example.com" } })),
            "disabled sing-box TLS contains active options",
        ),
    ] {
        assert_refused(outbound, message);
    }
}

#[test]
fn tls_curves_and_ech_are_kept() {
    let ech = [
        "-----BEGIN ECH CONFIGS-----",
        "AAT+DQAA",
        "-----END ECH CONFIGS-----",
    ];
    let tls = imported(trojan(json!({
        "tls": {
            "enabled": true,
            "server_name": "t.example.com",
            "min_version": "1.3",
            "curve_preferences": ["X25519MLKEM768"],
            "ech": { "enabled": true, "config": ech },
        }
    })))["tls"]
        .clone();
    assert_eq!(tls["curve_preferences"], json!(["X25519MLKEM768"]));
    assert_eq!(tls["ech"], json!({ "enabled": true, "config": ech }));
}

#[test]
fn outbound_options_the_profile_cannot_carry_are_refused() {
    for (outbound, message) in [
        (
            json!({ "type": "shadowsocks", "tag": "S", "server": "s.example.com", "server_port": 8388, "method": "aes-256-gcm", "password": "TopSecretValue123", "plugin": "obfs-local" }),
            "sing-box Shadowsocks plugins are unsupported",
        ),
        (
            vmess(json!({ "global_padding": true })),
            "sing-box VMess padding modes are unsupported",
        ),
        (
            vmess(json!({ "packet_encoding": "invented" })),
            "sing-box VMess packet encoding",
        ),
        (
            hysteria2(json!({ "brutal_debug": true })),
            "sing-box Hysteria2 brutal debug is unsupported",
        ),
        (
            hysteria2(json!({ "server_port": 0 })),
            "sing-box Hysteria2 server_port is invalid",
        ),
        (
            hysteria2(json!({ "server_port": null })),
            "sing-box Hysteria2 server port is missing",
        ),
        (
            hysteria2(json!({ "hop_interval": "30s" })),
            "sing-box Hysteria2 hop_interval requires server_ports",
        ),
        (
            hysteria2(json!({ "obfs": { "type": "invented", "password": "TopSecretValue!" } })),
            "sing-box Hysteria2 obfuscation is unsupported or incomplete",
        ),
        (
            hysteria2(json!({ "obfs": { "type": "salamander", "password": "" } })),
            "sing-box Hysteria2 obfuscation is unsupported or incomplete",
        ),
        (
            hysteria2(
                json!({ "obfs": { "type": "salamander", "password": "TopSecretValue!", "min_packet_size": 64 } }),
            ),
            "sing-box Hysteria2 packet sizes apply only to gecko obfs",
        ),
        (
            tuic(json!({ "udp_over_stream": true })),
            "sing-box TUIC UDP-over-stream is unsupported",
        ),
        (
            tuic(json!({ "congestion_control": "reno" })),
            "TUIC congestion control is unsupported",
        ),
        (
            tuic(json!({ "udp_relay_mode": "stream" })),
            "TUIC UDP relay mode is unsupported",
        ),
        (
            json!({ "type": "anytls", "tag": "A", "server": "a.example.com", "server_port": 443, "password": "TopSecretValue!", "idle_session_check_interval": "30s", "tls": { "enabled": true, "server_name": "a.example.com" } }),
            "sing-box source uses unsupported AnyTLS idle-session check interval",
        ),
        (
            json!({ "type": "http", "tag": "P", "server": "p.example.com", "server_port": 8080, "password": "TopSecretValue!" }),
            "HTTP proxy password requires a username",
        ),
    ] {
        assert_refused(outbound, message);
    }
}

#[test]
fn optional_outbound_settings_are_kept() {
    let vmess = imported(vmess(json!({ "alter_id": 4, "security": "aes-128-gcm" })));
    assert_eq!(vmess["alter_id"], 1);
    assert_eq!(vmess["security"], "aes-128-gcm");

    let hysteria2 = imported(hysteria2(json!({ "up_mbps": 50, "down_mbps": 200 })));
    assert_eq!(hysteria2["up_mbps"], 50);
    assert_eq!(hysteria2["down_mbps"], 200);

    let tuic = imported(tuic(
        json!({ "congestion_control": "bbr", "udp_relay_mode": "quic" }),
    ));
    assert_eq!(tuic["congestion_control"], "bbr");
    assert_eq!(tuic["udp_relay_mode"], "quic");
}

#[test]
fn the_node_list_is_bounded_and_tailscale_runs_as_a_plain_userspace_node() {
    let node = |index: usize| trojan(json!({ "tag": format!("T{index}") }));
    let error = import_subscription_document(&node_list(
        (0..=cfw_singbox_config::MAX_OUTBOUNDS).map(node).collect(),
    ))
    .expect_err("too many outbounds");
    assert!(
        error.contains(&format!(
            "sing-box source JSON has more than {} outbounds",
            cfw_singbox_config::MAX_OUTBOUNDS
        )),
        "{error}"
    );

    for (flag, message) in [
        (
            "system_interface",
            "sing-box Tailscale system interfaces are unsupported",
        ),
        (
            "ephemeral",
            "sing-box Tailscale ephemeral nodes are unsupported",
        ),
    ] {
        let document = json!({
            "outbounds": [],
            "endpoints": [{ "type": "tailscale", "tag": "T", "auth_key": "TopSecretValue!", "exit_node": "exit-mac", flag: true }],
        });
        let error = import_subscription_document(&document.to_string()).expect_err(flag);
        assert!(error.contains(message), "{flag}: {error}");
    }
}
