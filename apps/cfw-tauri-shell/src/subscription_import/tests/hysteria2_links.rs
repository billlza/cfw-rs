//! VLESS Reality and Hysteria2 links: default ports, port hopping, hop
//! intervals, obfuscation and congestion options, and certificate pins.

use super::*;

#[test]
fn imports_vless_reality_and_hysteria2_links() {
    let imported = import_subscription_document(
        "vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&fp=chrome&flow=xtls-rprx-vision&encryption=none&packetEncoding=xudp#Reality\nhy2://supersecret@hy2.example.com:8443?sni=hy2.example.com&upmbps=100&downmbps=200&obfs=salamander&obfs-password=mask#HY2",
    )
    .expect("vless and hy2 URIs");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    assert_eq!(profile["outbounds"][0]["type"], "vless");
    assert_eq!(profile["outbounds"][0]["packet_encoding"], "xudp");
    assert_eq!(profile["outbounds"][0]["tls"]["reality"]["enabled"], true);
    assert_eq!(profile["outbounds"][1]["type"], "hysteria2");
    assert_eq!(profile["outbounds"][1]["obfs"]["type"], "salamander");
    assert_eq!(imported.credentials.len(), 3);
    assert_eq!(
        imported.credentials[0].reference.kind(),
        CredentialKind::VlessUuid
    );
    assert_eq!(
        imported.credentials[1].reference.kind(),
        CredentialKind::Hysteria2Password
    );
    assert_eq!(
        imported.credentials[2].reference.kind(),
        CredentialKind::Hysteria2ObfsPassword
    );
    let projected = imported
        .profile
        .project(
            SYNTHETIC_PROFILE_ID,
            ProjectionMode::Tunnel,
            &EngineSettings::default(),
        )
        .expect("VLESS packet encoding projection");
    let runtime: Value =
        serde_json::from_str(projected.as_json()).expect("runtime projection JSON");
    assert_eq!(runtime["outbounds"][0]["packet_encoding"], "xudp");
}

#[test]
fn hysteria2_and_anytls_omitted_ports_default_to_443() {
    let imported = import_subscription_document(
        "hysteria2://user%3Apass@hy.example/?sni=hy.example#HY2\nanytls://letmein@any.example/?sni=any.example#AnyTLS",
    )
    .expect("official omitted-port URI forms");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("canonical JSON");
    let outbounds = profile["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds[0]["server_port"], 443);
    assert_eq!(outbounds[1]["server_port"], 443);
    assert_eq!(imported.credentials[0].secret, "user:pass");
    assert_eq!(imported.credentials[1].secret, "letmein");
    assert!(!imported.profile.as_json().contains("user:pass"));
    assert!(!imported.profile.as_json().contains("letmein"));

    for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
        imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
            .expect("omitted-port runtime projection");
    }
}

#[test]
fn hysteria2_port_hopping_projects_from_uri_clash_and_sing_box() {
    let documents = [
        (
            "official URI",
            "hysteria2://hy-secret@hy.example.com:443,5000-5002/?sni=hy.example.com#URI-Hop"
                .to_owned(),
            None,
        ),
        (
            "Clash",
            "proxies:\n  - name: Clash-Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 443,5000-5002\n    hop-interval: 30\n    password: hy-secret\n    sni: hy.example.com\n"
                .to_owned(),
            Some(30),
        ),
        (
            "sing-box",
            json!({
                "outbounds": [{
                    "type": "hysteria2",
                    "tag": "SingBox-Hop",
                    "server": "hy.example.com",
                    "server_ports": ["443", "5000:5002"],
                    "hop_interval": "15s",
                    "password": "hy-secret",
                    "tls": { "enabled": true, "server_name": "hy.example.com" }
                }]
            })
            .to_string(),
            Some(15),
        ),
    ];

    for (label, document, hop_interval) in documents {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value = serde_json::from_str(imported.profile.as_json())
            .expect("canonical Hysteria2 hopping profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["server_port"], 443, "{label}");
        assert_eq!(outbound["server_ports"], json!(["443", "5000:5002"]));
        match hop_interval {
            Some(seconds) => {
                assert_eq!(outbound["hop_interval_seconds"], seconds, "{label}")
            }
            None => assert!(outbound.get("hop_interval_seconds").is_none(), "{label}"),
        }
        assert_eq!(imported.credentials[0].secret, "hy-secret");

        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projected = imported
                .profile
                .project(SYNTHETIC_PROFILE_ID, mode, &EngineSettings::default())
                .expect("Hysteria2 hopping projection");
            let runtime: Value =
                serde_json::from_str(projected.as_json()).expect("Hysteria2 hopping runtime JSON");
            let runtime_hysteria2 = runtime["outbounds"]
                .as_array()
                .expect("runtime outbounds")
                .iter()
                .find(|candidate| candidate["type"] == "hysteria2")
                .expect("runtime Hysteria2 outbound");
            assert_eq!(
                runtime_hysteria2["server_ports"],
                json!(["443:443", "5000:5002"]),
                "{label}"
            );
            if let Some(seconds) = hop_interval {
                assert_eq!(
                    runtime_hysteria2["hop_interval"],
                    format!("{seconds}s"),
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn hysteria2_port_hopping_rejects_ambiguous_or_unprojectable_ranges() {
    for (label, document, expected) in [
        (
            "overlap",
            "hysteria2://hy-secret@hy.example.com:443,440-450/?sni=hy.example.com#Overlap",
            "overlapping",
        ),
        (
            "leading zero",
            "hysteria2://hy-secret@hy.example.com:0443,5000-5002/?sni=hy.example.com#LeadingZero",
            "invalid port",
        ),
        (
            "Mihomo descending hop interval range",
            "proxies:\n  - name: Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 30-15\n    password: TopSecretValue!\n",
            "hop interval maximum must be between hop_interval_seconds and 3600 seconds",
        ),
        (
            "Mihomo hop interval below the runtime minimum",
            "proxies:\n  - name: Hop\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 3\n    password: TopSecretValue!\n",
            "hop interval must be between 5 and 3600 seconds",
        ),
        (
            "URI open hop interval range",
            "hysteria2://TopSecretValue!@hy.example.com:443,5000-5002/?sni=hy.example.com&hop-interval=15-#Hop",
            "canonical 1..=3600 second",
        ),
    ] {
        let error = import_subscription_document(document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("TopSecretValue!"), "{label}: {error}");
    }

    let sing_box = |hop_interval_max: Option<&str>| {
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": "SingBox-Hop",
            "server": "hy.example.com",
            "server_ports": ["443", "5000:5002"],
            "hop_interval": "15s",
            "password": "TopSecretValue!",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        });
        if let Some(value) = hop_interval_max {
            outbound["hop_interval_max"] = json!(value);
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    import_subscription_document(&sing_box(None)).expect("fixed sing-box hop interval");
    let error = import_subscription_document(&sing_box(Some("10s")))
        .expect_err("a sing-box hop_interval_max below hop_interval");
    assert!(
        error
            .contains("hop interval maximum must be between hop_interval_seconds and 3600 seconds"),
        "{error}"
    );
}

#[test]
fn hysteria2_hop_interval_ranges_import_from_every_format() {
    let sing_box = json!({
        "outbounds": [{
            "type": "hysteria2",
            "tag": "SingBox-Range",
            "server": "hy.example.com",
            "server_ports": ["5000:5002"],
            "hop_interval": "15s",
            "hop_interval_max": "30s",
            "password": "hy-secret",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        }]
    })
    .to_string();
    for (label, document, expected) in [
        (
            "Clash",
            "proxies:\n  - name: Range\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 15-30\n    password: hy-secret\n".to_owned(),
            (15, Some(30)),
        ),
        (
            "Clash single-valued range",
            "proxies:\n  - name: Range\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    ports: 5000-5002\n    hop-interval: 20-20\n    password: hy-secret\n".to_owned(),
            (20, None),
        ),
        (
            "URI",
            "hysteria2://hy-secret@hy.example.com:443,5000-5002/?sni=hy.example.com&hop-interval=15-30#Range".to_owned(),
            (15, Some(30)),
        ),
        ("sing-box", sing_box, (15, Some(30))),
    ] {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["hop_interval_seconds"], expected.0, "{label}");
        match expected.1 {
            Some(maximum) => assert_eq!(outbound["hop_interval_max_seconds"], maximum, "{label}"),
            None => assert!(outbound.get("hop_interval_max_seconds").is_none(), "{label}"),
        }
        let projected = imported
            .profile
            .project(SYNTHETIC_PROFILE_ID, ProjectionMode::SystemProxy, &EngineSettings::default())
            .expect("Hysteria2 range projection");
        let runtime: Value = serde_json::from_str(projected.as_json()).expect("runtime JSON");
        let hysteria2 = runtime["outbounds"]
            .as_array()
            .expect("runtime outbounds")
            .iter()
            .find(|candidate| candidate["type"] == "hysteria2")
            .expect("runtime Hysteria2");
        assert_eq!(hysteria2["hop_interval"], format!("{}s", expected.0), "{label}");
        match expected.1 {
            Some(maximum) => {
                assert_eq!(hysteria2["hop_interval_max"], format!("{maximum}s"), "{label}")
            }
            None => assert!(hysteria2.get("hop_interval_max").is_none(), "{label}"),
        }
    }
}

#[test]
fn hysteria2_gecko_obfs_and_bbr_profile_import_from_clash_and_sing_box() {
    let clash = |extra: &str| {
        format!(
            "proxies:\n  - name: Gecko\n    type: hysteria2\n    server: hy.example.com\n    port: 443\n    password: hy-secret\n{extra}"
        )
    };
    let sing_box = |extra: Value| {
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": "Gecko",
            "server": "hy.example.com",
            "server_port": 443,
            "password": "hy-secret",
            "tls": { "enabled": true, "server_name": "hy.example.com" }
        });
        for (key, value) in extra.as_object().expect("extra fields") {
            outbound[key] = value.clone();
        }
        json!({ "outbounds": [outbound] }).to_string()
    };
    for (label, document) in [
        (
            "Clash",
            clash(
                "    obfs: gecko\n    obfs-password: mask-secret\n    obfs-min-packet-size: 400\n    obfs-max-packet-size: 1400\n    bbr-profile: conservative\n",
            ),
        ),
        (
            "sing-box",
            sing_box(json!({
                "obfs": {"type": "gecko", "password": "mask-secret", "min_packet_size": 400, "max_packet_size": 1400},
                "bbr_profile": "conservative"
            })),
        ),
    ] {
        let imported = import_subscription_document(&document).expect(label);
        let profile: Value =
            serde_json::from_str(imported.profile.as_json()).expect("canonical profile");
        let outbound = &profile["outbounds"][0];
        assert_eq!(outbound["obfs"]["type"], "gecko", "{label}");
        assert_eq!(
            outbound["obfs"]["credential_ref"]["kind"], "hysteria2_obfs_password",
            "{label}"
        );
        assert_eq!(outbound["obfs"]["min_packet_size"], 400, "{label}");
        assert_eq!(outbound["obfs"]["max_packet_size"], 1400, "{label}");
        assert_eq!(outbound["bbr_profile"], "conservative", "{label}");
        assert!(
            imported
                .credentials
                .iter()
                .any(|credential| credential.secret == "mask-secret"),
            "{label}"
        );
    }
    let defaults =
        import_subscription_document(&clash("    obfs: gecko\n    obfs-password: mask-secret\n"))
            .expect("gecko with the runtime packet sizes");
    let profile: Value = serde_json::from_str(defaults.profile.as_json()).expect("profile");
    assert!(
        profile["outbounds"][0]["obfs"]
            .get("min_packet_size")
            .is_none()
    );

    for (label, document, expected) in [
        (
            "Clash unknown BBR profile",
            clash("    bbr-profile: fast\n"),
            "bbr-profile",
        ),
        (
            "Clash BBR profile beside Brutal upload",
            clash("    up: 100\n    bbr-profile: standard\n"),
            "bbr_profile is ignored when up_mbps selects Brutal",
        ),
        (
            "Clash salamander packet size",
            clash(
                "    obfs: salamander\n    obfs-password: mask-secret\n    obfs-min-packet-size: 400\n",
            ),
            "unsupported keys",
        ),
        (
            "Clash gecko packet size beyond the wire limit",
            clash(
                "    obfs: gecko\n    obfs-password: mask-secret\n    obfs-max-packet-size: 4096\n",
            ),
            "gecko packet sizes",
        ),
        (
            "sing-box Chrome parrot switch",
            sing_box(json!({"disable_chrome_parrot": true})),
            "disable_chrome_parrot is unsupported",
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert!(error.contains(expected), "{label}: {error}");
        assert!(!error.contains("mask-secret"), "{label}: {error}");
    }
}

#[test]
fn hysteria2_share_links_import_pin_sha256_as_a_certificate_pin() {
    let upper_colons = ASCENDING_PIN_HEX
        .to_ascii_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).expect("ASCII hex"))
        .collect::<Vec<_>>()
        .join(":");
    let dashes = upper_colons.to_ascii_lowercase().replace(':', "-");
    for (label, uri) in [
        (
            "hy2 scheme, OpenSSL form",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={upper_colons}#HY2"
            ),
        ),
        (
            "hysteria2 scheme, dashes",
            format!(
                "hysteria2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={dashes}#HY2"
            ),
        ),
        (
            "percent-encoded colons",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={}#HY2",
                upper_colons.replace(':', "%3A")
            ),
        ),
        (
            "explicit insecure=0",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&insecure=0&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
        (
            // Upstream pairs insecure=1 with a pin for self-signed servers. CFM
            // verifies the pin with the name and validity checks and never
            // emits insecure.
            "insecure=1 beside a pin",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&insecure=1&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
        (
            "every insecure alias beside a pin",
            format!(
                "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&allowInsecure=1&allow_insecure=true&skip-cert-verify=1&pinSHA256={ASCENDING_PIN_HEX}#HY2"
            ),
        ),
    ] {
        let imported =
            import_subscription_document(&uri).unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(
            imported_outbounds(&imported)[0]["tls"],
            json!({"enabled":true,"server_name":"hy2.example.com","certificate_sha256":[ASCENDING_PIN_BASE64]}),
            "{label}"
        );
        // The pin is profile data: the vault receives only the password.
        assert_eq!(imported.credentials.len(), 1, "{label}");
        let runtime: Value = serde_json::from_str(&projected_json(&imported)).expect("runtime");
        let tls = &runtime["outbounds"][0]["tls"];
        assert_eq!(
            tls["certificate_sha256"],
            json!([ASCENDING_PIN_BASE64]),
            "{label}"
        );
        assert_eq!(tls["server_name"], "hy2.example.com", "{label}");
        assert!(tls.get("insecure").is_none(), "{label}");
        assert!(
            tls.get("certificate_public_key_sha256").is_none(),
            "{label}"
        );
    }
    let hopping = import_subscription_document(&format!(
        "hysteria2://TopSecretValue%21@hop.example.com:443,5000-5002?sni=hop.example.com&obfs=salamander&obfs-password=ObfsSecret&hop-interval=30&pinSHA256={ASCENDING_PIN_HEX}#HOP"
    ))
    .expect("pinned port-hopping link");
    let outbound = &imported_outbounds(&hopping)[0];
    assert_eq!(
        outbound["tls"]["certificate_sha256"],
        json!([ASCENDING_PIN_BASE64])
    );
    assert_eq!(outbound["server_ports"], json!(["443", "5000:5002"]));
    assert_eq!(outbound["hop_interval_seconds"], json!(30));
    assert_eq!(hopping.credentials.len(), 2);
    let pinned_to = |hex: &str| {
        import_subscription_document(&format!(
            "hy2://TopSecretValue%21@hy2.example.com:443?sni=hy2.example.com&pinSHA256={hex}#HY2"
        ))
        .expect("pinned link")
        .profile
        .digest()
        .to_owned()
    };
    assert_ne!(pinned_to(ASCENDING_PIN_HEX), pinned_to(&"ff".repeat(32)));
}

#[test]
fn reality_imports_without_utls_fail_at_import_instead_of_engine_start() {
    const PUBLIC_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
    let clash_vless = |fingerprint: &str| {
        format!(
            "proxies:\n  - name: Reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    servername: www.example.com\n{fingerprint}    reality-opts:\n      public-key: {PUBLIC_KEY}\n      short-id: 0123456789abcdef\n"
        )
    };
    let clash_anytls = format!(
        "proxies:\n  - name: AnyTLS\n    type: anytls\n    server: anytls.example.com\n    port: 443\n    password: TopSecretValue!\n    sni: front.example.com\n    reality-opts:\n      public-key: {PUBLIC_KEY}\n      short-id: 0123456789abcdef\n"
    );
    let vless_uri = |fingerprint: &str| {
        format!(
            "vless://22222222-2222-4222-8222-222222222222@vless.example.com:443?security=reality&sni=www.example.com&pbk={PUBLIC_KEY}&sid=0123456789abcdef{fingerprint}&encryption=none#Reality"
        )
    };
    let sing_box = |utls: Value| {
        let mut tls = json!({
            "enabled": true,
            "server_name": "www.example.com",
            "reality": {"enabled": true, "public_key": PUBLIC_KEY, "short_id": "0123456789abcdef"},
        });
        if !utls.is_null() {
            tls["utls"] = utls;
        }
        json!({"outbounds": [{
            "type": "vless", "tag": "Reality", "server": "vless.example.com",
            "server_port": 443, "uuid": "22222222-2222-4222-8222-222222222222", "tls": tls,
        }]})
        .to_string()
    };

    for (label, document) in [
        ("Clash VLESS without client-fingerprint", clash_vless("")),
        (
            "Clash VLESS with an empty client-fingerprint",
            clash_vless("    client-fingerprint: \"\"\n"),
        ),
        ("Clash AnyTLS without client-fingerprint", clash_anytls),
        ("VLESS URI without fp", vless_uri("")),
        ("VLESS URI with an empty fp", vless_uri("&fp=")),
        ("sing-box JSON without utls", sing_box(Value::Null)),
        (
            "sing-box JSON with an empty disabled utls",
            sing_box(json!({"enabled": false})),
        ),
    ] {
        let error = import_subscription_document(&document).expect_err(label);
        assert_eq!(
            error,
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls: Reality requires uTLS",
            "{label}"
        );
    }

    let accepted = [
        clash_vless("    client-fingerprint: chrome\n"),
        vless_uri("&fp=chrome"),
        sing_box(json!({"enabled": true, "fingerprint": "chrome"})),
    ];
    for document in accepted {
        let imported = import_subscription_document(&document).expect("Reality with uTLS");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(
            profile["outbounds"][0]["tls"]["utls"],
            json!({"enabled": true, "fingerprint": "chrome"})
        );
        assert_eq!(profile["outbounds"][0]["tls"]["reality"]["enabled"], true);
    }
}
