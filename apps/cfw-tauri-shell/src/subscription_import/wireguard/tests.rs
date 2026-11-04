use super::*;

fn source() -> String {
    "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\nMTU = 1380\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n".into()
}

#[test]
fn full_tunnel_file_preserves_keys_dns_mtu_and_address_family_scope() {
    let imported = super::super::import_subscription_document(&source()).expect("WireGuard file");
    let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
    assert_eq!(imported.credentials.len(), 1);
    assert_eq!(profile["outbounds"][0]["mtu"], 1380);
    assert_eq!(profile["outbounds"][0]["persistent_keepalive_seconds"], 25);
    assert_eq!(
        profile["outbounds"][0]["peer_allowed_ips"],
        json!(["0.0.0.0/0"])
    );
    assert_eq!(profile["dns"]["servers"][0]["server"], "10.64.0.1");
    assert!(!imported.profile.as_json().contains("AQEBAQE"));
}

#[test]
fn unsupported_hooks_split_routes_and_ambiguous_files_are_rejected() {
    for bad in [
        source().replace("MTU = 1380", "PostUp = echo PRIVATE"),
        source().replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 10.0.0.0/8"),
        source().replace("DNS = 10.64.0.1", "DNS = private.example"),
        source().replace("[Peer]", "[Peer]\n[Peer]"),
        source().replace("MTU = 1380", "MTU = 1380\nMTU = 1400"),
        source().replace("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "PRIVATE"),
    ] {
        let error = super::super::import_subscription_document(&bad).expect_err("invalid file");
        assert!(!error.contains("PRIVATE"));
    }
}

#[test]
fn comments_and_blank_lines_are_skipped_within_a_bounded_file_that_has_a_peer() {
    let import = |body: &str| super::super::import_subscription_document(body).map(|_| ());
    let commented = source().replace("[Peer]", "\n# the server\n[Peer] # trailing comment");
    assert_eq!(import(&commented), Ok(()));
    // 256 lines are read; a 257th is refused.
    let padded = |lines: usize| {
        let body = source();
        format!("{body}{}", "#\n".repeat(lines - body.lines().count()))
    };
    assert_eq!(import(&padded(256)), Ok(()));
    assert_eq!(
        import(&padded(257)),
        Err("WireGuard configuration exceeds 256 lines".into())
    );
    let interface_only = source()
        .split("[Peer]")
        .next()
        .expect("interface")
        .to_owned();
    assert_eq!(
        import(&interface_only),
        Err("WireGuard Peer section is missing".into())
    );
}
