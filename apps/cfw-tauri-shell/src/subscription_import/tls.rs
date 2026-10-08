use base64::{Engine as _, engine::general_purpose::STANDARD};

/// Mihomo fingerprints hash the DER certificate, not its public key. Keep that
/// distinction in the model; accepting a pin never disables name/time checks.
pub(super) fn certificate_fingerprint(value: &str) -> Result<String, String> {
    let compact = value.replace(':', "");
    if compact.len() != 64 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("TLS certificate fingerprint must be a SHA256 hex value".into());
    }
    let mut bytes = Vec::with_capacity(32);
    for offset in (0..64).step_by(2) {
        bytes.push(
            u8::from_str_radix(&compact[offset..offset + 2], 16)
                .map_err(|_| "invalid TLS certificate fingerprint")?,
        );
    }
    Ok(STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription_import::import_subscription_document;
    use cfw_singbox_config::{EngineSettings, ProjectionMode};
    use serde_json::Value;
    #[test]
    fn clash_certificate_hash_keeps_its_identity_kind_in_projection() {
        let hex = "ab".repeat(32);
        let source = format!(
            "proxies:\n  - name: pinned\n    type: trojan\n    server: proxy.example.com\n    port: 443\n    password: synthetic\n    fingerprint: {hex}\n"
        );
        let imported = import_subscription_document(&source).unwrap();
        let config = imported
            .profile
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .unwrap();
        let config: Value = serde_json::from_str(config.as_json()).unwrap();
        assert_eq!(
            config["outbounds"][0]["tls"]["certificate_sha256"][0],
            STANDARD.encode([0xabu8; 32])
        );
        assert!(
            config["outbounds"][0]["tls"]
                .get("certificate_public_key_sha256")
                .is_none()
        );
        let separated = std::iter::repeat_n("AB", 32).collect::<Vec<_>>().join(":");
        assert_eq!(
            certificate_fingerprint(&separated).unwrap(),
            STANDARD.encode([0xabu8; 32])
        );
        assert!(certificate_fingerprint("ab").is_err());
    }

    #[test]
    fn reality_x25519mlkem768_key_share_is_an_opt_in_imported_from_clash_and_sing_box() {
        let reality = |imported: &crate::subscription_import::ImportedSubscription| {
            let stored: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
            stored["outbounds"][0]["tls"]["reality"].clone()
        };
        let clash = |fingerprint: &str, extra: &str| {
            format!(
                "proxies:\n  - name: reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    servername: www.example.com\n    client-fingerprint: {fingerprint}\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n      short-id: 0123456789abcdef\n{extra}"
            )
        };
        let sing_box = |extra: &str| {
            format!(
                r#"{{"outbounds":[{{"type":"vless","tag":"reality","server":"vless.example.com","server_port":443,"uuid":"22222222-2222-4222-8222-222222222222","tls":{{"enabled":true,"server_name":"www.example.com","utls":{{"enabled":true,"fingerprint":"chrome"}},"reality":{{"enabled":true,"public_key":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","short_id":"0123456789abcdef"{extra}}}}}}}]}}"#
            )
        };

        for source in [
            clash("chrome", "      support-x25519mlkem768: true\n"),
            sing_box(r#","support_x25519mlkem768":true"#),
        ] {
            let imported = import_subscription_document(&source).unwrap();
            assert_eq!(
                reality(&imported)["support_x25519mlkem768"],
                true,
                "{source}"
            );
        }
        for source in [
            clash("chrome", ""),
            clash("chrome", "      support-x25519mlkem768: false\n"),
            sing_box(""),
            sing_box(r#","support_x25519mlkem768":false"#),
        ] {
            let imported = import_subscription_document(&source).unwrap();
            assert!(
                reality(&imported).get("support_x25519mlkem768").is_none(),
                "{source}"
            );
        }

        let error =
            import_subscription_document(&clash("firefox", "      support-x25519mlkem768: true\n"))
                .expect_err("only the chrome hello carries the hybrid key share");
        assert_eq!(
            error,
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls.fingerprint: Reality X25519MLKEM768 requires the chrome uTLS fingerprint"
        );
        let error =
            import_subscription_document(&clash("chrome", "      support-x25519mlkem768: on\n"))
                .expect_err("the key share flag is a YAML boolean");
        assert!(error.contains("support-x25519mlkem768"), "{error}");
    }

    #[test]
    fn an_inherited_global_fingerprint_decides_the_reality_key_share_requirement() {
        let document = |global: &str| {
            format!(
                "global-client-fingerprint: {global}\nproxies:\n  - name: reality\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    tls: true\n    servername: www.example.com\n    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n      short-id: 0123456789abcdef\n      support-x25519mlkem768: true\n"
            )
        };
        let imported = import_subscription_document(&document("chrome")).unwrap();
        let stored: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert_eq!(
            stored["outbounds"][0]["tls"]["utls"]["fingerprint"],
            "chrome"
        );
        assert_eq!(
            stored["outbounds"][0]["tls"]["reality"]["support_x25519mlkem768"],
            true
        );

        let error = import_subscription_document(&document("firefox"))
            .expect_err("an inherited non-chrome fingerprint cannot carry the key share");
        assert_eq!(
            error,
            "unsupported credential-free policy shape at $.outbounds[0].tls.utls.fingerprint: Reality X25519MLKEM768 requires the chrome uTLS fingerprint"
        );
    }

    #[test]
    fn clash_ech_opts_import_an_inline_config_and_refuse_dns_fetched_ones() {
        let trojan = |extra: &str| {
            format!(
                "proxies:\n  - name: ech\n    type: trojan\n    server: proxy.example.com\n    port: 443\n    password: synthetic\n    sni: inner.example.com\n{extra}"
            )
        };
        let mut list = vec![0u8, 98];
        list.extend([0x5a; 98]);
        let config = STANDARD.encode(&list);
        let imported = import_subscription_document(&trojan(&format!(
            "    ech-opts:\n      enable: true\n      config: {config}\n"
        )))
        .expect("inline ECH config");
        let stored: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        let tls = &stored["outbounds"][0]["tls"];
        assert_eq!(tls["min_version"], "1.3");
        assert_eq!(tls["ech"]["enabled"], true);
        let lines = tls["ech"]["config"].as_array().expect("PEM lines");
        assert_eq!(lines.first().unwrap(), "-----BEGIN ECH CONFIGS-----");
        assert_eq!(lines.last().unwrap(), "-----END ECH CONFIGS-----");
        let body = lines[1..lines.len() - 1]
            .iter()
            .map(|line| line.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(body.iter().all(|line| line.len() <= 64), "{body:?}");
        assert_eq!(STANDARD.decode(body.concat()).unwrap(), list);
        let projected = imported
            .profile
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                ProjectionMode::SystemProxy,
                &EngineSettings::default(),
            )
            .unwrap();
        let runtime: Value = serde_json::from_str(projected.as_json()).unwrap();
        assert_eq!(
            runtime["outbounds"][0]["tls"]["ech"]["config"],
            tls["ech"]["config"]
        );

        let disabled =
            import_subscription_document(&trojan("    ech-opts:\n      enable: false\n"))
                .expect("disabled ECH sets nothing");
        let stored: Value = serde_json::from_str(disabled.profile.as_json()).unwrap();
        assert!(stored["outbounds"][0]["tls"].get("ech").is_none());

        for (label, extra, expected) in [
            (
                "DNS-fetched config",
                "    ech-opts:\n      enable: true\n".to_owned(),
                "ech-opts requires an inline config",
            ),
            (
                "query server name",
                format!(
                    "    ech-opts:\n      enable: true\n      config: {config}\n      query-server-name: ech.example.com\n"
                ),
                "query-server-name is unsupported",
            ),
            (
                "invalid base64",
                "    ech-opts:\n      enable: true\n      config: not*base64\n".to_owned(),
                "ech-opts.config",
            ),
            (
                "disabled with a config",
                format!("    ech-opts:\n      enable: false\n      config: {config}\n"),
                "ech-opts is disabled but carries",
            ),
            (
                "malformed ECHConfigList",
                "    ech-opts:\n      enable: true\n      config: AAEC\n".to_owned(),
                "ECHConfigList length is invalid",
            ),
        ] {
            let error = import_subscription_document(&trojan(&extra)).expect_err(label);
            assert!(error.contains(expected), "{label}: {error}");
        }

        let vless = "proxies:\n  - name: ech\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n    ech-opts:\n      enable: true\n      config: AAT+DQAA\n";
        let error = import_subscription_document(vless).expect_err("ECH without TLS");
        assert!(error.contains("ECH requires TLS"), "{error}");
    }

    #[test]
    fn clash_certificate_fingerprint_is_absent_when_empty_and_refused_without_tls_or_with_reality()
    {
        let vless = |extra: &str| {
            format!(
                "proxies:\n  - name: pinned\n    type: vless\n    server: vless.example.com\n    port: 443\n    uuid: 22222222-2222-4222-8222-222222222222\n{extra}"
            )
        };
        let pin = format!("    fingerprint: {}\n", "ab".repeat(32));

        let imported =
            import_subscription_document(&vless("    tls: true\n    fingerprint: \"\"\n"))
                .expect("an empty fingerprint is absent");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).unwrap();
        assert!(
            profile["outbounds"][0]["tls"]
                .get("certificate_sha256")
                .is_none()
        );

        let error = import_subscription_document(&vless(&pin)).expect_err("pin without TLS");
        assert!(error.contains("certificate pin requires TLS"), "{error}");

        let error = import_subscription_document(&vless(&format!(
            "    tls: true\n    client-fingerprint: chrome\n{pin}    reality-opts:\n      public-key: jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0\n"
        )))
        .expect_err("pin beside Reality");
        assert_eq!(
            error,
            "unsupported credential-free policy shape at $.outbounds[0]: certificate pinning requires TLS, one pin kind, and no Reality"
        );
    }
}
