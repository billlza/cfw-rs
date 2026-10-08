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
