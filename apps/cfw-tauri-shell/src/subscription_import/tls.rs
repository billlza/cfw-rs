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
