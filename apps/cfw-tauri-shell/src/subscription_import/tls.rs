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
}
