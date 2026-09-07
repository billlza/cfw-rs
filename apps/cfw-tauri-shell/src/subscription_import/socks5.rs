//! SOCKS5 source normalization shared by URI, Clash, and sing-box adapters.
//!
//! The source may omit authentication or supply a complete RFC 1929 pair.
//! Credentials leave this boundary only through the existing vault batch;
//! stored outbounds contain references, never username or password bytes.

use cfw_singbox_config::{CredentialKind, CredentialSecret};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    OutboundCollector, credential_ref_json, decode_base64_text, decode_url_component, host_string,
    port_from_url, reject_query_leftovers, split_fragment_strict, split_query_strict,
    validate_share_url_path,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Network {
    Tcp,
    Udp,
}

impl OutboundCollector {
    pub(super) fn parse_socks5(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        if entry.chars().any(char::is_control) {
            return Err("SOCKS5 URI must not contain control characters".into());
        }
        validate_percent_encoding(entry)?;
        let (without_fragment, tag) = split_fragment_strict(entry, "SOCKS5")?;
        let (main, query) = split_query_strict(without_fragment, "SOCKS5")?;
        reject_query_leftovers(&query, "SOCKS5")?;
        let (scheme, authority) = main
            .split_once("://")
            .ok_or_else(|| "SOCKS5 URI is invalid".to_owned())?;
        if !scheme.eq_ignore_ascii_case("socks") && !scheme.eq_ignore_ascii_case("socks5") {
            return Err("SOCKS5 URI has an unsupported version".into());
        }

        // Split before URL parsing: standard base64 userinfo can contain '/'.
        // Only the endpoint goes through URL normalization, so credential
        // whitespace and reserved characters cannot be silently rewritten.
        let (endpoint, username, password) = match authority.rsplit_once('@') {
            None => (authority, None, None),
            Some((userinfo, endpoint)) => {
                if userinfo.is_empty() || userinfo.contains('@') {
                    return Err("SOCKS5 URI authentication is invalid".into());
                }
                let (username, password) = decode_authentication(userinfo)?;
                (endpoint, Some(username), Some(password))
            }
        };
        let url = Url::parse(&format!("socks5://{endpoint}"))
            .map_err(|_| "SOCKS5 URI endpoint is invalid".to_owned())?;
        validate_share_url_path(&url, "SOCKS5")?;
        self.socks5_outbound(
            tag.unwrap_or_else(|| format!("socks5-{index}")),
            host_string(&url)?,
            port_from_url(&url)?,
            username,
            password,
            None,
        )
    }

    pub(super) fn socks5_outbound(
        &mut self,
        name: String,
        server: String,
        server_port: u16,
        username: Option<String>,
        password: Option<String>,
        network: Option<Network>,
    ) -> Result<Value, String> {
        let authentication = match (username, password) {
            (None, None) => None,
            (Some(username), Some(password)) => {
                for (kind, value) in [
                    (CredentialKind::Socks5Username, &username),
                    (CredentialKind::Socks5Password, &password),
                ] {
                    CredentialSecret::new(value)
                        .and_then(|secret| secret.validate_for_kind(kind))
                        .map_err(|_| {
                            "SOCKS5 username and password must each contain 1..=255 UTF-8 bytes without control characters"
                                .to_owned()
                        })?;
                }
                let username = self.push_secret(CredentialKind::Socks5Username, username);
                let password = self.push_secret(CredentialKind::Socks5Password, password);
                Some(json!({
                    "username_credential_ref": credential_ref_json(&username),
                    "password_credential_ref": credential_ref_json(&password),
                }))
            }
            _ => return Err("SOCKS5 authentication requires both username and password".into()),
        };
        let mut outbound = json!({
            "type": "socks5",
            "tag": self.unique_tag(name)?,
            "server": server,
            "server_port": server_port,
        });
        if let Some(authentication) = authentication {
            outbound["authentication"] = authentication;
        }
        if let Some(network) = network {
            outbound["network"] = json!(network);
        }
        Ok(outbound)
    }
}

fn decode_authentication(userinfo: &str) -> Result<(String, String), String> {
    if let Some((username, password)) = userinfo.split_once(':') {
        return Ok((
            decode_url_component(username)?,
            decode_url_component(password)?,
        ));
    }
    let encoded = decode_url_component(userinfo)?;
    let decoded = String::from_utf8(decode_base64_text(&encoded).map_err(|_| {
        "SOCKS5 URI authentication must be a username/password pair or base64 envelope".to_owned()
    })?)
    .map_err(|_| "SOCKS5 URI authentication envelope is not UTF-8".to_owned())?;
    let (username, password) = decoded
        .split_once(':')
        .ok_or_else(|| "SOCKS5 URI authentication envelope has no password separator".to_owned())?;
    Ok((username.to_owned(), password.to_owned()))
}

fn validate_percent_encoding(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && (!bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit()))
        {
            return Err("SOCKS5 URI contains invalid percent-encoding".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use cfw_singbox_config::{EngineSettings, ProjectionMode};
    use uuid::Uuid;

    use super::super::{
        ImportedSubscription, MAX_SUBSCRIPTION_DOCUMENT_BYTES, import_subscription_document,
        import_subscription_document_with_credential_namespace,
        import_subscription_document_with_reusable_references,
    };
    use super::*;

    const PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    fn assert_authentication(imported: &ImportedSubscription, username: &str, password: &str) {
        assert_eq!(imported.credentials.len(), 2);
        assert_eq!(
            imported.credentials[0].reference.kind(),
            CredentialKind::Socks5Username
        );
        assert_eq!(imported.credentials[0].secret, username);
        assert_eq!(
            imported.credentials[1].reference.kind(),
            CredentialKind::Socks5Password
        );
        assert_eq!(imported.credentials[1].secret, password);
        assert!(!imported.profile.as_json().contains(username));
        assert!(!imported.profile.as_json().contains(password));
        assert!(!format!("{imported:?}").contains(password));
        for mode in [ProjectionMode::SystemProxy, ProjectionMode::Tunnel] {
            let projection = imported
                .profile
                .project(PROFILE_ID, mode, &EngineSettings::default())
                .expect("SOCKS5 projection");
            let wire: Value = serde_json::from_str(projection.as_json()).expect("runtime JSON");
            assert_eq!(wire["outbounds"][0]["type"], "socks");
            assert_eq!(wire["outbounds"][0]["username"], "");
            assert_eq!(wire["outbounds"][0]["password"], "");
            assert_eq!(projection.credential_slots().len(), 2);
        }
    }

    #[test]
    fn socks5_uri_authentication_preserves_plain_percent_and_base64_bytes() {
        let username = " synthetic user ";
        let password = " p@ss:word+/?#% ";
        let pair = format!("{username}:{password}");
        for scheme in ["socks", "socks5", "SOCKS5"] {
            for userinfo in [
                format!(
                    "{}:{}",
                    urlencoding::encode(username),
                    urlencoding::encode(password)
                ),
                STANDARD.encode(&pair),
                URL_SAFE_NO_PAD.encode(&pair),
            ] {
                let imported = import_subscription_document(&format!(
                    "{scheme}://{userinfo}@proxy.example.com:29177#Imported%20SOCKS5"
                ))
                .expect("authenticated SOCKS5 URI");
                assert_authentication(&imported, username, password);
            }
        }
        let encoded = STANDARD.encode("synthetic-user:???");
        assert!(
            encoded.contains('/'),
            "fixture must exercise a base64 slash before @"
        );
        let imported =
            import_subscription_document(&format!("socks://{encoded}@proxy.example.com:1080"))
                .expect("standard base64 userinfo may contain a slash");
        assert_authentication(&imported, "synthetic-user", "???");
    }

    #[test]
    fn socks5_anonymous_uris_support_domain_ipv4_and_ipv6_endpoints() {
        for (authority, expected) in [
            ("proxy.example.com", "proxy.example.com"),
            ("9.9.9.9", "9.9.9.9"),
            ("[2606:4700:4700::1111]", "2606:4700:4700::1111"),
        ] {
            let imported = import_subscription_document(&format!("socks5://{authority}:1080/"))
                .expect("anonymous SOCKS5 URI");
            let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
            assert_eq!(profile["outbounds"][0]["server"], expected);
            assert!(profile["outbounds"][0].get("authentication").is_none());
            assert!(imported.credentials.is_empty());
        }
    }

    #[test]
    fn socks5_uri_rejects_invalid_authentication_extensions_and_endpoints_without_echoing_secrets()
    {
        for uri in [
            "socks5://synthetic-user@proxy.example.com:1080",
            "socks5://synthetic-user:@proxy.example.com:1080",
            "socks5://:synthetic-secret@proxy.example.com:1080",
            "socks5://@proxy.example.com:1080",
            "socks5://synthetic-user:synthetic-secret@extra@proxy.example.com:1080",
            "socks5://synthetic-user:%GG@proxy.example.com:1080",
            "socks5://synthetic-user:bad%0Asecret@proxy.example.com:1080",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com:0",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com:65536",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080/path",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080?tls=true",
            "socks5://synthetic-user:synthetic-secret@proxy.example.com:1080?udp-over-tcp=true",
            "socks5://synthetic-user:synthetic-secret@127.0.0.1:1080",
            "socks5://synthetic-user:synthetic-secret@[::1]:1080",
            "socks4://synthetic-user:synthetic-secret@proxy.example.com:1080",
        ] {
            let error = import_subscription_document(uri).expect_err("unsupported SOCKS source");
            assert!(!error.contains("synthetic-user"));
            assert!(!error.contains("synthetic-secret"));
        }
        for pair in [
            "missing-separator".to_owned(),
            "synthetic-user:".to_owned(),
            format!("synthetic-user:{}", "x".repeat(256)),
        ] {
            let uri = format!("socks://{}@proxy.example.com:1080", STANDARD.encode(pair));
            assert!(import_subscription_document(&uri).is_err());
        }
    }

    #[test]
    fn socks5_clash_import_preserves_authentication_and_udp_policy() {
        for (udp, expected_network) in [
            ("", Some("tcp")),
            ("    udp: false\n", Some("tcp")),
            ("    udp: true\n", None),
        ] {
            let body = format!(
                "proxies:\n  - name: SOCKS5\n    type: socks5\n    server: proxy.example.com\n    port: 29177\n    username: '012345'\n    password: ' synthetic-secret '\n{udp}"
            );
            let imported = import_subscription_document(&body).expect("Clash SOCKS5");
            assert_authentication(&imported, "012345", " synthetic-secret ");
            let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
            assert_eq!(
                profile["outbounds"][0]
                    .get("network")
                    .and_then(Value::as_str),
                expected_network
            );
        }
        let anonymous = "proxies:\n  - { name: SOCKS5, type: socks5, server: proxy.example.com, port: 1080, udp: true }";
        assert!(
            import_subscription_document(anonymous)
                .expect("anonymous Clash SOCKS5")
                .credentials
                .is_empty()
        );
        for extra in [
            "username: synthetic-user",
            "password: synthetic-secret",
            "tls: true",
            "udp-over-tcp: true",
            "udp: 'true'",
            "unexpected: synthetic-secret",
        ] {
            let body = format!(
                "proxies:\n  - name: SOCKS5\n    type: socks5\n    server: proxy.example.com\n    port: 1080\n    {extra}\n"
            );
            let error =
                import_subscription_document(&body).expect_err("unsupported Clash SOCKS5 option");
            assert!(!error.contains("synthetic-secret"));
        }
    }

    #[test]
    fn socks5_sing_box_import_maps_only_version_five_and_preserves_network() {
        for network in [None, Some("tcp"), Some("udp")] {
            let mut node = json!({"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":1080,"username":"synthetic-user","password":"synthetic-secret"});
            if let Some(network) = network {
                node["network"] = json!(network);
            }
            for version in [None, Some("5")] {
                if let Some(version) = version {
                    node["version"] = json!(version);
                }
                let imported =
                    import_subscription_document(&json!({"outbounds":[node.clone()]}).to_string())
                        .expect("sing-box SOCKS5");
                assert_authentication(&imported, "synthetic-user", "synthetic-secret");
                let profile: Value =
                    serde_json::from_str(imported.profile.as_json()).expect("profile");
                assert_eq!(
                    profile["outbounds"][0]
                        .get("network")
                        .and_then(Value::as_str),
                    network
                );
            }
        }
        let node =
            json!({"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":1080});
        assert!(
            import_subscription_document(&json!({"outbounds":[node.clone()]}).to_string())
                .expect("anonymous sing-box SOCKS5")
                .credentials
                .is_empty()
        );
        for (field, value) in [
            ("version", json!("4")),
            ("version", json!("4a")),
            ("username", json!("synthetic-user")),
            ("password", json!("synthetic-secret")),
            ("network", json!("tcp,udp")),
            ("udp_over_tcp", json!(true)),
            ("tls", json!({"enabled":true})),
        ] {
            let mut invalid = node.clone();
            invalid[field] = value;
            let error = import_subscription_document(&json!({"outbounds":[invalid]}).to_string())
                .expect_err("unsupported sing-box SOCKS5 option");
            assert!(!error.contains("synthetic-secret"));
        }
    }

    #[test]
    fn socks5_bundles_keep_credential_identity_across_preview_and_update() {
        let uri = "socks://synthetic-user:synthetic-secret@proxy.example.com:1080#SOCKS5";
        let namespace = Uuid::parse_str(PROFILE_ID).expect("namespace");
        let first = import_subscription_document_with_credential_namespace(uri, namespace)
            .expect("preview");
        let replay = import_subscription_document_with_credential_namespace(uri, namespace)
            .expect("commit reconstruction");
        assert_eq!(first, replay);
        let updated = import_subscription_document_with_reusable_references(
            uri,
            first.profile.credential_references_in_outbound_order(),
        )
        .expect("unchanged update");
        assert_eq!(first, updated);
        let bundle = STANDARD.encode(format!("{uri}\n{uri}"));
        let imported = import_subscription_document(&bundle).expect("base64 SOCKS5 bundle");
        let profile: Value = serde_json::from_str(imported.profile.as_json()).expect("profile");
        assert_eq!(profile["outbounds"][0]["tag"], "SOCKS5");
        assert_eq!(profile["outbounds"][1]["tag"], "SOCKS5-2");
        assert_eq!(imported.credentials.len(), 4);
    }

    #[test]
    fn source_documents_are_bounded_before_parsing_or_base64_expansion() {
        let body = "x".repeat(MAX_SUBSCRIPTION_DOCUMENT_BYTES + 1);
        assert!(
            import_subscription_document(&body)
                .expect_err("oversized source")
                .contains("byte limit")
        );
    }
}
