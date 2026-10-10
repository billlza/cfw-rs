//! HTTP CONNECT import. Basic credentials use protocol-specific vault slots;
//! an omitted password is a valid empty Basic password, not an empty secret.
use super::{
    OutboundCollector, credential_ref_json, decode_url_component, host_string,
    port_from_url_or_default, reject_query_leftovers, split_fragment_strict, split_query_strict,
    validate_share_url_path,
};
use cfw_singbox_config::{CredentialKind, CredentialSecret};
use reqwest::Url;
use serde_json::{Value, json};

impl OutboundCollector {
    pub(super) fn http_proxy_outbound(
        &mut self,
        name: String,
        server: String,
        server_port: u16,
        username: Option<String>,
        password: Option<String>,
        tls: Option<Value>,
    ) -> Result<Value, String> {
        let mut outbound = json!({"type":"http","tag":self.unique_tag(name)?,"server":server,"server_port":server_port});
        match (
            username.filter(|value| !value.is_empty()),
            password.filter(|value| !value.is_empty()),
        ) {
            (None, None) => {}
            (None, Some(_)) => return Err("HTTP proxy password requires a username".into()),
            (Some(username), password) => {
                CredentialSecret::new(&username)
                    .and_then(|value| value.validate_for_kind(CredentialKind::HttpProxyUsername))
                    .map_err(|_| "HTTP proxy username is invalid")?;
                let username = self.push_secret(CredentialKind::HttpProxyUsername, username);
                let mut authentication =
                    json!({"username_credential_ref":credential_ref_json(&username)});
                if let Some(password) = password {
                    CredentialSecret::new(&password)
                        .and_then(|value| {
                            value.validate_for_kind(CredentialKind::HttpProxyPassword)
                        })
                        .map_err(|_| "HTTP proxy password is invalid")?;
                    let password = self.push_secret(CredentialKind::HttpProxyPassword, password);
                    authentication["password_credential_ref"] = credential_ref_json(&password);
                }
                outbound["authentication"] = authentication;
            }
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        Ok(outbound)
    }

    pub(super) fn parse_http_proxy(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        if entry.chars().any(char::is_control) {
            return Err("HTTP proxy URI contains control characters".into());
        }
        super::socks5::validate_percent_encoding(entry)?;
        let (without_fragment, name) = split_fragment_strict(entry, "HTTP proxy")?;
        let (address, mut query) = split_query_strict(without_fragment, "HTTP proxy")?;
        let url = Url::parse(address).map_err(|_| "HTTP proxy URI is invalid")?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("HTTP proxy URI scheme is invalid".into());
        }
        validate_share_url_path(&url, "HTTP proxy")?;
        let server = host_string(&url)?;
        let sni = query.remove("sni");
        reject_query_leftovers(&query, "HTTP proxy")?;
        let tls = if url.scheme() == "https" {
            Some(json!({"enabled":true,"server_name":sni.unwrap_or_else(||server.clone())}))
        } else if sni.is_some() {
            return Err("HTTP proxy SNI requires HTTPS".into());
        } else {
            None
        };
        let username = if url.username().is_empty() {
            None
        } else {
            Some(decode_url_component(url.username())?)
        };
        let password = url.password().map(decode_url_component).transpose()?;
        let port = port_from_url_or_default(&url, if tls.is_some() { 443 } else { 80 })?;
        self.http_proxy_outbound(
            name.unwrap_or_else(|| format!("HTTP-{index}")),
            server,
            port,
            username,
            password,
            tls,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::import_subscription_document;
    use cfw_singbox_config::{CredentialKind, EngineSettings, ProjectionMode};
    use serde_json::{Value, json};

    #[test]
    fn http_sources_keep_transport_and_protocol_specific_private_credentials() {
        for body in [
            "https://alice:p%3Ass@proxy.example.com:8443#Office".to_owned(),
            "proxies:\n  - name: Office\n    type: http\n    server: proxy.example.com\n    port: 8443\n    tls: true\n    username: alice\n    password: p:ss\n".to_owned(),
            json!({"outbounds":[{"type":"http","tag":"Office","server":"proxy.example.com","server_port":8443,"username":"alice","password":"p:ss","tls":{"enabled":true,"server_name":"proxy.example.com"}}]}).to_string(),
        ] {
            let imported=import_subscription_document(&body).unwrap();
            assert_eq!(imported.credentials.len(),2);
            assert_eq!(imported.credentials[0].reference.kind(),CredentialKind::HttpProxyUsername);
            assert_eq!(imported.credentials[1].reference.kind(),CredentialKind::HttpProxyPassword);
            assert_eq!(imported.credentials[1].secret,"p:ss");
            assert!(!imported.profile.as_json().contains("alice"));
            let projected=imported.profile.project("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",ProjectionMode::SystemProxy,&EngineSettings::default()).unwrap();
            let config:Value=serde_json::from_str(projected.as_json()).unwrap();
            assert_eq!(config["outbounds"][0]["type"],"http");
            assert_eq!(config["outbounds"][0]["tls"]["server_name"],"proxy.example.com");
            assert_eq!(projected.credential_slots().len(),2);
        }
    }

    #[test]
    fn http_anonymous_empty_password_and_unsafe_options_remain_distinct() {
        for (source, slots) in [
            ("http://proxy.example.com:8080#Anonymous", 0),
            ("http://alice:@proxy.example.com:8080#Empty", 1),
        ] {
            let imported = import_subscription_document(source).unwrap();
            assert_eq!(imported.credentials.len(), slots);
        }
        for source in [
            "https://a%3Ab:secret@proxy.example.com/#Bad",
            "https://alice:%00@proxy.example.com/#Bad",
            "https://proxy.example.com/?insecure=true#Bad",
            "http://proxy.example.com/?sni=other.example#Bad",
            "http://proxy.example.com/a#Bad",
        ] {
            assert!(import_subscription_document(source).is_err());
        }
    }
}
