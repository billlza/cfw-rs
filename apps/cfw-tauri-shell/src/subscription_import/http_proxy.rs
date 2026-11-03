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
mod tests;
