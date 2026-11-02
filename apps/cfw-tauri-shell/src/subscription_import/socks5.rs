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

pub(super) fn validate_percent_encoding(value: &str) -> Result<(), String> {
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
mod tests;
