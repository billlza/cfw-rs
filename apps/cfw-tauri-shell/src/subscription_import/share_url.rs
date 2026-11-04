//! Strict share-link parsing the URI adapters share: fragments, query
//! parameters, TLS markers, hosts, ports and encoded text.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use reqwest::Url;

use super::sanitized_token;

pub(super) fn split_fragment_strict<'a>(
    entry: &'a str,
    protocol: &str,
) -> Result<(&'a str, Option<String>), String> {
    match entry.split_once('#') {
        Some((before, fragment)) => decode_url_component(fragment)
            .map(|fragment| (before, Some(fragment)))
            .map_err(|_| format!("{protocol} URI fragment has invalid percent-encoding")),
        None => Ok((entry, None)),
    }
}

pub(super) fn split_query_strict<'a>(
    entry: &'a str,
    protocol: &str,
) -> Result<(&'a str, BTreeMap<String, String>), String> {
    match entry.split_once('?') {
        Some((before, query)) => Ok((before, strict_query_pairs(query, protocol)?)),
        None => Ok((entry, BTreeMap::new())),
    }
}

fn strict_query_pairs(encoded: &str, protocol: &str) -> Result<BTreeMap<String, String>, String> {
    let mut query = BTreeMap::new();
    for pair in encoded.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_url_component(key)
            .map_err(|_| format!("{protocol} URI query key has invalid percent-encoding"))?;
        let value = decode_url_component(value)
            .map_err(|_| format!("{protocol} URI query value has invalid percent-encoding"))?;
        if query.insert(key.clone(), value).is_some() {
            return Err(format!(
                "{protocol} URI repeats query parameter {}",
                sanitized_token(&key)
            ));
        }
    }
    Ok(query)
}

pub(super) fn strict_query_map(
    url: &Url,
    protocol: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut query = BTreeMap::new();
    for (key, value) in url.query_pairs() {
        let key = key.into_owned();
        if query.insert(key.clone(), value.into_owned()).is_some() {
            return Err(format!(
                "{protocol} URI repeats query parameter {}",
                sanitized_token(&key)
            ));
        }
    }
    Ok(query)
}

pub(super) fn validate_share_url_path(url: &Url, protocol: &str) -> Result<(), String> {
    if !matches!(url.path(), "" | "/") {
        return Err(format!("{protocol} URI path is unsupported"));
    }
    Ok(())
}

pub(super) fn required_url_username(url: &Url, label: &str) -> Result<String, String> {
    let decoded = decode_url_component(url.username())?;
    if decoded.is_empty() {
        return Err(format!("{label} is missing"));
    }
    Ok(decoded)
}

pub(super) fn required_url_password(url: &Url, label: &str) -> Result<String, String> {
    let encoded = url
        .password()
        .ok_or_else(|| format!("{label} is missing"))?;
    let decoded = decode_url_component(encoded)?;
    if decoded.is_empty() {
        return Err(format!("{label} is missing"));
    }
    Ok(decoded)
}

pub(super) fn decoded_fragment_strict(url: &Url, protocol: &str) -> Result<Option<String>, String> {
    url.fragment()
        .map(decode_url_component)
        .transpose()
        .map_err(|_| format!("{protocol} URI fragment has invalid percent-encoding"))
}

pub(super) fn consume_tls_marker(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    match query.remove("security") {
        None => Ok(()),
        Some(value) if value.eq_ignore_ascii_case("tls") => Ok(()),
        Some(value) => Err(format!(
            "{protocol} URI security mode is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

pub(super) fn consume_required_tls_marker(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    match query.remove("security") {
        None => Ok(()),
        Some(value) if value.is_empty() || value.eq_ignore_ascii_case("tls") => Ok(()),
        Some(value) => Err(format!(
            "{protocol} URI security mode is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

pub(super) fn consume_empty_or_none_parameter(
    query: &mut BTreeMap<String, String>,
    key: &str,
    feature: &str,
) -> Result<(), String> {
    match query.remove(key) {
        None => Ok(()),
        Some(value) if value.is_empty() || value.eq_ignore_ascii_case("none") => Ok(()),
        Some(value) => Err(format!(
            "{feature} is unsupported: {}",
            sanitized_token(&value)
        )),
    }
}

pub(super) fn take_query_alias(
    query: &mut BTreeMap<String, String>,
    keys: &[&str],
    protocol: &str,
    field: &str,
) -> Result<Option<String>, String> {
    let mut selected = None;
    for key in keys {
        if let Some(value) = query.remove(*key) {
            if selected.is_some() {
                return Err(format!(
                    "{protocol} URI repeats {field} using multiple aliases"
                ));
            }
            selected = Some(value);
        }
    }
    Ok(selected)
}

pub(super) fn consume_certificate_verification_flags(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    if certificate_verification_disabled(query, protocol)? {
        return Err(insecure_tls_error(protocol));
    }
    Ok(())
}

/// Consumes every alias of the link's "skip certificate verification" flag and
/// reports whether any of them is true. Callers other than
/// `consume_certificate_verification_flags` must still refuse a true value
/// unless something else authenticates the server.
pub(super) fn certificate_verification_disabled(
    query: &mut BTreeMap<String, String>,
    protocol: &str,
) -> Result<bool, String> {
    let mut disabled = false;
    for key in [
        "insecure",
        "allowInsecure",
        "allow_insecure",
        "skip-cert-verify",
    ] {
        if let Some(value) = query.remove(key) {
            disabled |= parse_uri_boolean(&value, protocol, key)?;
        }
    }
    Ok(disabled)
}

pub(super) fn insecure_tls_error(protocol: &str) -> String {
    format!("{protocol} URI requires disabling TLS certificate verification")
}

pub(super) fn consume_unsupported_enabled_flag(
    query: &mut BTreeMap<String, String>,
    keys: &[&str],
    feature: &str,
) -> Result<(), String> {
    for key in keys {
        if let Some(value) = query.remove(*key)
            && parse_uri_boolean(&value, feature, key)?
        {
            return Err(format!("{feature} is unsupported"));
        }
    }
    Ok(())
}

pub(super) fn parse_uri_boolean(value: &str, context: &str, key: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!(
            "{context} URI parameter {} must be a boolean",
            sanitized_token(key)
        )),
    }
}

pub(super) fn reject_query_leftovers(
    query: &BTreeMap<String, String>,
    protocol: &str,
) -> Result<(), String> {
    if query.is_empty() {
        return Ok(());
    }
    let keys = query
        .keys()
        .map(|key| sanitized_token(key))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!("{protocol} URI has unsupported parameters: {keys}"))
}

pub(super) fn decode_url_component(value: &str) -> Result<String, String> {
    urlencoding::decode(value)
        .map(|value| value.into_owned())
        .map_err(|error| format!("subscription URI contains invalid percent-encoding: {error}"))
}

pub(super) fn decode_base64_text(value: &str) -> Result<Vec<u8>, String> {
    let compact = value.trim();
    for candidate in [pad_base64(compact), compact.to_owned()] {
        if let Ok(decoded) = STANDARD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(candidate.as_bytes()) {
            return Ok(decoded);
        }
    }
    Err("input is not valid base64".into())
}

fn pad_base64(value: &str) -> String {
    match value.len() % 4 {
        0 => value.to_owned(),
        remainder => format!("{value}{}", "=".repeat(4 - remainder)),
    }
}

pub(super) fn split_host_port(value: &str) -> Result<(String, u16), String> {
    let parsed = Url::parse(&format!("tcp://{value}"))
        .map_err(|_| "subscription endpoint host or port is invalid".to_owned())?;
    Ok((host_string(&parsed)?, port_from_url(&parsed)?))
}

pub(super) fn host_string(url: &Url) -> Result<String, String> {
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "subscription endpoint host is missing".to_owned())?;
    // URL authorities bracket IPv6 literals; the typed profile stores the
    // address itself, matching every other endpoint source format.
    Ok(host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned())
}

pub(super) fn port_from_url(url: &Url) -> Result<u16, String> {
    url.port_or_known_default()
        .filter(|port| *port != 0)
        .ok_or_else(|| "subscription endpoint port is missing".to_owned())
}

pub(super) fn port_from_url_or_default(url: &Url, default: u16) -> Result<u16, String> {
    match url.port() {
        Some(0) => Err("subscription endpoint port is invalid".to_owned()),
        Some(port) => Ok(port),
        None if default != 0 => Ok(default),
        None => Err("subscription endpoint port is missing".to_owned()),
    }
}

pub(super) fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn non_empty(value: impl Into<String>) -> Option<String> {
    let value = value.into();
    (!value.is_empty()).then_some(value)
}

pub(super) fn parse_port_value(value: &serde_json::Value) -> Result<u16, String> {
    match value {
        serde_json::Value::String(value) => value
            .parse()
            .map_err(|_| "vmess port is invalid".to_owned()),
        serde_json::Value::Number(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| "vmess port is invalid".to_owned()),
        _ => Err("vmess port is invalid".into()),
    }
}

pub(super) fn parse_positive_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} must be a positive integer"))
}
