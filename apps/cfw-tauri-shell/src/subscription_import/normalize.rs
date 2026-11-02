//! Protocol options every adapter normalizes the same way: Shadowsocks
//! methods, VMess security and alterId, VLESS flow, V2Ray packet encoding and
//! HTTP method, and the TUIC modes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;
use zeroize::Zeroize;

use super::{MAX_SOURCE_VMESS_ALTER_ID, sanitized_token};

fn normalize_shadowsocks_method(method: &str) -> Result<String, String> {
    match method.to_ascii_lowercase().as_str() {
        "aes-128-gcm"
        | "aes-256-gcm"
        | "chacha20-ietf-poly1305"
        | "xchacha20-ietf-poly1305"
        | "2022-blake3-aes-128-gcm"
        | "2022-blake3-aes-256-gcm"
        | "2022-blake3-chacha20-poly1305" => Ok(method.to_ascii_lowercase()),
        other => Err(format!(
            "Shadowsocks method is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

pub(super) fn normalize_shadowsocks_method_and_password(
    method: &str,
    password: &str,
) -> Result<String, String> {
    let method = normalize_shadowsocks_method(method)?;
    let key_bytes = match method.as_str() {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return Ok(method),
    };
    for encoded_key in password.split(':') {
        let mut decoded_key = STANDARD.decode(encoded_key).map_err(|_| {
            format!(
                "Shadowsocks 2022 key chain must contain canonical standard-base64 {key_bytes}-byte keys"
            )
        })?;
        let valid_length = decoded_key.len() == key_bytes;
        decoded_key.zeroize();
        if !valid_length {
            return Err(format!(
                "Shadowsocks 2022 key chain must contain canonical standard-base64 {key_bytes}-byte keys"
            ));
        }
    }
    Ok(method)
}

pub(super) fn canonical_uuid_credential(value: String, label: &str) -> Result<String, String> {
    let parsed = Uuid::parse_str(&value).map_err(|_| format!("{label} is not a UUID"))?;
    if parsed.is_nil() {
        return Err(format!("{label} must not be the nil UUID"));
    }
    Ok(parsed.hyphenated().to_string())
}

pub(super) fn normalize_vmess_security(security: &str) -> Result<Option<String>, String> {
    if security.is_empty() || security.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    match security.to_ascii_lowercase().as_str() {
        "none" | "zero" | "aes-128-cfb" | "aes-128-gcm" | "chacha20-poly1305" => {
            Ok(Some(security.to_ascii_lowercase()))
        }
        other => Err(format!(
            "vmess security is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

pub(super) fn parse_vmess_alter_id(value: &str, field: &str) -> Result<u8, String> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{field} must be a canonical non-negative decimal integer no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        ));
    }
    let value = value.parse::<u64>().map_err(|_| {
        format!(
            "{field} must be a canonical non-negative decimal integer no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        )
    })?;
    normalize_vmess_alter_id(value, field)
}

pub(super) fn normalize_vmess_alter_id(value: u64, field: &str) -> Result<u8, String> {
    if value > MAX_SOURCE_VMESS_ALTER_ID {
        return Err(format!(
            "{field} must be no greater than {MAX_SOURCE_VMESS_ALTER_ID}"
        ));
    }
    // The pinned sing-box VMess contract treats every positive alter ID as
    // the same legacy protocol mode. Keep the stored profile closed to 0/1 so
    // equivalent source spellings cannot create different canonical state.
    Ok(u8::from(value != 0))
}

pub(super) fn normalize_vless_flow(flow: &str) -> Result<String, String> {
    match flow {
        "xtls-rprx-vision" => Ok(flow.to_owned()),
        other => Err(format!(
            "VLESS flow is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

pub(super) fn normalize_v2ray_packet_encoding(value: &str, field: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "" | "none" | "raw" => Ok("raw".to_owned()),
        "packetaddr" | "packet_addr" => Ok("packet_addr".to_owned()),
        "xudp" => Ok("xudp".to_owned()),
        other => Err(format!(
            "{field} is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

pub(super) fn normalize_v2ray_http_method(value: &str, field: &str) -> Result<String, String> {
    match value.to_ascii_uppercase().as_str() {
        "GET" | "PUT" | "POST" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => {
            Ok(value.to_ascii_uppercase())
        }
        _ => Err(format!(
            "{field} is unsupported: {}",
            sanitized_token(value)
        )),
    }
}

pub(super) fn normalize_tuic_congestion_control(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "cubic" | "new_reno" | "bbr" => Ok(value.to_ascii_lowercase()),
        other => Err(format!(
            "TUIC congestion control is unsupported: {}",
            sanitized_token(other)
        )),
    }
}

pub(super) fn normalize_tuic_udp_relay_mode(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "native" | "quic" => Ok(value.to_ascii_lowercase()),
        other => Err(format!(
            "TUIC UDP relay mode is unsupported: {}",
            sanitized_token(other)
        )),
    }
}
