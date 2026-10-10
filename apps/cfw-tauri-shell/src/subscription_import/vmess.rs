//! Protocol-specific share-link conversion; collection and secret binding remain shared.
use super::{
    OutboundCollector, build_tls_parts, canonical_uuid_credential,
    consume_certificate_verification_flags, consume_empty_or_none_parameter, credential_ref_json,
    decode_base64_text, decoded_fragment_strict, host_string, non_empty,
    normalize_v2ray_packet_encoding, normalize_vmess_alter_id, normalize_vmess_security,
    parse_port_value, parse_uri_boolean, parse_utls, parse_vmess_alter_id, port_from_url,
    reject_query_leftovers, required_url_username, sanitized_token, split_csv, strict_query_map,
    take_query_alias, tls_json, transport_from_parts, validate_share_url_path,
};
use cfw_singbox_config::CredentialKind;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VmessPayload {
    #[serde(default)]
    v: Option<VmessVersion>,
    #[serde(default)]
    ps: String,
    add: String,
    port: serde_json::Value,
    id: String,
    #[serde(default)]
    aid: VmessAid,
    #[serde(default)]
    scy: String,
    #[serde(default)]
    net: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    tls: String,
    #[serde(default)]
    sni: String,
    #[serde(default)]
    alpn: String,
    #[serde(default)]
    fp: String,
    #[serde(default, rename = "serviceName")]
    service_name: String,
    #[serde(default, rename = "type")]
    header_type: String,
    #[serde(default)]
    insecure: Option<VmessBoolean>,
    #[serde(default)]
    vcn: String,
    #[serde(default)]
    pcs: String,
    #[serde(default, rename = "packetEncoding")]
    packet_encoding: String,
    #[serde(default)]
    method: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessVersion {
    Text(String),
    Integer(u64),
}

impl VmessVersion {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Text(value) if value == "2" => Ok(()),
            Self::Integer(2) => Ok(()),
            Self::Text(value) => Err(format!(
                "vmess URI version is unsupported: {}",
                sanitized_token(value)
            )),
            Self::Integer(_) => Err("vmess URI version is unsupported".to_owned()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessBoolean {
    Boolean(bool),
    Text(String),
    Integer(u8),
}

impl VmessBoolean {
    fn parse(&self, field: &str) -> Result<bool, String> {
        match self {
            Self::Boolean(value) => Ok(*value),
            Self::Text(value) => parse_uri_boolean(value, "vmess", field),
            Self::Integer(0) => Ok(false),
            Self::Integer(1) => Ok(true),
            Self::Integer(_) => Err(format!("vmess URI field {field} must be a boolean")),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum VmessAid {
    Text(String),
    Integer(u64),
}

impl Default for VmessAid {
    fn default() -> Self {
        Self::Integer(0)
    }
}

impl VmessAid {
    fn parse(&self) -> Result<u8, String> {
        match self {
            Self::Text(value) => parse_vmess_alter_id(value, "vmess URI aid"),
            Self::Integer(value) => normalize_vmess_alter_id(*value, "vmess URI aid"),
        }
    }
}

impl OutboundCollector {
    pub(super) fn parse_vmess(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let encoded = entry
            .trim()
            .strip_prefix("vmess://")
            .ok_or_else(|| "invalid vmess URI".to_owned())?;
        let authority_end = encoded.find(['?', '#']).unwrap_or(encoded.len());
        if encoded[..authority_end].contains('@') {
            return self.parse_vmess_url(entry, index);
        }
        let payload = String::from_utf8(
            decode_base64_text(encoded)
                .map_err(|error| format!("vmess URI payload is invalid base64: {error}"))?,
        )
        .map_err(|_| "vmess URI payload is not UTF-8".to_owned())?;
        let payload: VmessPayload = serde_json::from_str(&payload)
            .map_err(|_| "vmess URI payload does not match the supported schema".to_owned())?;
        if let Some(version) = &payload.v {
            version.validate()?;
        }
        if !matches!(payload.header_type.as_str(), "" | "none") {
            return Err(format!(
                "vmess header type is unsupported: {}",
                sanitized_token(&payload.header_type)
            ));
        }
        if payload
            .insecure
            .as_ref()
            .map(|value| value.parse("insecure"))
            .transpose()?
            .unwrap_or(false)
        {
            return Err("vmess URI requires disabling TLS certificate verification".into());
        }
        if !payload.vcn.is_empty() {
            return Err("vmess certificate domain verification is unsupported".into());
        }
        if !payload.pcs.is_empty() {
            return Err("vmess pinned certificate verification is unsupported".into());
        }
        let packet_encoding = non_empty(payload.packet_encoding)
            .map(|value| normalize_v2ray_packet_encoding(&value, "vmess packet encoding"))
            .transpose()?;
        let alter_id = payload.aid.parse()?;
        let reference = self.push_secret(
            CredentialKind::VmessUuid,
            canonical_uuid_credential(payload.id, "VMess UUID")?,
        );
        let tag =
            self.unique_tag(non_empty(payload.ps).unwrap_or_else(|| format!("vmess-{index}")))?;
        let server_port = parse_port_value(&payload.port)?;
        let tls = match payload.tls.to_ascii_lowercase().as_str() {
            "" | "none" => None,
            "tls" => {
                let parts = build_tls_parts(
                    true,
                    non_empty(payload.sni).unwrap_or_else(|| payload.add.clone()),
                    split_csv(&payload.alpn),
                    parse_utls(payload.fp.as_str())?,
                    None,
                );
                Some(tls_json(parts))
            }
            other => {
                return Err(format!(
                    "vmess TLS mode is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        let transport = transport_from_parts(
            payload.net.as_str(),
            non_empty(payload.path),
            non_empty(payload.host),
            non_empty(payload.service_name),
            non_empty(payload.method),
        )?;
        let mut outbound = json!({
            "type": "vmess",
            "tag": tag,
            "server": payload.add,
            "server_port": server_port,
            "credential_ref": credential_ref_json(&reference),
        });
        if alter_id != 0 {
            outbound["alter_id"] = Value::from(alter_id);
        }
        if let Some(security) = normalize_vmess_security(payload.scy.as_str())? {
            outbound["security"] = Value::String(security);
        }
        if let Some(packet_encoding) = packet_encoding {
            outbound["packet_encoding"] = Value::String(packet_encoding);
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        Ok(outbound)
    }

    pub(super) fn parse_vmess_url(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry)
            .map_err(|_| "subscription VMess URL-shaped URI is invalid".to_owned())?;
        validate_share_url_path(&url, "VMess")?;
        if url.password().is_some() {
            return Err("VMess URI must encode its UUID as the single user-info component".into());
        }
        let mut query = strict_query_map(&url, "VMess")?;
        consume_certificate_verification_flags(&mut query, "VMess")?;
        let uuid =
            canonical_uuid_credential(required_url_username(&url, "VMess UUID")?, "VMess UUID")?;
        let server = host_string(&url)?;
        let encryption = query.remove("encryption").unwrap_or_else(|| "auto".into());
        if encryption.is_empty() {
            return Err("VMess URI encryption must not be empty".to_owned());
        }
        let encryption = match encryption.to_ascii_lowercase().as_str() {
            "auto" => None,
            "none" | "aes-128-gcm" | "chacha20-poly1305" => Some(encryption.to_ascii_lowercase()),
            other => {
                return Err(format!(
                    "VMess URL-shaped encryption is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        let security = query.remove("security").unwrap_or_else(|| "none".into());
        let tls = match security.to_ascii_lowercase().as_str() {
            "none" => None,
            "tls" => Some(tls_json(build_tls_parts(
                true,
                query.remove("sni").unwrap_or_else(|| server.clone()),
                split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                None,
            ))),
            other => {
                return Err(format!(
                    "VMess URL-shaped security mode is unsupported: {}",
                    sanitized_token(other)
                ));
            }
        };
        consume_empty_or_none_parameter(&mut query, "headerType", "VMess header type")?;
        let packet_encoding = take_query_alias(
            &mut query,
            &["packetEncoding", "packet-encoding"],
            "VMess",
            "packet encoding",
        )?
        .map(|value| normalize_v2ray_packet_encoding(&value, "VMess packet encoding"))
        .transpose()?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "VMess",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        reject_query_leftovers(&query, "VMess")?;

        let reference = self.push_secret(CredentialKind::VmessUuid, uuid);
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "VMess")?.unwrap_or_else(|| format!("vmess-{index}")),
        )?;
        let mut outbound = json!({
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(encryption) = encryption {
            outbound["security"] = Value::String(encryption);
        }
        if let Some(packet_encoding) = packet_encoding {
            outbound["packet_encoding"] = Value::String(packet_encoding);
        }
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        Ok(outbound)
    }
}
