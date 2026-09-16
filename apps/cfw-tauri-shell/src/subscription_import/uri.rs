//! Protocol-specific share-link conversion; collection and secret binding remain shared.
use super::{
    OutboundCollector, build_tls_parts, canonical_uuid_credential,
    consume_certificate_verification_flags, consume_empty_or_none_parameter,
    consume_required_tls_marker, consume_tls_marker, consume_unsupported_enabled_flag,
    credential_ref_json, decode_base64_text, decode_url_component, decoded_fragment_strict,
    host_string, normalize_shadowsocks_method_and_password, normalize_tuic_congestion_control,
    normalize_tuic_udp_relay_mode, normalize_v2ray_packet_encoding, normalize_vless_flow,
    parse_hysteria2_hop_interval_seconds, parse_hysteria2_share_url, parse_positive_u32,
    parse_utls, port_from_url, port_from_url_or_default, reject_query_leftovers,
    required_url_password, required_url_username, sanitized_token, split_csv,
    split_fragment_strict, split_host_port, split_query_strict, strict_query_map, take_query_alias,
    tls_json, transport_from_parts, validate_share_url_path,
};
use cfw_singbox_config::CredentialKind;
use reqwest::Url;
use serde_json::{Value, json};

impl OutboundCollector {
    pub(super) fn parse_shadowsocks(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let (without_fragment, tag) = split_fragment_strict(entry, "Shadowsocks")?;
        let (main, mut query) = split_query_strict(without_fragment, "Shadowsocks")?;
        if query.remove("plugin").is_some() {
            return Err("Shadowsocks plugins are unsupported in subscription imports".into());
        }
        reject_query_leftovers(&query, "Shadowsocks")?;
        let raw = main
            .strip_prefix("ss://")
            .ok_or_else(|| "invalid Shadowsocks URI".to_owned())?;
        let (credentials_part, host_port_part, legacy_full_base64) =
            if let Some((left, right)) = raw.rsplit_once('@') {
                (left.to_owned(), right.to_owned(), false)
            } else {
                let decoded = String::from_utf8(decode_base64_text(raw).map_err(|error| {
                    format!("Shadowsocks URI credentials are invalid base64: {error}")
                })?)
                .map_err(|_| "Shadowsocks URI credentials are not UTF-8".to_owned())?;
                let (left, right) = decoded
                    .rsplit_once('@')
                    .ok_or_else(|| "Shadowsocks URI must contain host and port".to_owned())?;
                (left.to_owned(), right.to_owned(), true)
            };
        let (method, password, base64_userinfo) = if legacy_full_base64 {
            let (method, password) = credentials_part
                .split_once(':')
                .ok_or_else(|| "Shadowsocks URI must contain method and password".to_owned())?;
            (method.to_owned(), password.to_owned(), true)
        } else if let Some((method, password)) = credentials_part.split_once(':') {
            (
                decode_url_component(method)?,
                decode_url_component(password)?,
                false,
            )
        } else {
            let encoded = decode_url_component(&credentials_part)?;
            let decoded = String::from_utf8(decode_base64_text(&encoded).map_err(|error| {
                format!("Shadowsocks URI method/password envelope is invalid base64: {error}")
            })?)
            .map_err(|_| "Shadowsocks URI method/password envelope is not UTF-8".to_owned())?;
            let (method, password) = decoded
                .split_once(':')
                .ok_or_else(|| "Shadowsocks URI must contain method and password".to_owned())?;
            (method.to_owned(), password.to_owned(), true)
        };
        let method = normalize_shadowsocks_method_and_password(&method, &password)?;
        if method.starts_with("2022-") && base64_userinfo {
            return Err(
                "Shadowsocks 2022 credentials must use percent-encoded plain userinfo".to_owned(),
            );
        }
        let (server, server_port) = split_host_port(&host_port_part)?;
        let reference = self.push_secret(CredentialKind::ShadowsocksPassword, password);
        let tag = self.unique_tag(tag.unwrap_or_else(|| format!("ss-{index}")))?;
        Ok(json!({
            "type": "shadowsocks",
            "tag": tag,
            "server": server,
            "server_port": server_port,
            "method": method,
            "credential_ref": credential_ref_json(&reference),
        }))
    }

    pub(super) fn parse_vless(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription VLESS URI is invalid".to_owned())?;
        validate_share_url_path(&url, "VLESS")?;
        if url.password().is_some() {
            return Err("VLESS URI must encode its UUID as the single user-info component".into());
        }
        let mut query = strict_query_map(&url, "VLESS")?;
        consume_certificate_verification_flags(&mut query, "VLESS")?;
        match query.remove("encryption") {
            None => {}
            Some(value) if value.is_empty() || value.eq_ignore_ascii_case("none") => {}
            Some(value) => {
                return Err(format!(
                    "VLESS encryption is unsupported: {}",
                    sanitized_token(&value)
                ));
            }
        }
        let reference = self.push_secret(
            CredentialKind::VlessUuid,
            canonical_uuid_credential(required_url_username(&url, "VLESS UUID")?, "VLESS UUID")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "VLESS")?.unwrap_or_else(|| format!("vless-{index}")),
        )?;
        let server = host_string(&url)?;
        let security = query.remove("security").unwrap_or_else(|| "none".into());
        let tls = match security.to_ascii_lowercase().as_str() {
            "none" | "" => None,
            "tls" => Some(tls_json(build_tls_parts(
                true,
                query.remove("sni").unwrap_or_else(|| server.clone()),
                split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                None,
            ))),
            "reality" => {
                let public_key = query
                    .remove("pbk")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "VLESS Reality public key is missing".to_owned())?;
                let short_id = query.remove("sid").unwrap_or_default();
                Some(tls_json(build_tls_parts(
                    true,
                    query.remove("sni").unwrap_or_else(|| server.clone()),
                    split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
                    parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
                    Some(json!({
                        "enabled": true,
                        "public_key": public_key,
                        "short_id": short_id,
                    })),
                )))
            }
            _ => {
                return Err(format!(
                    "VLESS security mode is unsupported: {}",
                    sanitized_token(&security)
                ));
            }
        };
        consume_empty_or_none_parameter(&mut query, "headerType", "VLESS header type")?;
        let packet_encoding = take_query_alias(
            &mut query,
            &["packetEncoding", "packet-encoding"],
            "VLESS",
            "packet encoding",
        )?;
        let packet_encoding = packet_encoding
            .map(|value| normalize_v2ray_packet_encoding(&value, "VLESS packet encoding"))
            .transpose()?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "VLESS",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        let flow = query.remove("flow").filter(|value| !value.is_empty());
        reject_query_leftovers(&query, "VLESS")?;
        let mut outbound = json!({
            "type": "vless",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
        });
        if let Some(flow) = flow {
            outbound["flow"] = Value::String(normalize_vless_flow(&flow)?);
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

    pub(super) fn parse_trojan(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription Trojan URI is invalid".to_owned())?;
        validate_share_url_path(&url, "Trojan")?;
        if url.password().is_some() {
            return Err("Trojan URI password must percent-encode reserved separators".into());
        }
        let mut query = strict_query_map(&url, "Trojan")?;
        consume_required_tls_marker(&mut query, "Trojan")?;
        consume_certificate_verification_flags(&mut query, "Trojan")?;
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::TrojanPassword,
            required_url_username(&url, "Trojan password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "Trojan")?.unwrap_or_else(|| format!("trojan-{index}")),
        )?;
        consume_empty_or_none_parameter(&mut query, "headerType", "Trojan header type")?;
        let transport = transport_from_parts(
            query.remove("type").as_deref().unwrap_or("tcp"),
            query.remove("path"),
            query.remove("host"),
            take_query_alias(
                &mut query,
                &["serviceName", "service_name"],
                "Trojan",
                "gRPC service name",
            )?,
            query.remove("method"),
        )?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
            None,
        ));
        reject_query_leftovers(&query, "Trojan")?;
        Ok(json!({
            "type": "trojan",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
            "transport": transport,
        }))
    }

    pub(super) fn parse_hysteria2(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let (url, server_ports) = parse_hysteria2_share_url(entry)?;
        validate_share_url_path(&url, "Hysteria2")?;
        if url.password().is_some() {
            return Err(
                "Hysteria2 URI must encode its password as the single user-info component".into(),
            );
        }
        let mut query = strict_query_map(&url, "Hysteria2")?;
        consume_tls_marker(&mut query, "Hysteria2")?;
        consume_certificate_verification_flags(&mut query, "Hysteria2")?;
        if query.remove("fp").is_some() {
            return Err("Hysteria2 does not support uTLS".into());
        }
        let server = host_string(&url)?;
        let reference = self.push_secret(
            CredentialKind::Hysteria2Password,
            required_url_username(&url, "Hysteria2 password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "Hysteria2")?.unwrap_or_else(|| format!("hy2-{index}")),
        )?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            None,
            None,
        ));
        let mut outbound = json!({
            "type": "hysteria2",
            "tag": tag,
            "server": server,
            "server_port": port_from_url_or_default(&url, 443)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
        });
        if let Some(server_ports) = server_ports {
            outbound["server_ports"] = json!(server_ports);
        }
        if let Some(value) = take_query_alias(
            &mut query,
            &["hop-interval", "hop_interval"],
            "Hysteria2",
            "hop interval",
        )? {
            outbound["hop_interval_seconds"] = json!(parse_hysteria2_hop_interval_seconds(
                &value,
                "Hysteria2 hop interval"
            )?);
        }
        if let Some(value) = query.remove("upmbps") {
            outbound["up_mbps"] = json!(parse_positive_u32(&value, "Hysteria2 upmbps")?);
        }
        if let Some(value) = query.remove("downmbps") {
            outbound["down_mbps"] = json!(parse_positive_u32(&value, "Hysteria2 downmbps")?);
        }
        if let Some(obfs) = query.remove("obfs")
            && !obfs.is_empty()
        {
            if obfs != "salamander" {
                return Err(format!(
                    "Hysteria2 obfs mode is unsupported: {}",
                    sanitized_token(&obfs)
                ));
            }
            let obfs_secret = query
                .remove("obfs-password")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "Hysteria2 obfs password is missing".to_owned())?;
            let reference = self.push_secret(CredentialKind::Hysteria2ObfsPassword, obfs_secret);
            outbound["obfs"] = json!({
                "type": "salamander",
                "credential_ref": credential_ref_json(&reference),
            });
        }
        reject_query_leftovers(&query, "Hysteria2")?;
        Ok(outbound)
    }

    pub(super) fn parse_anytls(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription AnyTLS URI is invalid".to_owned())?;
        validate_share_url_path(&url, "AnyTLS")?;
        if url.password().is_some() {
            return Err(
                "AnyTLS URI must encode its password as the single user-info component".into(),
            );
        }
        let mut query = strict_query_map(&url, "AnyTLS")?;
        consume_tls_marker(&mut query, "AnyTLS")?;
        consume_certificate_verification_flags(&mut query, "AnyTLS")?;
        let server = host_string(&url)?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            parse_utls(query.remove("fp").as_deref().unwrap_or_default())?,
            None,
        ));
        reject_query_leftovers(&query, "AnyTLS")?;
        let reference = self.push_secret(
            CredentialKind::AnyTlsPassword,
            required_url_username(&url, "AnyTLS password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "AnyTLS")?.unwrap_or_else(|| format!("anytls-{index}")),
        )?;
        Ok(json!({
            "type": "anytls",
            "tag": tag,
            "server": server,
            "server_port": port_from_url_or_default(&url, 443)?,
            "credential_ref": credential_ref_json(&reference),
            "tls": tls,
        }))
    }

    pub(super) fn parse_tuic(&mut self, entry: &str, index: usize) -> Result<Value, String> {
        let url = Url::parse(entry).map_err(|_| "subscription TUIC URI is invalid".to_owned())?;
        validate_share_url_path(&url, "TUIC")?;
        let mut query = strict_query_map(&url, "TUIC")?;
        consume_tls_marker(&mut query, "TUIC")?;
        consume_certificate_verification_flags(&mut query, "TUIC")?;
        consume_unsupported_enabled_flag(
            &mut query,
            &["zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt"],
            "TUIC 0-RTT handshake",
        )?;
        consume_unsupported_enabled_flag(
            &mut query,
            &["udp_over_stream", "udp-over-stream"],
            "TUIC UDP-over-stream",
        )?;
        let server = host_string(&url)?;
        let tls = tls_json(build_tls_parts(
            true,
            query.remove("sni").unwrap_or_else(|| server.clone()),
            split_csv(query.remove("alpn").as_deref().unwrap_or_default()),
            None,
            None,
        ));
        let congestion_control = query
            .remove("congestion_control")
            .map(|value| normalize_tuic_congestion_control(&value))
            .transpose()?;
        let udp_relay_mode = query
            .remove("udp_relay_mode")
            .map(|value| normalize_tuic_udp_relay_mode(&value))
            .transpose()?;
        reject_query_leftovers(&query, "TUIC")?;

        let uuid_reference = self.push_secret(
            CredentialKind::TuicUuid,
            canonical_uuid_credential(required_url_username(&url, "TUIC UUID")?, "TUIC UUID")?,
        );
        let password_reference = self.push_secret(
            CredentialKind::TuicPassword,
            required_url_password(&url, "TUIC password")?,
        );
        let tag = self.unique_tag(
            decoded_fragment_strict(&url, "TUIC")?.unwrap_or_else(|| format!("tuic-{index}")),
        )?;
        let mut outbound = json!({
            "type": "tuic",
            "tag": tag,
            "server": server,
            "server_port": port_from_url(&url)?,
            "uuid_credential_ref": credential_ref_json(&uuid_reference),
            "password_credential_ref": credential_ref_json(&password_reference),
            "tls": tls,
        });
        if let Some(value) = congestion_control {
            outbound["congestion_control"] = Value::String(value);
        }
        if let Some(value) = udp_relay_mode {
            outbound["udp_relay_mode"] = Value::String(value);
        }
        Ok(outbound)
    }
}
