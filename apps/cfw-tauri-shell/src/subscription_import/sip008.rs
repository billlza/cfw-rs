//! Shadowsocks SIP008 online-configuration conversion.
//!
//! SIP008 is a JSON delivery container, not a second runtime configuration
//! system. Root-level custom fields are metadata under the specification and
//! are ignored. Server entries stay strict: every connection-affecting field
//! must be understood, plugins are rejected, and passwords are extracted into
//! the credential vault before the closed profile is validated.

use std::collections::{BTreeMap, BTreeSet};

use cfw_singbox_config::{CredentialKind, MAX_OUTBOUNDS};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ImportedSubscription, OutboundCollector, credential_ref_json,
    normalize_shadowsocks_method_and_password,
};

#[derive(Debug, Deserialize)]
struct SourceDocument {
    version: u8,
    servers: Vec<SourceServer>,
    #[serde(default)]
    bytes_used: Option<u64>,
    #[serde(default)]
    bytes_remaining: Option<u64>,
    #[serde(flatten)]
    _custom_metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceServer {
    id: String,
    remarks: String,
    server: String,
    server_port: u16,
    password: String,
    method: String,
    #[serde(default)]
    plugin: String,
    #[serde(default)]
    plugin_opts: String,
}

pub(super) fn import_sip008_document(
    body: &str,
    mut collector: OutboundCollector,
) -> Result<ImportedSubscription, String> {
    let source: SourceDocument = serde_json::from_str(body)
        .map_err(|_| "SIP008 JSON does not match the supported schema".to_owned())?;
    if source.version != 1 {
        return Err("SIP008 JSON version is unsupported".to_owned());
    }
    if source.servers.is_empty() {
        return Err("SIP008 JSON contains no servers".to_owned());
    }
    if source.servers.len() > MAX_OUTBOUNDS {
        return Err(format!("SIP008 JSON has more than {MAX_OUTBOUNDS} servers"));
    }
    if source.bytes_remaining.is_some() && source.bytes_used.is_none() {
        return Err("SIP008 bytes_remaining requires bytes_used".to_owned());
    }

    let mut server_ids = BTreeSet::new();
    for server in source.servers {
        let id =
            Uuid::parse_str(&server.id).map_err(|_| "SIP008 server id is not a UUID".to_owned())?;
        if id.is_nil() || !server_ids.insert(id) {
            return Err("SIP008 server ids must be unique non-nil UUIDs".to_owned());
        }
        if server.server_port == 0 {
            return Err("SIP008 server port is invalid".to_owned());
        }
        if server.password.is_empty() {
            return Err("SIP008 server password is empty".to_owned());
        }
        if !server.plugin.is_empty() || !server.plugin_opts.is_empty() {
            return Err("SIP008 Shadowsocks plugins are unsupported".to_owned());
        }

        let method = normalize_shadowsocks_method_and_password(&server.method, &server.password)?;
        let reference = collector.push_secret(CredentialKind::ShadowsocksPassword, server.password);
        let tag = collector.unique_tag(server.remarks)?;
        collector.outbounds.push(json!({
            "type": "shadowsocks",
            "tag": tag,
            "server": server.server,
            "server_port": server.server_port,
            "method": method,
            "credential_ref": credential_ref_json(&reference),
        }));
    }
    collector.into_subscription()
}
