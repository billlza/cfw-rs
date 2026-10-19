//! Validate the existing shared application request at the Windows native
//! boundary. This does not grant a runtime lease or credential authorization.
use super::{Error, PreparedConfig, ResolvedProjection, SecretDocument, serialize_bounded};
use cfw_engine_api::{EngineCommandContext, EngineStartRequest};
use cfw_singbox_config::{
    CredentialAudience, CredentialRef, CredentialSlot, LanProxySettings, MAX_ENGINE_CONFIG_BYTES,
    ProjectionMode, canonicalize_configuration_value, configuration_identity_digest,
    lan_access_rule, sha256_hex, validate_credential_slots,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
};
use zeroize::Zeroize;

/// Keeps the exact source template, including its per-process controller key.
/// No Clone/serde constructor exposes unchecked configuration as validated.
pub struct CheckedStartConfiguration {
    request: EngineStartRequest,
}
impl Drop for CheckedStartConfiguration {
    fn drop(&mut self) {
        self.request.config_json.zeroize();
    }
}
impl CheckedStartConfiguration {
    pub fn new(request: EngineStartRequest) -> Result<Self, Error> {
        let value = Self { request };
        value.validate()?;
        Ok(value)
    }
    pub fn context(&self) -> &EngineCommandContext {
        &self.request.context
    }
    pub(crate) fn shared_request(&self) -> &EngineStartRequest {
        &self.request
    }
    pub fn mode(&self) -> ProjectionMode {
        self.request.mode
    }
    pub fn configuration_digest(&self) -> &str {
        &self.request.config_content_digest
    }
    pub fn digest(&self) -> &str {
        &self.request.config_digest
    }
    pub fn credential_audience(&self) -> &CredentialAudience {
        &self.request.credential_audience
    }
    pub fn credential_slots(&self) -> &[CredentialSlot] {
        &self.request.credential_slots
    }
    pub fn credential_references(&self) -> Vec<CredentialRef> {
        self.request
            .credential_slots
            .iter()
            .map(|slot| slot.reference().clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    fn document(&self) -> Result<SecretDocument, Error> {
        Ok(SecretDocument(canonicalize_configuration_value(
            serde_json::from_str(&self.request.config_json)
                .map_err(|_| Error::Configuration("invalid native configuration JSON"))?,
        )))
    }
    fn validate(&self) -> Result<(), Error> {
        let request = &self.request;
        let installation = uuid::Uuid::parse_str(&request.context.installation_id)
            .map_err(|_| Error::Configuration("invalid native installation identity"))?;
        if installation.is_nil()
            || installation.to_string() != request.context.installation_id
            || request.context.config_epoch == 0
            || request.context.generation == 0
            || request.config_json.is_empty()
            || request.config_json.len() > MAX_ENGINE_CONFIG_BYTES
            || request.credential_slots.len() > cfw_singbox_config::MAX_CREDENTIAL_SLOTS
        {
            return Err(Error::Configuration(
                "invalid native configuration context or size",
            ));
        }
        if sha256_hex(request.config_json.as_bytes()) != request.config_content_digest {
            return Err(Error::Configuration(
                "native configuration content digest mismatch",
            ));
        }
        let options_match = match request.mode {
            ProjectionMode::LocalProxy | ProjectionMode::SystemProxy => {
                request.tunnel_options.is_none()
            }
            ProjectionMode::Tunnel => request
                .tunnel_options
                .is_some_and(|options| options.system_proxy_port.is_none()),
            ProjectionMode::TunnelSystemProxy => request
                .tunnel_options
                .is_some_and(|options| options.system_proxy_port.is_some()),
        };
        if !options_match {
            return Err(Error::Configuration(
                "native mode and network options differ",
            ));
        }
        let identity = configuration_identity_digest(
            &request.config_content_digest,
            &request.credential_audience,
            &request.credential_slots,
            request.mode,
            &request.tunnel_options,
        )
        .map_err(|_| Error::Configuration("invalid native configuration identity"))?;
        if identity != request.config_digest {
            return Err(Error::Configuration(
                "native configuration identity digest mismatch",
            ));
        }
        let document = self.document()?;
        if !document.0.is_object()
            || serialize_bounded(&document.0, MAX_ENGINE_CONFIG_BYTES)?.as_slice()
                != request.config_json.as_bytes()
        {
            return Err(Error::Configuration(
                "native configuration is not the canonical projected template",
            ));
        }
        validate_credential_slots(&document.0, &request.credential_slots)
            .map_err(|_| Error::Configuration("invalid native credential slot binding"))?;
        if !request.mode.has_tunnel() {
            proxy_controller(&document.0)?;
        }
        Ok(())
    }
    /// Resolve only after the owner has authenticated this exact audience and
    /// lease. Candidate checks do not start a runtime, including Tunnel modes.
    pub fn resolve<'a>(
        &self,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<ResolvedProjection, Error> {
        ResolvedProjection::resolve_template(
            &self.request.config_json,
            &self.request.credential_slots,
            &self.request.config_digest,
            material,
        )
    }
    pub fn prepare_proxy<'a>(
        self,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<PreparedConfig, Error> {
        if self.mode().has_tunnel() {
            return Err(Error::Configuration("platform mode is not yet admitted"));
        }
        let controller = proxy_controller(&self.document()?.0)?;
        let resolved = self.resolve(material)?;
        PreparedConfig::from_parts(
            resolved,
            &self.request.config_json,
            &self.request.config_content_digest,
            self.request.mode,
            controller,
        )
    }
}

fn invalid() -> Error {
    Error::Configuration("native proxy template violates application-owned endpoints")
}
fn port(value: &Value) -> Result<u16, Error> {
    value
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0)
        .ok_or_else(invalid)
}
fn exact_keys(value: &Value, keys: &[&str]) -> Result<(), Error> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}

fn proxy_controller(root: &Value) -> Result<SocketAddr, Error> {
    let api = &root["experimental"]["clash_api"];
    exact_keys(api, &["external_controller", "secret"])?;
    let address_text = api["external_controller"].as_str().ok_or_else(invalid)?;
    let controller: SocketAddr = address_text.parse().map_err(|_| invalid())?;
    if controller.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        || controller.port() < 1024
        || controller.to_string() != address_text
    {
        return Err(invalid());
    }
    let secret = api["secret"].as_str().ok_or_else(invalid)?;
    if secret.len() != 64
        || !secret
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let inbounds = root["inbounds"].as_array().ok_or_else(invalid)?;
    if !(1..=2).contains(&inbounds.len()) {
        return Err(invalid());
    }
    let mut main = false;
    let mut lan = false;
    let mut ports = BTreeSet::from([controller.port()]);
    for inbound in inbounds {
        exact_keys(inbound, &["type", "tag", "listen", "listen_port"])?;
        if inbound["type"] != "mixed" {
            return Err(invalid());
        }
        let listen_text = inbound["listen"].as_str().ok_or_else(invalid)?;
        let address: Ipv4Addr = listen_text.parse().map_err(|_| invalid())?;
        let port = port(&inbound["listen_port"])?;
        if address.to_string() != listen_text || !ports.insert(port) {
            return Err(invalid());
        }
        match inbound["tag"].as_str() {
            Some("cfw-system-proxy") if !main && address == Ipv4Addr::LOCALHOST => main = true,
            Some("cfw-lan-proxy") if !lan => {
                let rule = &root["route"]["rules"][0];
                let sources = rule["rules"][1]["source_ip_cidr"]
                    .as_array()
                    .ok_or_else(invalid)?;
                let settings = LanProxySettings {
                    listen: address,
                    port,
                    allowed_source_cidrs: sources
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
                        .collect::<Result<_, _>>()?,
                };
                settings.validate().map_err(|_| invalid())?;
                let expected = lan_access_rule(&settings);
                if rule != &expected {
                    return Err(invalid());
                }
                lan = true;
            }
            _ => return Err(invalid()),
        }
    }
    if !main {
        return Err(invalid());
    }
    Ok(controller)
}

#[cfg(test)]
mod tests;
