use std::{collections::BTreeMap, fmt, io::Write};

use cfw_singbox_config::{
    CredentialRef, CredentialSecret, LAN_INBOUND_TAG, MAX_ENGINE_CONFIG_BYTES, ProjectedConfig,
    ProjectionMode, SYSTEM_PROXY_INBOUND_TAG, TUNNEL_INBOUND_TAG,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

mod start_request;
pub use start_request::CheckedStartConfiguration;
mod probe;
pub(crate) use probe::ProbeOptions;
pub use probe::{CheckedProbeConfiguration, ResolvedProbe};

/// Resolved material for one already validated projection. The identity is the
/// original projection digest, never a hash of injected vault credentials.
pub struct ResolvedProjection {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    pub(crate) digest: String,
}

impl fmt::Debug for ResolvedProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedProjection")
            .field("digest", &self.digest)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl ResolvedProjection {
    /// The caller must resolve these references for `credential_audience()`
    /// under its lifecycle guard. This method checks exact material coverage;
    /// it does not grant vault authorization or own the global engine lineage.
    /// All projection modes can be checked without activating a runtime. This
    /// type is not a start capability; local starts require `PreparedConfig`.
    pub fn new<'a>(
        projection: &ProjectedConfig,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<Self, Error> {
        Self::resolve_template(
            projection.as_json(),
            projection.credential_slots(),
            projection.digest(),
            material,
        )
    }

    fn resolve_template<'a>(
        template: &str,
        slots: &[cfw_singbox_config::CredentialSlot],
        digest: &str,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<Self, Error> {
        let mut values = BTreeMap::new();
        let mut total = 0usize;
        for (reference, value) in material {
            total = total
                .checked_add(value.len())
                .ok_or(Error::Configuration("material size overflow"))?;
            if total > 448 * 1024 || values.len() >= 8192 {
                return Err(Error::Configuration("material capacity exceeded"));
            }
            CredentialSecret::new(value)
                .and_then(|secret| secret.validate_for_kind(reference.kind()))
                .map_err(|_| Error::Configuration("invalid credential material"))?;
            if values.insert(reference, value).is_some() {
                return Err(Error::Configuration("duplicate credential material"));
            }
        }
        let mut document = SecretDocument(
            serde_json::from_str(template)
                .map_err(|_| Error::Configuration("invalid projected template"))?,
        );
        let mut used = std::collections::BTreeSet::new();
        for slot in slots {
            let value = values
                .get(slot.reference())
                .ok_or(Error::Configuration("missing credential material"))?;
            let target = document
                .0
                .pointer_mut(slot.json_pointer())
                .ok_or(Error::Configuration("missing credential slot"))?;
            if target.as_str() != Some("") {
                return Err(Error::Configuration("credential slot is not empty"));
            }
            *target = Value::String((*value).to_owned());
            used.insert(slot.reference());
        }
        if used.len() != values.len() {
            return Err(Error::Configuration("unrequested credential material"));
        }
        let bytes = serialize_bounded(&document.0, MAX_ENGINE_CONFIG_BYTES)?;
        Ok(Self {
            bytes,
            digest: digest.to_owned(),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Admits a local, SystemProxy or packet-fed Tunnel data plane, or a tunnel
/// with the SystemProxy listener beside it. Starting this child alone claims
/// no OS proxy, adapter, route or DNS ownership. A tunnel is admitted only
/// through the checked shared request, never from a projection.
#[derive(Debug)]
pub struct PreparedConfig {
    pub(crate) resolved: ResolvedProjection,
    pub(crate) listeners: Vec<std::net::SocketAddr>,
    configuration_digest: String,
    mode: ProjectionMode,
    system_proxy_endpoint: Option<std::net::SocketAddr>,
    tunnel_mtu: Option<u16>,
}

impl PreparedConfig {
    pub fn local_proxy<'a>(
        projection: &ProjectedConfig,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<Self, Error> {
        Self::prepare(projection, material, ProjectionMode::LocalProxy)
    }

    /// Prepare the exact SystemProxy projection; the authority must separately
    /// activate and durably own OS settings through `WindowsSystemProxy`.
    pub fn system_proxy_data_plane<'a>(
        projection: &ProjectedConfig,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<Self, Error> {
        Self::prepare(projection, material, ProjectionMode::SystemProxy)
    }

    fn prepare<'a>(
        projection: &ProjectedConfig,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
        expected: ProjectionMode,
    ) -> Result<Self, Error> {
        if projection.mode() != expected {
            return Err(Error::Configuration("platform mode is not yet admitted"));
        }
        let resolved = ResolvedProjection::new(projection, material)?;
        Self::from_parts(
            resolved,
            projection.as_json(),
            projection.configuration_digest(),
            expected,
            std::net::SocketAddr::new(
                projection.clash_api().address().into(),
                projection.clash_api().port(),
            ),
            None,
        )
    }

    fn from_parts(
        resolved: ResolvedProjection,
        template: &str,
        template_digest: &str,
        expected: ProjectionMode,
        controller: std::net::SocketAddr,
        tunnel_mtu: Option<u16>,
    ) -> Result<Self, Error> {
        if expected.has_tunnel() != tunnel_mtu.is_some() {
            return Err(Error::Configuration("platform mode is not yet admitted"));
        }
        // The listener this user's proxy settings will name.
        let owns_proxy = matches!(
            expected,
            ProjectionMode::SystemProxy | ProjectionMode::TunnelSystemProxy
        );
        // Listener metadata comes from the immutable projection. Its generated
        // controller credential is also erased when this temporary DOM drops.
        let document = SecretDocument(
            serde_json::from_str(template)
                .map_err(|_| Error::Configuration("invalid projected template"))?,
        );
        let mut listeners = vec![controller];
        let inbounds = document
            .0
            .get("inbounds")
            .and_then(Value::as_array)
            .ok_or(Error::Configuration("missing projected listeners"))?;
        let mut system_proxy_endpoint = None;
        let mut packet_interface = false;
        for inbound in inbounds {
            let tag = inbound.get("tag").and_then(Value::as_str);
            if inbound.get("type").and_then(Value::as_str) == Some("tun") {
                // The checked admission validated this one packet-fed
                // interface. It has no listener and is never a proxy endpoint.
                if !expected.has_tunnel() || packet_interface || tag != Some(TUNNEL_INBOUND_TAG) {
                    return Err(Error::Configuration("unowned packet interface"));
                }
                packet_interface = true;
                continue;
            }
            if expected == ProjectionMode::Tunnel && tag != Some(LAN_INBOUND_TAG) {
                return Err(Error::Configuration("unknown projected tunnel role"));
            }
            let address: std::net::IpAddr = inbound
                .get("listen")
                .and_then(Value::as_str)
                .and_then(|value| value.parse().ok())
                .ok_or(Error::Configuration("invalid listener address"))?;
            let port = inbound
                .get("listen_port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value != 0)
                .ok_or(Error::Configuration("invalid listener port"))?;
            listeners.push(std::net::SocketAddr::new(address, port));
            if owns_proxy {
                // The shared projection separately validates LAN ingress and
                // its source allowlist. Retain its native listener observation,
                // but never adopt that endpoint as this user's OS proxy.
                match tag {
                    Some(LAN_INBOUND_TAG) => continue,
                    Some(SYSTEM_PROXY_INBOUND_TAG) => {}
                    _ => return Err(Error::Configuration("unknown projected proxy role")),
                }
                if inbound.get("type").and_then(Value::as_str) != Some("mixed")
                    || system_proxy_endpoint.is_some()
                {
                    return Err(Error::Configuration(
                        "SystemProxy requires one mixed listener",
                    ));
                }
                let local_address = match address {
                    std::net::IpAddr::V4(value) if value.is_unspecified() => {
                        std::net::Ipv4Addr::LOCALHOST.into()
                    }
                    std::net::IpAddr::V6(value) if value.is_unspecified() => {
                        std::net::Ipv6Addr::LOCALHOST.into()
                    }
                    value if value.is_loopback() => value,
                    _ => {
                        return Err(Error::Configuration(
                            "SystemProxy listener is not locally addressable",
                        ));
                    }
                };
                system_proxy_endpoint = Some(std::net::SocketAddr::new(local_address, port));
            }
        }
        if owns_proxy && system_proxy_endpoint.is_none() {
            return Err(Error::Configuration("SystemProxy listener is missing"));
        }
        if expected.has_tunnel() && !packet_interface {
            return Err(Error::Configuration(
                "Tunnel data plane requires exactly one packet interface",
            ));
        }
        Ok(Self {
            resolved,
            listeners,
            configuration_digest: template_digest.to_owned(),
            mode: expected,
            system_proxy_endpoint,
            tunnel_mtu,
        })
    }

    pub fn digest(&self) -> &str {
        self.resolved.digest()
    }

    /// Digest of the exact template before vault credential injection, distinct
    /// from `digest()`. The template still contains the private controller key.
    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
    pub fn mode(&self) -> ProjectionMode {
        self.mode
    }

    pub fn system_proxy_endpoint(&self) -> Option<std::net::SocketAddr> {
        self.system_proxy_endpoint
    }

    /// The MTU of the packet endpoint this Tunnel data plane must be fed by.
    pub fn tunnel_mtu(&self) -> Option<u16> {
        self.tunnel_mtu
    }
}

struct SecretDocument(Value);

impl Drop for SecretDocument {
    fn drop(&mut self) {
        fn erase(value: &mut Value) {
            match value {
                Value::String(string) => string.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(erase),
                Value::Object(values) => values.values_mut().for_each(erase),
                _ => {}
            }
        }
        erase(&mut self.0);
    }
}

/// Reserve once so reallocation cannot leave earlier secret-bearing buffers.
pub(crate) fn serialize_bounded(
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Writer {
        bytes: Zeroizing<Vec<u8>>,
        limit: usize,
    }
    impl Write for Writer {
        fn write(&mut self, value: &[u8]) -> std::io::Result<usize> {
            if value.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(std::io::Error::other("configuration capacity exceeded"));
            }
            self.bytes.extend_from_slice(value);
            Ok(value.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer {
        bytes: Zeroizing::new(Vec::with_capacity(limit)),
        limit,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| Error::Configuration("encoded configuration capacity exceeded"))?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests;
