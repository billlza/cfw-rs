use std::{collections::BTreeMap, fmt, io::Write};

use cfw_singbox_config::{
    CredentialRef, CredentialSecret, MAX_ENGINE_CONFIG_BYTES, ProjectedConfig, ProjectionMode,
};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

/// Resolved material for one already validated projection. The identity is the
/// original secret-free projection digest, never a hash of injected secrets.
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
            serde_json::from_str(projection.as_json())
                .map_err(|_| Error::Configuration("invalid projected template"))?,
        );
        let mut used = std::collections::BTreeSet::new();
        for slot in projection.credential_slots() {
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
            digest: projection.digest().to_owned(),
        })
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Admits only the local proxy data plane. A checked tunnel projection cannot
/// be passed to `EngineProcess::start` through this type.
#[derive(Debug)]
pub struct PreparedConfig {
    pub(crate) resolved: ResolvedProjection,
    pub(crate) listeners: Vec<std::net::SocketAddr>,
}

impl PreparedConfig {
    pub fn local_proxy<'a>(
        projection: &ProjectedConfig,
        material: impl IntoIterator<Item = (&'a CredentialRef, &'a str)>,
    ) -> Result<Self, Error> {
        if projection.mode() != ProjectionMode::LocalProxy {
            return Err(Error::Configuration("platform mode is not yet admitted"));
        }
        let resolved = ResolvedProjection::new(projection, material)?;
        // Listener metadata comes from the immutable projection. Its generated
        // controller credential is also erased when this temporary DOM drops.
        let document = SecretDocument(
            serde_json::from_str(projection.as_json())
                .map_err(|_| Error::Configuration("invalid projected template"))?,
        );
        let mut listeners = vec![std::net::SocketAddr::new(
            projection.clash_api().address().into(),
            projection.clash_api().port(),
        )];
        let inbounds = document
            .0
            .get("inbounds")
            .and_then(Value::as_array)
            .ok_or(Error::Configuration("missing projected listeners"))?;
        for inbound in inbounds {
            let address = inbound
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
        }
        Ok(Self {
            resolved,
            listeners,
        })
    }

    pub fn digest(&self) -> &str {
        self.resolved.digest()
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
mod tests {
    use super::*;
    use cfw_singbox_config::{CredentialKind, EngineSettings, ValidatedSingBoxProfile};

    const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const REFERENCE: &str = "11111111-1111-4111-8111-111111111111";

    fn projection() -> ProjectedConfig {
        ValidatedSingBoxProfile::parse(&format!(
            r#"{{"outbounds":[{{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{{"id":"{REFERENCE}","kind":"trojan_password"}},"tls":{{"enabled":true,"server_name":"proxy.example.com"}}}}]}}"#
        ))
        .unwrap()
        .project(PROFILE, ProjectionMode::LocalProxy, &EngineSettings::default())
        .unwrap()
    }

    #[test]
    fn material_is_injected_without_changing_public_identity_or_debug_output() {
        let projected = projection();
        let reference = CredentialRef::new(REFERENCE, CredentialKind::TrojanPassword).unwrap();
        let config =
            PreparedConfig::local_proxy(&projected, [(&reference, "test-secret-123")]).unwrap();
        let parsed: Value = serde_json::from_slice(&config.resolved.bytes).unwrap();
        assert_eq!(
            parsed
                .pointer(projected.credential_slots()[0].json_pointer())
                .unwrap(),
            "test-secret-123"
        );
        assert_eq!(config.digest(), projected.digest());
        assert_eq!(config.listeners.len(), 2);
        assert!(!format!("{config:?}").contains("test-secret-123"));
        assert!(!projected.as_json().contains("test-secret-123"));
    }

    #[test]
    fn missing_duplicate_wrong_kind_and_extra_material_fail() {
        let projected = projection();
        let reference = CredentialRef::new(REFERENCE, CredentialKind::TrojanPassword).unwrap();
        let wrong = CredentialRef::new(REFERENCE, CredentialKind::Socks5Password).unwrap();
        assert!(PreparedConfig::local_proxy(&projected, []).is_err());
        assert!(
            PreparedConfig::local_proxy(&projected, [(&reference, "a"), (&reference, "a")])
                .is_err()
        );
        assert!(PreparedConfig::local_proxy(&projected, [(&wrong, "a")]).is_err());
        assert!(
            PreparedConfig::local_proxy(&projected, [(&reference, "a"), (&wrong, "a")]).is_err()
        );
        assert!(PreparedConfig::local_proxy(&projected, [(&reference, "")]).is_err());
    }

    #[test]
    fn other_modes_cannot_activate_platform_effects_through_this_component() {
        let profile =
            ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
                .unwrap();
        for mode in [
            ProjectionMode::SystemProxy,
            ProjectionMode::Tunnel,
            ProjectionMode::TunnelSystemProxy,
        ] {
            let projected = profile
                .project(PROFILE, mode, &EngineSettings::default())
                .unwrap();
            let checked = ResolvedProjection::new(&projected, []).unwrap();
            assert_eq!(checked.digest(), projected.digest());
            assert!(PreparedConfig::local_proxy(&projected, []).is_err());
        }
    }

    #[test]
    fn encoding_budget_counts_escaped_bytes() {
        assert!(serialize_bounded(&"\\\\\\", 6).is_err());
        assert_eq!(&*serialize_bounded(&"ok", 4).unwrap(), b"\"ok\"");
    }
}
