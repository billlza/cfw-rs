//! Live SCPreferences sessions and the network services they hold.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{CFArray, CFRetained, CFString};
use objc2_system_configuration::{SCNetworkService, SCNetworkSet, SCPreferences};

use crate::legacy_proxy::LegacyProxyServiceIdentity;
use crate::sysproxy_sc::{MAX_IDENTITY_BYTES, MAX_SERVICES, PREFS_NAME};

pub(crate) struct PreferencesSession {
    pub(super) preferences: CFRetained<SCPreferences>,
    pub(super) locked: bool,
}

impl PreferencesSession {
    pub(crate) fn open() -> Result<Self> {
        let name = CFString::from_str(PREFS_NAME);
        let preferences =
            SCPreferences::new(None, &name, None).context("SCPreferencesCreate failed")?;
        Ok(Self {
            preferences,
            locked: false,
        })
    }

    pub(crate) fn lock(&mut self) -> Result<()> {
        if !self.preferences.lock(true) {
            bail!("SCPreferencesLock failed")
        }
        self.locked = true;
        Ok(())
    }

    pub(crate) fn commit_apply(&self) -> Result<()> {
        if !self.preferences.commit_changes() {
            bail!("SCPreferencesCommitChanges failed")
        }
        if !self.preferences.apply_changes() {
            bail!("SCPreferencesApplyChanges failed")
        }
        Ok(())
    }
}

impl Drop for PreferencesSession {
    fn drop(&mut self) {
        if self.locked {
            let _unlocked = self.preferences.unlock();
        }
    }
}

pub(crate) fn current_services(prefs: &SCPreferences) -> Result<Vec<CFRetained<SCNetworkService>>> {
    let set = SCNetworkSet::current(prefs).context("SCNetworkSetCopyCurrent failed")?;
    let services = set.services().context("SCNetworkSetCopyServices failed")?;
    // SAFETY: SCNetworkSetCopyServices returns an array of SCNetworkService refs.
    let typed = unsafe { CFRetained::cast_unchecked::<CFArray<SCNetworkService>>(services) };
    if typed.len() > MAX_SERVICES {
        bail!("current network service count exceeds the cutover safety bound")
    }
    let mut result = Vec::with_capacity(typed.len());
    for index in 0..typed.len() {
        if let Some(service) = typed.get(index) {
            result.push(service);
        }
    }
    Ok(result)
}

pub(crate) fn service_id(service: &SCNetworkService) -> Result<String> {
    let value = service
        .service_id()
        .context("SC network service has no stable identifier")?
        .to_string();
    validate_identity_text("service identifier", &value)?;
    Ok(value)
}

pub(crate) fn service_name(service: &SCNetworkService, id: &str) -> Result<String> {
    let value = service
        .name()
        .map(|name| name.to_string())
        .unwrap_or_else(|| id.to_owned());
    validate_identity_text("service display name", &value)?;
    Ok(value)
}

pub(crate) fn validate_identity_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("SC network {label} is invalid")
    }
    Ok(())
}

pub(crate) fn find_service<'a>(
    services: &'a [CFRetained<SCNetworkService>],
    identity: &LegacyProxyServiceIdentity,
) -> Result<&'a SCNetworkService> {
    let service = services
        .iter()
        .find(|service| {
            service
                .service_id()
                .is_some_and(|id| id.to_string() == identity.service_id)
        })
        .map(AsRef::as_ref)
        .with_context(|| {
            format!(
                "SC network service identity disappeared: {}",
                identity.service_id
            )
        })?;
    if service_name(service, &identity.service_id)? != identity.display_name {
        bail!(
            "SC network service {} changed display identity during cutover",
            identity.service_id
        )
    }
    Ok(service)
}
