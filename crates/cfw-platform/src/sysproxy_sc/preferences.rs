//! The live SCPreferences session behind the proxy store.
//!
//! Nothing here decides anything. Every check lives in the steps this session
//! is handed to, and the tests run those against an in-memory store.

use anyhow::{Context, Result, bail};
use objc2_core_foundation::{CFArray, CFDictionary, CFRetained, CFString};
use objc2_system_configuration::{
    SCNetworkService, SCNetworkSet, SCPreferences, kSCNetworkProtocolTypeProxies,
};

use crate::sysproxy_sc::PREFS_NAME;
use crate::sysproxy_sc::store::{ProxyConfiguration, ProxyPreferences, ProxyService};

/// A session on this Mac's network preferences.
pub(crate) struct PreferencesSession {
    preferences: CFRetained<SCPreferences>,
    locked: bool,
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
}

impl ProxyPreferences for PreferencesSession {
    type Service = CFRetained<SCNetworkService>;

    fn lock(&mut self) -> Result<()> {
        if !self.preferences.lock(true) {
            bail!("SCPreferencesLock failed")
        }
        self.locked = true;
        Ok(())
    }

    fn services(&self) -> Result<Vec<Self::Service>> {
        let set =
            SCNetworkSet::current(&self.preferences).context("SCNetworkSetCopyCurrent failed")?;
        let services = set.services().context("SCNetworkSetCopyServices failed")?;
        // SAFETY: SCNetworkSetCopyServices returns an array of SCNetworkService refs.
        let typed = unsafe { CFRetained::cast_unchecked::<CFArray<SCNetworkService>>(services) };
        Ok((0..typed.len())
            .filter_map(|index| typed.get(index))
            .collect())
    }

    fn commit_apply(&self) -> Result<()> {
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

impl ProxyService for CFRetained<SCNetworkService> {
    fn identifier(&self) -> Option<String> {
        self.service_id().map(|id| id.to_string())
    }

    fn display_name(&self) -> Option<String> {
        self.name().map(|name| name.to_string())
    }

    fn proxy_configuration(&self) -> ProxyConfiguration {
        match self.protocol(unsafe { kSCNetworkProtocolTypeProxies }) {
            None => ProxyConfiguration::NoProtocol,
            Some(protocol) => protocol.configuration().map_or(
                ProxyConfiguration::Unconfigured,
                ProxyConfiguration::Configured,
            ),
        }
    }

    fn stage_proxy_configuration(&self, configuration: &CFDictionary) -> bool {
        self.protocol(unsafe { kSCNetworkProtocolTypeProxies })
            .is_some_and(|protocol| unsafe { protocol.set_configuration(Some(configuration)) })
    }
}
