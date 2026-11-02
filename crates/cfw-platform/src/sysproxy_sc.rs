//! SystemConfiguration ownership checks and one-way legacy proxy cleanup.
//!
//! Historical proxy snapshots are deliberately not an authority: the legacy
//! app stored them in a user-writable location without an authenticated digest.
//! A cutover may mutate only service IDs captured from live SCPreferences whose
//! HTTP, HTTPS and SOCKS values all exactly equal the product loopback endpoint.

use objc2_core_foundation::{CFDictionary, CFMutableDictionary, CFString, CFType};

mod legacy;
mod observation;
mod preferences;
mod values;

pub(crate) use legacy::{
    capture_legacy_applied_proxy, disable_legacy_proxy, recover_legacy_proxy, validate_plan,
    verify_legacy_applied_proxy, verify_legacy_proxy_disabled, verify_no_legacy_owned_proxy,
};
pub(crate) use observation::observe_network_services;

pub(crate) const PREFS_NAME: &str = "com.bill.clashformac.legacy-cutover";
pub(crate) const MAX_SERVICES: usize = 64;
pub(crate) const MAX_IDENTITY_BYTES: usize = 1024;

pub(crate) type ConfigDict = CFDictionary<CFString, CFType>;
pub(crate) type MutableConfigDict = CFMutableDictionary<CFString, CFType>;
