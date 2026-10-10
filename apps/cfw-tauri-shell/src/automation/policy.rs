//! Explicit user automation policy. No policy is enabled by default, and an
//! unobservable SSID cannot satisfy a named-network rule.
use cfw_engine_api::EngineMode;
use cfw_platform::{NetworkContext, NetworkKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tauri_plugin_global_shortcut::{Modifiers, Shortcut};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShortcutAction {
    ShowDashboard,
    ToggleCore,
    ToggleSystemProxy,
    ToggleTunnel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShortcutBinding {
    pub action: ShortcutAction,
    pub shortcut: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NetworkMatch {
    Wifi,
    Wired,
    Ssid { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkRule {
    pub network: NetworkMatch,
    pub mode: EngineMode,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomationPreferences {
    pub shortcuts: Vec<ShortcutBinding>,
    pub network_enabled: bool,
    pub network_rules: Vec<NetworkRule>,
}

impl AutomationPreferences {
    pub fn validate(&self) -> Result<Vec<(Shortcut, ShortcutAction)>, String> {
        if self.shortcuts.len() > 4 || self.network_rules.len() > 16 {
            return Err("automation preferences exceed their size limits".into());
        }
        if self.network_enabled && self.network_rules.is_empty() {
            return Err("add a network rule before enabling automation".into());
        }
        let mut ids = BTreeSet::new();
        let mut actions = BTreeSet::new();
        let mut shortcuts = Vec::new();
        for binding in &self.shortcuts {
            if binding.shortcut.len() > 96 {
                return Err("shortcut is too long".into());
            }
            let shortcut: Shortcut = binding
                .shortcut
                .parse()
                .map_err(|error| format!("invalid shortcut: {error}"))?;
            if !shortcut
                .mods
                .intersects(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER)
            {
                return Err("global shortcuts require Control, Option or Command".into());
            }
            if !ids.insert(shortcut.id()) || !actions.insert(binding.action) {
                return Err("shortcut keys and actions must be unique".into());
            }
            shortcuts.push((shortcut, binding.action));
        }
        let mut matches = BTreeSet::new();
        for rule in &self.network_rules {
            let key = match &rule.network {
                NetworkMatch::Wifi => "wifi".to_string(),
                NetworkMatch::Wired => "wired".to_string(),
                NetworkMatch::Ssid { name } => {
                    if name.is_empty() || name.len() > 32 || name.chars().any(char::is_control) {
                        return Err(
                            "Wi-Fi names must contain 1–32 UTF-8 bytes without control characters"
                                .into(),
                        );
                    }
                    format!("ssid:{name}")
                }
            };
            if !matches.insert(key) {
                return Err("network rules must not repeat the same match".into());
            }
        }
        Ok(shortcuts)
    }

    pub fn mode_for(&self, network: &NetworkContext) -> Option<EngineMode> {
        if !self.network_enabled {
            return None;
        }
        self.network_rules
            .iter()
            .find(|rule| match &rule.network {
                NetworkMatch::Wifi => network.kind == NetworkKind::Wifi,
                NetworkMatch::Wired => network.kind == NetworkKind::Wired,
                NetworkMatch::Ssid { name } => {
                    network.kind == NetworkKind::Wifi && network.ssid.as_ref() == Some(name)
                }
            })
            .map(|rule| rule.mode)
    }
}

/// Requires two equal observations. It consumes an edge once, even if the
/// requested transition fails; manual Stop cannot be undone by a later poll.
#[derive(Default)]
pub(crate) struct NetworkEdge {
    candidate: Option<Option<NetworkContext>>,
    consumed: Option<Option<NetworkContext>>,
}
impl NetworkEdge {
    pub fn observe(&mut self, network: Option<NetworkContext>) -> Option<NetworkContext> {
        if self.candidate.as_ref() != Some(&network) {
            self.candidate = Some(network);
            return None;
        }
        if self.consumed.as_ref() == Some(&network) {
            return None;
        }
        self.consumed = Some(network.clone());
        network
    }
    pub fn uncertain(&mut self) {
        self.candidate = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wifi(ssid: Option<&str>) -> NetworkContext {
        NetworkContext {
            interface: "en0".into(),
            kind: NetworkKind::Wifi,
            ssid: ssid.map(str::to_string),
            addresses: vec!["192.168.1.2".into()],
        }
    }
    #[test]
    fn named_networks_require_an_observed_name_and_preserve_rule_order() {
        let prefs = AutomationPreferences {
            network_enabled: true,
            network_rules: vec![
                NetworkRule {
                    network: NetworkMatch::Ssid {
                        name: "Home".into(),
                    },
                    mode: EngineMode::LocalProxy,
                },
                NetworkRule {
                    network: NetworkMatch::Wifi,
                    mode: EngineMode::Tunnel,
                },
            ],
            ..Default::default()
        };
        prefs.validate().unwrap();
        assert_eq!(
            prefs.mode_for(&wifi(Some("Home"))),
            Some(EngineMode::LocalProxy)
        );
        assert_eq!(prefs.mode_for(&wifi(None)), Some(EngineMode::Tunnel));
        let named = AutomationPreferences {
            network_rules: prefs.network_rules[..1].to_vec(),
            ..prefs
        };
        assert_eq!(named.mode_for(&wifi(None)), None);
    }
    #[test]
    fn network_edges_debounce_and_never_retry_after_manual_stop_or_unknown_reads() {
        let mut edge = NetworkEdge::default();
        let n = Some(wifi(Some("Home")));
        assert!(edge.observe(n.clone()).is_none());
        assert!(edge.observe(n.clone()).is_some());
        assert!(edge.observe(n.clone()).is_none());
        edge.uncertain();
        assert!(edge.observe(n.clone()).is_none());
        assert!(edge.observe(n.clone()).is_none());
        assert!(edge.observe(None).is_none());
        assert!(edge.observe(None).is_none());
        assert!(edge.observe(n.clone()).is_none());
        assert!(edge.observe(n).is_some());
    }
    #[test]
    fn shortcut_alias_collisions_and_plain_typing_are_rejected() {
        for keys in [["Control+A", "Ctrl+A"], ["A", "Alt+B"]] {
            let prefs = AutomationPreferences {
                shortcuts: vec![
                    ShortcutBinding {
                        action: ShortcutAction::ToggleCore,
                        shortcut: keys[0].into(),
                    },
                    ShortcutBinding {
                        action: ShortcutAction::ShowDashboard,
                        shortcut: keys[1].into(),
                    },
                ],
                ..Default::default()
            };
            assert!(prefs.validate().is_err());
        }
    }
}
