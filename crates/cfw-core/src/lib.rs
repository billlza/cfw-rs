use serde::{Deserialize, Serialize};

mod control_session;
mod protocol;
mod settings;

pub use control_session::{
    CONTROL_SESSION_DIR, CONTROL_SESSION_FILE, ControlSession, ControlSessionError,
};
pub use protocol::{DeepLinkAction, DeepLinkIntent, DeepLinkParseError, parse_deep_link};
pub use settings::{
    APP_CONFIG_FILE_NAME, APP_HOME_DIR_NAME, CORES_DIR_NAME, HELPERS_DIR_NAME, LOGS_DIR_NAME,
    MacOsAppPaths, PROFILES_DIR_NAME, PersistedSettings, SETTINGS_FILE_NAME, SettingsSnapshot,
    SettingsStore, SettingsStoreError,
};

pub const PRODUCT_NAME: &str = "Clash for Mac";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppTarget {
    Cfw02039Parity,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeMode {
    Global,
    #[default]
    Rule,
    Direct,
    Script,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSet {
    pub tray: bool,
    pub system_proxy: bool,
    pub tun_mode: bool,
    pub profiles: bool,
    pub connections: bool,
    pub logs: bool,
    pub clash_protocol: bool,
}

impl FeatureSet {
    pub fn baseline_cfw_02039() -> Self {
        Self {
            tray: true,
            system_proxy: true,
            tun_mode: true,
            profiles: true,
            connections: true,
            logs: true,
            clash_protocol: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiPage {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub parity_scope: Vec<String>,
}

impl UiPage {
    pub fn cfw_primary_nav() -> Vec<Self> {
        vec![
            Self {
                id: "general".into(),
                title: "General".into(),
                summary: "Overview, runtime status, mode, system proxy and TUN toggles.".into(),
                parity_scope: vec![
                    "Dashboard overview".into(),
                    "Mode switcher".into(),
                    "System proxy status".into(),
                    "TUN status".into(),
                ],
            },
            Self {
                id: "proxies".into(),
                title: "Proxies".into(),
                summary: "Proxy groups, selections, delay indicators and quick switching.".into(),
                parity_scope: vec![
                    "Selector groups".into(),
                    "Latency indicators".into(),
                    "Current group selection".into(),
                ],
            },
            Self {
                id: "profiles".into(),
                title: "Profiles".into(),
                summary: "Subscription import, update, validation and profile lifecycle.".into(),
                parity_scope: vec![
                    "Subscription import".into(),
                    "Update schedule".into(),
                    "YAML validation".into(),
                ],
            },
            Self {
                id: "providers".into(),
                title: "Providers".into(),
                summary: "Proxy providers, rule providers, health checks and update actions."
                    .into(),
                parity_scope: vec![
                    "Proxy Providers".into(),
                    "Rule Providers".into(),
                    "Update All".into(),
                    "Health Check All".into(),
                ],
            },
            Self {
                id: "logs".into(),
                title: "Logs".into(),
                summary: "Core logs, helper logs and filtered runtime diagnostics.".into(),
                parity_scope: vec![
                    "Core log stream".into(),
                    "Level filters".into(),
                    "Structured diagnostics".into(),
                ],
            },
            Self {
                id: "connections".into(),
                title: "Connections".into(),
                summary: "Live connection list, close-all action and traffic visibility.".into(),
                parity_scope: vec![
                    "Live connections".into(),
                    "Close all".into(),
                    "Traffic counters".into(),
                ],
            },
            Self {
                id: "rules".into(),
                title: "Rules".into(),
                summary: "Rule matching visibility and router/provider diagnostics.".into(),
                parity_scope: vec![
                    "Rule Providers".into(),
                    "Router diagnostics".into(),
                    "Rule payload visibility".into(),
                ],
            },
            Self {
                id: "settings".into(),
                title: "Settings".into(),
                summary: "Shell settings, startup, deep link, helper and migration options.".into(),
                parity_scope: vec![
                    "Launch at login".into(),
                    "Protocol registration".into(),
                    "Migration controls".into(),
                ],
            },
            Self {
                id: "feedback".into(),
                title: "Feedback".into(),
                summary: "About, feedback and migration references from the original app.".into(),
                parity_scope: vec![
                    "Feedback route".into(),
                    "Version and source attribution".into(),
                    "Reverse artifact notes".into(),
                ],
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsSkeleton {
    pub launch_at_login: bool,
    pub random_controller_port: bool,
    pub retain_window_bounds: bool,
    pub show_tray_proxy_delay_indicator: bool,
    pub check_for_updates: bool,
    pub only_arm64_macos_supported: bool,
}

impl Default for SettingsSkeleton {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            random_controller_port: true,
            retain_window_bounds: true,
            show_tray_proxy_delay_indicator: true,
            check_for_updates: false,
            only_arm64_macos_supported: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBudget {
    pub multiplier_vs_cfw_02039: u8,
    pub cold_start_p95_ms: u16,
    pub page_switch_p95_ms: u16,
    pub proxy_toggle_p95_ms: u16,
    pub profile_apply_p95_ms: u16,
    pub max_idle_rss_mb: u16,
    pub log_ingest_events_per_sec: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityBudget {
    pub crash_free_session_rate_basis_points: u16,
    pub restore_system_proxy_on_exit: bool,
    pub rollback_failed_profile_apply: bool,
    pub idempotent_helper_install: bool,
    pub tun_failure_restores_previous_route: bool,
    pub single_instance_deep_link_safe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QualityTargets {
    pub performance: PerformanceBudget,
    pub stability: StabilityBudget,
    pub parity_gates: Vec<String>,
}

impl QualityTargets {
    pub fn macos_arm64_3x() -> Self {
        Self {
            performance: PerformanceBudget {
                multiplier_vs_cfw_02039: 3,
                cold_start_p95_ms: 700,
                page_switch_p95_ms: 16,
                proxy_toggle_p95_ms: 150,
                profile_apply_p95_ms: 450,
                max_idle_rss_mb: 90,
                log_ingest_events_per_sec: 10_000,
            },
            stability: StabilityBudget {
                crash_free_session_rate_basis_points: 9_995,
                restore_system_proxy_on_exit: true,
                rollback_failed_profile_apply: true,
                idempotent_helper_install: true,
                tun_failure_restores_previous_route: true,
                single_instance_deep_link_safe: true,
            },
            parity_gates: vec![
                "All primary CFW navigation pages exist and preserve user task flow".into(),
                "Tray exposes dashboard, mode, system proxy, TUN, groups and quit actions".into(),
                "clash:// URLs focus the existing window and dispatch import/update intent".into(),
                "System proxy, helper, launchd and TUN operations are typed Rust boundaries".into(),
                "Controller data path is async, bounded and recoverable under core restarts".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductBlueprint<P> {
    pub name: String,
    pub target: AppTarget,
    pub features: FeatureSet,
    pub platform: P,
    pub parity_source: String,
}

impl<P> ProductBlueprint<P> {
    pub fn arm64_macos_only(features: FeatureSet, platform: P) -> Self {
        Self {
            name: PRODUCT_NAME.into(),
            target: AppTarget::Cfw02039Parity,
            features,
            platform,
            parity_source: "Clash for Windows 0.20.39 macOS arm64 public release artifact".into(),
        }
    }
}
