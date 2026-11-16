//! What one Windows run owns, as the Authority records it.
//!
//! The shared `authority_v1::AuthorityMode` is the contract of the macOS
//! runtime. Windows records a mode of its own under the same names, so that
//! journals and peers written before this type read as they did, and so that
//! the two platforms can differ where their resources do.
use cfw_singbox_config::ProjectionMode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    LocalProxy,
    SystemProxy,
    Tunnel,
    /// A tunnel together with this user's proxy settings. The shared mode has
    /// no such value: on macOS the proxy is part of the tunnel's own network
    /// settings and goes with it. Here the two are separate state, each with
    /// its own proof, and Off needs both.
    TunnelSystemProxy,
}
impl RunMode {
    /// The run changes this user's proxy settings. Only a Desktop of the same
    /// account can restore them and prove it.
    pub const fn owns_system_proxy(self) -> bool {
        matches!(self, Self::SystemProxy | Self::TunnelSystemProxy)
    }
    /// SYSTEM keeps an adapter and a packet pump for the run, and retires
    /// them by itself.
    pub const fn owns_tunnel(self) -> bool {
        matches!(self, Self::Tunnel | Self::TunnelSystemProxy)
    }
}
impl From<ProjectionMode> for RunMode {
    fn from(mode: ProjectionMode) -> Self {
        match mode {
            ProjectionMode::LocalProxy => Self::LocalProxy,
            ProjectionMode::SystemProxy => Self::SystemProxy,
            ProjectionMode::Tunnel => Self::Tunnel,
            ProjectionMode::TunnelSystemProxy => Self::TunnelSystemProxy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::authority_v1::AuthorityMode;

    const ALL: [(RunMode, ProjectionMode, &str); 4] = [
        (
            RunMode::LocalProxy,
            ProjectionMode::LocalProxy,
            "local_proxy",
        ),
        (
            RunMode::SystemProxy,
            ProjectionMode::SystemProxy,
            "system_proxy",
        ),
        (RunMode::Tunnel, ProjectionMode::Tunnel, "tunnel"),
        (
            RunMode::TunnelSystemProxy,
            ProjectionMode::TunnelSystemProxy,
            "tunnel_system_proxy",
        ),
    ];

    #[test]
    fn the_names_are_those_earlier_journals_and_peers_wrote() {
        for (run, shared) in [
            (RunMode::LocalProxy, AuthorityMode::LocalProxy),
            (RunMode::SystemProxy, AuthorityMode::SystemProxy),
            (RunMode::Tunnel, AuthorityMode::Tunnel),
        ] {
            let written = serde_json::to_value(run).unwrap();
            assert_eq!(written, serde_json::to_value(shared).unwrap());
            assert_eq!(serde_json::from_value::<RunMode>(written).unwrap(), run);
        }
        // The combined run is Windows' own: the shared contract refuses it.
        let combined = serde_json::to_value(RunMode::TunnelSystemProxy).unwrap();
        assert!(serde_json::from_value::<AuthorityMode>(combined).is_err());
        assert!(serde_json::from_value::<RunMode>(serde_json::json!("off")).is_err());
    }

    #[test]
    fn every_projection_has_its_run_mode_under_the_same_name() {
        for (run, projection, name) in ALL {
            assert_eq!(RunMode::from(projection), run);
            assert_eq!(serde_json::to_value(run).unwrap(), serde_json::json!(name));
            assert_eq!(
                serde_json::to_value(projection).unwrap(),
                serde_json::json!(name)
            );
            assert_eq!(run.owns_tunnel(), projection.has_tunnel());
        }
    }

    #[test]
    fn a_combined_run_owns_what_both_single_modes_own() {
        let owned = |mode: RunMode| (mode.owns_system_proxy(), mode.owns_tunnel());
        assert_eq!(owned(RunMode::LocalProxy), (false, false));
        assert_eq!(owned(RunMode::SystemProxy), (true, false));
        assert_eq!(owned(RunMode::Tunnel), (false, true));
        assert_eq!(owned(RunMode::TunnelSystemProxy), (true, true));
    }
}
