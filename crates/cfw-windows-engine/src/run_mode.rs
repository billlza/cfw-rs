//! What one Windows run owns, as the Authority records it.
//!
//! The shared `authority_v1::AuthorityMode` is the contract of the macOS
//! runtime. Windows records a mode of its own under the same names, so that
//! journals and peers written before this type read as they did, and so that
//! the two platforms can differ where their resources do.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    LocalProxy,
    SystemProxy,
    Tunnel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfw_engine_api::authority_v1::AuthorityMode;

    #[test]
    fn the_names_are_those_earlier_journals_and_peers_wrote() {
        for (run, shared, name) in [
            (
                RunMode::LocalProxy,
                AuthorityMode::LocalProxy,
                "local_proxy",
            ),
            (
                RunMode::SystemProxy,
                AuthorityMode::SystemProxy,
                "system_proxy",
            ),
            (RunMode::Tunnel, AuthorityMode::Tunnel, "tunnel"),
        ] {
            let written = serde_json::to_value(run).unwrap();
            assert_eq!(written, serde_json::json!(name));
            assert_eq!(written, serde_json::to_value(shared).unwrap());
            assert_eq!(serde_json::from_value::<RunMode>(written).unwrap(), run);
        }
        assert!(serde_json::from_value::<RunMode>(serde_json::json!("off")).is_err());
    }
}
