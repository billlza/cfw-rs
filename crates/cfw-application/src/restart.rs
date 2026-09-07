use std::fmt;

use cfw_engine_api::{EngineMode, EngineOwner, EngineSnapshot, EngineState};
use cfw_singbox_config::{EngineSettings, ValidatedSingBoxProfile};

/// The last source inputs accepted by the serialized coordinator actor.
///
/// This value is process-memory only. It contains a validated profile template
/// and credential references, never resolved credential bytes, controller
/// secrets or native tickets. Its snapshot binding prevents a stale spec from
/// being treated as a recoverable baseline after state drift.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineRestartSpec {
    mode: EngineMode,
    profile_id: String,
    profile: ValidatedSingBoxProfile,
    settings: EngineSettings,
    generation: u64,
    config_digest: Option<String>,
}

impl EngineRestartSpec {
    pub(crate) fn accepted(
        mode: EngineMode,
        profile_id: String,
        profile: ValidatedSingBoxProfile,
        settings: EngineSettings,
        snapshot: &EngineSnapshot,
    ) -> Self {
        Self {
            mode,
            profile_id,
            profile,
            settings,
            generation: snapshot.generation,
            config_digest: snapshot.config_digest.clone(),
        }
    }

    pub fn mode(&self) -> EngineMode {
        self.mode
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn profile(&self) -> &ValidatedSingBoxProfile {
        &self.profile
    }

    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn config_digest(&self) -> Option<&str> {
        self.config_digest.as_deref()
    }

    /// Requires a ready native owner with the exact accepted identity.
    /// Awaiting approval, Failed, stale generations and digest drift are not a
    /// restartable transaction baseline.
    pub fn matches_ready_snapshot(&self, snapshot: &EngineSnapshot) -> bool {
        if snapshot.desired_mode != self.mode
            || snapshot.generation != self.generation
            || snapshot.config_digest.as_deref() != self.config_digest()
        {
            return false;
        }
        match (&snapshot.state, self.mode) {
            (EngineState::Off, EngineMode::Off) => self.config_digest.is_none(),
            (EngineState::ProxyActive { runtime }, EngineMode::SystemProxy) => {
                runtime.ready
                    && runtime.owner == EngineOwner::ProxyAgent
                    && runtime.context.generation == self.generation
                    && Some(runtime.config_digest.as_str()) == self.config_digest()
            }
            (EngineState::TunnelActive { runtime }, EngineMode::Tunnel) => {
                runtime.ready
                    && runtime.owner == EngineOwner::PacketTunnelSystemExtension
                    && runtime.context.generation == self.generation
                    && Some(runtime.config_digest.as_str()) == self.config_digest()
            }
            _ => false,
        }
    }
}

impl fmt::Debug for EngineRestartSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineRestartSpec")
            .field("mode", &self.mode)
            .field("profile_id", &self.profile_id)
            .field("profile_digest", &self.profile.digest())
            .field("generation", &self.generation)
            .field("config_digest", &self.config_digest)
            .field("settings", &"[REDACTED ENGINE SETTINGS]")
            .finish()
    }
}
