//! Maintenance of the installed native services and the receipts that prove it.

use serde::{Deserialize, Serialize};

/// Versioned command sent over the narrow Rust/Swift host boundary.
///
/// This is the only product-level native wire command. Swift maps it onto the
/// already-versioned ProxyAgent and Packet Tunnel command envelopes; it does
/// not expose an independent product state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceMaintenanceAction {
    RetireOrphanedServices,
    Status,
    ProveOff,
    #[serde(rename = "prove_installed_40019_off")]
    ProveInstalled40019Off,
    UnregisterProxyAgent,
    #[serde(rename = "unregister_installed_40019_proxy_agent")]
    UnregisterInstalled40019ProxyAgent,
    UnregisterGlobalAuthority,
    #[serde(rename = "unregister_installed_40019_global_authority")]
    UnregisterInstalled40019GlobalAuthority,
    #[serde(rename = "recover_installed_40019_global_authority")]
    RecoverInstalled40019GlobalAuthority,
    RegisterGlobalAuthority,
    RegisterProxyAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceOffProofProfile {
    #[serde(rename = "installed_40019_engine_v5_authority_v1_0")]
    Installed40019EngineV5AuthorityV1_0,
    #[serde(rename = "installed_40019_recovery_current_authority_v1_1")]
    Installed40019RecoveryCurrentAuthorityV1_1,
    #[serde(rename = "current_engine_v6_authority_v1_1")]
    CurrentEngineV6AuthorityV1_1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceRegistrationStatus {
    Enabled,
    RequiresApproval,
    NotRegistered,
    NotFound,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceEngineStatus {
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeServiceMaintenanceResult {
    pub action: NativeServiceMaintenanceAction,
    pub engine_status: Option<NativeServiceEngineStatus>,
    pub global_authority: NativeServiceRegistrationStatus,
    pub off_proof_profile: Option<NativeServiceOffProofProfile>,
    pub proxy_agent: NativeServiceRegistrationStatus,
}

impl NativeServiceMaintenanceResult {
    pub fn validate(&self) -> bool {
        use NativeServiceMaintenanceAction as Action;
        use NativeServiceRegistrationStatus as Status;

        match self.action {
            Action::Status => self.engine_status.is_none() && self.off_proof_profile.is_none(),
            Action::RetireOrphanedServices => {
                self.engine_status.is_none()
                    && self.off_proof_profile.is_none()
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::NotRegistered
            }
            Action::ProveOff => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1)
                    && self.proxy_agent == Status::Enabled
                    && self.global_authority == Status::Enabled
            }
            Action::ProveInstalled40019Off => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0)
                    && self.proxy_agent == Status::Enabled
                    && self.global_authority == Status::Enabled
            }
            Action::UnregisterProxyAgent => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1)
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::Enabled
            }
            Action::UnregisterInstalled40019ProxyAgent => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0)
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::Enabled
            }
            Action::UnregisterGlobalAuthority => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1)
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::NotRegistered
            }
            Action::UnregisterInstalled40019GlobalAuthority => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0)
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::NotRegistered
            }
            Action::RecoverInstalled40019GlobalAuthority => self.engine_status
                == Some(NativeServiceEngineStatus::Off)
                && self.off_proof_profile
                    == Some(
                        NativeServiceOffProofProfile::Installed40019RecoveryCurrentAuthorityV1_1,
                    )
                && self.proxy_agent == Status::NotRegistered
                && self.global_authority == Status::NotRegistered,
            Action::RegisterGlobalAuthority => {
                self.engine_status.is_none()
                    && self.off_proof_profile.is_none()
                    && self.proxy_agent == Status::NotRegistered
                    && self.global_authority == Status::Enabled
            }
            Action::RegisterProxyAgent => {
                self.engine_status == Some(NativeServiceEngineStatus::Off)
                    && self.off_proof_profile
                        == Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1)
                    && self.proxy_agent == Status::Enabled
                    && self.global_authority == Status::Enabled
            }
        }
    }
}

#[cfg(test)]
mod tests;
