use cfw_apple_network::NativeFrameworkBridge;
use cfw_engine_api::{
    NativeServiceEngineStatus, NativeServiceMaintenanceAction, NativeServiceOffProofProfile,
    NativeServiceRegistrationStatus,
};
use serde::Serialize;

use crate::launch::ServiceMaintenanceAction;

const DOCUMENT: &str = "cfw-current-service-maintenance-v2";

#[derive(Serialize)]
struct MaintenanceReceipt {
    action: NativeServiceMaintenanceAction,
    document: &'static str,
    engine_status: Option<NativeServiceEngineStatus>,
    global_authority: NativeServiceRegistrationStatus,
    off_proof_profile: Option<NativeServiceOffProofProfile>,
    proxy_agent: NativeServiceRegistrationStatus,
}

pub(crate) fn run(action: ServiceMaintenanceAction) -> Result<(), String> {
    let bridge = NativeFrameworkBridge::load();
    if !bridge.is_available() {
        return Err(bridge
            .unavailable_reason()
            .unwrap_or("native bridge unavailable")
            .to_owned());
    }
    let action = native_action(action);
    let result = tauri::async_runtime::block_on(bridge.maintain_current_services(action))
        .map_err(|error| format!("native service maintenance failed: {}", error.message))?;
    let receipt = MaintenanceReceipt {
        action: result.action,
        document: DOCUMENT,
        engine_status: result.engine_status,
        global_authority: result.global_authority,
        off_proof_profile: result.off_proof_profile,
        proxy_agent: result.proxy_agent,
    };
    println!(
        "{}",
        serde_json::to_string(&receipt)
            .map_err(|_| "service maintenance receipt encoding failed".to_owned())?
    );
    Ok(())
}

const fn native_action(action: ServiceMaintenanceAction) -> NativeServiceMaintenanceAction {
    match action {
        ServiceMaintenanceAction::ProveOff => NativeServiceMaintenanceAction::ProveOff,
        ServiceMaintenanceAction::ProveInstalled40019Off => {
            NativeServiceMaintenanceAction::ProveInstalled40019Off
        }
        ServiceMaintenanceAction::Status => NativeServiceMaintenanceAction::Status,
        ServiceMaintenanceAction::UnregisterProxyAgent => {
            NativeServiceMaintenanceAction::UnregisterProxyAgent
        }
        ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent => {
            NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent
        }
        ServiceMaintenanceAction::UnregisterGlobalAuthority => {
            NativeServiceMaintenanceAction::UnregisterGlobalAuthority
        }
        ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority => {
            NativeServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority
        }
        ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority => {
            NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority
        }
        ServiceMaintenanceAction::RegisterGlobalAuthority => {
            NativeServiceMaintenanceAction::RegisterGlobalAuthority
        }
        ServiceMaintenanceAction::RegisterProxyAgent => {
            NativeServiceMaintenanceAction::RegisterProxyAgent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cli_action_maps_to_one_closed_native_action() {
        let cases = [
            (
                ServiceMaintenanceAction::ProveOff,
                NativeServiceMaintenanceAction::ProveOff,
            ),
            (
                ServiceMaintenanceAction::ProveInstalled40019Off,
                NativeServiceMaintenanceAction::ProveInstalled40019Off,
            ),
            (
                ServiceMaintenanceAction::Status,
                NativeServiceMaintenanceAction::Status,
            ),
            (
                ServiceMaintenanceAction::UnregisterProxyAgent,
                NativeServiceMaintenanceAction::UnregisterProxyAgent,
            ),
            (
                ServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent,
                NativeServiceMaintenanceAction::UnregisterInstalled40019ProxyAgent,
            ),
            (
                ServiceMaintenanceAction::UnregisterGlobalAuthority,
                NativeServiceMaintenanceAction::UnregisterGlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority,
                NativeServiceMaintenanceAction::UnregisterInstalled40019GlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority,
                NativeServiceMaintenanceAction::RecoverInstalled40019GlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RegisterGlobalAuthority,
                NativeServiceMaintenanceAction::RegisterGlobalAuthority,
            ),
            (
                ServiceMaintenanceAction::RegisterProxyAgent,
                NativeServiceMaintenanceAction::RegisterProxyAgent,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(native_action(input), expected);
        }
    }
}
