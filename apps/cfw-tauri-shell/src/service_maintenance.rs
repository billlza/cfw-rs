use cfw_apple_network::NativeFrameworkBridge;
use cfw_engine_api::{
    NativeServiceEngineStatus, NativeServiceMaintenanceAction, NativeServiceRegistrationStatus,
};
use serde::Serialize;

use crate::launch::ServiceMaintenanceAction;

const DOCUMENT: &str = "cfw-current-service-maintenance-v1";

#[derive(Serialize)]
struct MaintenanceReceipt {
    action: NativeServiceMaintenanceAction,
    document: &'static str,
    engine_status: Option<NativeServiceEngineStatus>,
    global_authority: NativeServiceRegistrationStatus,
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
        ServiceMaintenanceAction::Status => NativeServiceMaintenanceAction::Status,
        ServiceMaintenanceAction::UnregisterProxyAgent => {
            NativeServiceMaintenanceAction::UnregisterProxyAgent
        }
        ServiceMaintenanceAction::UnregisterGlobalAuthority => {
            NativeServiceMaintenanceAction::UnregisterGlobalAuthority
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
                ServiceMaintenanceAction::Status,
                NativeServiceMaintenanceAction::Status,
            ),
            (
                ServiceMaintenanceAction::UnregisterProxyAgent,
                NativeServiceMaintenanceAction::UnregisterProxyAgent,
            ),
            (
                ServiceMaintenanceAction::UnregisterGlobalAuthority,
                NativeServiceMaintenanceAction::UnregisterGlobalAuthority,
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
