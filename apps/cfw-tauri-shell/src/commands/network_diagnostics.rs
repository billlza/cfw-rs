//! Read-only diagnostics with platform-specific scope. Windows user LAN proxy
//! options are never projected onto individual adapters as invented services.
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(target_os = "macos")]
pub(crate) struct NetworkDiagnostics {
    default_route_interface: Option<String>,
    service_order: Vec<String>,
    services: Vec<cfw_platform::NetworkServiceObservation>,
    recommended_clash_proxy_services: Vec<String>,
    proxied_services: Vec<String>,
    unavailable: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg(windows)]
pub(crate) struct NetworkDiagnostics {
    platform: &'static str,
    adapters: Vec<cfw_platform::WindowsAdapterObservation>,
    user_proxy: cfw_windows_engine::LanProxyObservation,
}

#[cfg(target_os = "macos")]
const UNAVAILABLE_DIAGNOSTICS: [&str; 4] = [
    "default_route_interface",
    "hardware_port",
    "bsd_device",
    "recommended_clash_proxy_services",
];

#[cfg(target_os = "macos")]
pub(crate) fn collect() -> Result<NetworkDiagnostics, String> {
    let services = cfw_platform::MacOsPlatformService
        .observe_network_services()
        .map_err(|error| error.to_string())?;
    Ok(NetworkDiagnostics {
        default_route_interface: None,
        service_order: services
            .iter()
            .map(|service| service.display_name.clone())
            .collect(),
        recommended_clash_proxy_services: Vec::new(),
        proxied_services: services
            .iter()
            .filter(|service| service.any_proxy_enabled())
            .map(|service| service.display_name.clone())
            .collect(),
        services,
        unavailable: UNAVAILABLE_DIAGNOSTICS.to_vec(),
    })
}

#[cfg(windows)]
pub(crate) fn collect() -> Result<NetworkDiagnostics, String> {
    let adapters = cfw_platform::observe_windows_adapters().map_err(|error| error.to_string())?;
    let user_proxy =
        cfw_windows_engine::observe_lan_proxy_state().map_err(|error| error.to_string())?;
    Ok(NetworkDiagnostics {
        platform: "windows",
        adapters,
        user_proxy,
    })
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_declares_the_fields_the_retired_tools_used_to_supply() {
        let payload = serde_json::to_value(NetworkDiagnostics {
            default_route_interface: None,
            service_order: vec!["Wi-Fi".into()],
            services: Vec::new(),
            recommended_clash_proxy_services: Vec::new(),
            proxied_services: Vec::new(),
            unavailable: UNAVAILABLE_DIAGNOSTICS.to_vec(),
        })
        .expect("serialize diagnostics");
        assert!(payload["default_route_interface"].is_null());
        assert_eq!(
            payload["unavailable"],
            serde_json::json!([
                "default_route_interface",
                "hardware_port",
                "bsd_device",
                "recommended_clash_proxy_services",
            ])
        );
    }
}
