//! The listeners of each projection mode.

use super::*;

/// The inbounds of `mode`: a loopback mixed listener for the proxy modes, the
/// tunnel (with a mixed listener beside it for Tunnel + System Proxy), and
/// the LAN proxy listener when that is on.
pub(super) fn inbounds(
    mode: ProjectionMode,
    settings: &EngineSettings,
    tunnel_stack: TunnelStack,
) -> Result<Vec<Value>, ConfigError> {
    let inbound = match mode {
        ProjectionMode::LocalProxy | ProjectionMode::SystemProxy => {
            if settings.mixed_port == 0 {
                return Err(ConfigError::InvalidMixedPort);
            }
            json!({
                "type": "mixed",
                "tag": SYSTEM_PROXY_INBOUND_TAG,
                "listen": "127.0.0.1",
                "listen_port": settings.mixed_port
            })
        }
        ProjectionMode::Tunnel | ProjectionMode::TunnelSystemProxy => {
            let mut addresses = vec![format!(
                "{}/{}",
                TUNNEL_ADDRESS_PLAN.ipv4_address, TUNNEL_ADDRESS_PLAN.ipv4_prefix_length
            )];
            if settings.enable_ipv6 {
                addresses.push(format!(
                    "{}/{}",
                    TUNNEL_ADDRESS_PLAN.ipv6_address, TUNNEL_ADDRESS_PLAN.ipv6_prefix_length
                ));
            }
            json!({
                "type": "tun",
                "tag": TUNNEL_INBOUND_TAG,
                "address": addresses,
                // The native platform owner installs routes. This engine
                // processes only the packets supplied by that owner.
                "auto_route": false,
                "stack": tunnel_stack.as_str(),
                "mtu": settings.tunnel_mtu
            })
        }
    };
    let mut inbounds = vec![inbound];
    if mode == ProjectionMode::TunnelSystemProxy {
        if settings.mixed_port == 0 {
            return Err(ConfigError::InvalidMixedPort);
        }
        inbounds.push(json!({
            "type": "mixed",
            "tag": SYSTEM_PROXY_INBOUND_TAG,
            "listen": "127.0.0.1",
            "listen_port": settings.mixed_port,
        }));
    }
    if let Some(lan) = &settings.lan_proxy {
        inbounds.push(crate::lan::inbound(lan));
    }
    Ok(inbounds)
}
