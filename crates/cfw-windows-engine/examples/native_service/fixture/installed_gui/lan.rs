//! LAN sharing as the installed GUI configured it, observed from the GUI's own
//! user session. The session lets the engine listen on every interface and
//! trusts one source, this machine's private address. A request that leaves
//! from that address is forwarded; one from the loopback address is refused
//! and never reaches its origin. Once sharing is off, nothing listens there.
//!
//! Whether another device reaches the port is decided by the Windows firewall.
//! The product writes no firewall rule, and no probe on this machine sees it.
use super::*;
use std::net::{Ipv4Addr, SocketAddr};

pub(super) fn probe(operation: &str, interface: &str, port: &str) -> Result<()> {
    use super::super::user_agent::{
        lan::{private_interface, require_rejected},
        traffic,
    };
    let shared = match operation {
        "lan-shared" => true,
        "lan-closed" => false,
        _ => return Err("unknown GUI LAN probe".into()),
    };
    let (source, receipts) = validation_context()?;
    let interface: Ipv4Addr = interface.parse().map_err(|_| "invalid GUI LAN interface")?;
    let port: u16 = port.parse().map_err(|_| "invalid GUI LAN port")?;
    if port < 1024 {
        return Err("GUI LAN port is below the range the product accepts".into());
    }
    // The session entered this address as its only trusted source. A request
    // of this process to the address also leaves from it.
    if interface != private_interface()? {
        return Err("the session's trusted source is not this machine's private address".into());
    }
    let observed = network::ObservedGui::open(&source, &receipts)?;
    let before = network::proxy_snapshot()?;
    let digest = network::proxy_digest(&before)?;
    if digest != observed.original_proxy_digest()? {
        return Err("LAN sharing changed the original user proxy options".into());
    }
    let trusted = SocketAddr::from((interface, port));
    let untrusted = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listeners =
        cfw_windows_engine::observe_tcp_listeners_at_port(port).map_err(|e| e.to_string())?;
    if shared {
        let every_interface = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        if !listeners
            .iter()
            .any(|(_, address)| *address == every_interface)
        {
            return Err(format!(
                "nothing listens on every interface at port {port}: {listeners:?}"
            ));
        }
        traffic(trusted)?;
        require_rejected(untrusted)?;
    } else {
        network::verify_closed_listener(&source, &receipts, operation, trusted)?;
    }
    observed.recheck("LAN probe GUI image changed during observation")?;
    if network::proxy_snapshot()? != before {
        return Err(format!(
            "user proxy options changed during the {operation} probe"
        ));
    }
    write(
        &receipts,
        &format!("{operation}-probe.json"),
        &serde_json::json!({
            "document": "cfw-installed-gui-lan-probe-v1", "source": source,
            "operation": operation,
            "gui_process_id": observed.pid,
            "gui_process_creation_time": observed.process.identity().process_creation_time(),
            "gui_same_user_session": true,
            "trusted_address": trusted.to_string(), "untrusted_address": untrusted.to_string(),
            "listeners_before": listeners,
            "trusted_source_forwarded": shared, "untrusted_source_refused": shared,
            "listener_refused": !shared, "other_devices_exercised": false,
            "user_proxy_sha256": digest, "user_proxy_unchanged": true,
            "release_accepted": false
        }),
    )
}
