//! Real traffic through the listener selected by the installed GUI. Proxy
//! options are compared without putting raw proxy/PAC strings in artifacts.
use super::*;
use cfw_windows_engine::{ProxySettings, WindowsSystemProxy};
use std::{collections::BTreeSet, io::Read};

fn connect_observation(address: std::net::SocketAddr, seconds: u64) -> serde_json::Value {
    let started = std::time::Instant::now();
    let result = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(seconds));
    match result {
        Ok(_) => serde_json::json!({
            "address": address, "timeout_ms": seconds * 1000,
            "elapsed_ms": started.elapsed().as_millis(), "outcome": "connected"
        }),
        Err(error) => serde_json::json!({
            "address": address, "timeout_ms": seconds * 1000,
            "elapsed_ms": started.elapsed().as_millis(), "outcome": "error",
            "kind": format!("{:?}", error.kind()), "raw_os_error": error.raw_os_error(),
            "message": error.to_string(), "connection_refused": error.kind() == io::ErrorKind::ConnectionRefused
        }),
    }
}

fn listener_observation(port: u16) -> Result<BTreeSet<(u32, std::net::SocketAddr)>> {
    cfw_windows_engine::observe_tcp_listeners_at_port(port).map_err(|error| error.to_string())
}

fn verify_closed_listener(
    source: &str,
    receipts: &Path,
    address: std::net::SocketAddr,
) -> Result<()> {
    let before = listener_observation(address.port())?;
    // Native target/control observations at abe0692d both timed out at 2 s,
    // then returned WSAECONNREFUSED just after 2 s with a 5 s deadline. Keep
    // the bounded refusal requirement and independently require no listeners.
    let primary = connect_observation(address, 5);
    let after = listener_observation(address.port())?;
    write(
        receipts,
        "closed-listener-observation.json",
        &serde_json::json!({
            "source": source, "primary": primary, "listeners_before": before, "listeners_after": after,
            "release_accepted": false
        }),
    )?;
    if primary["connection_refused"].as_bool() == Some(true)
        && before.is_empty()
        && after.is_empty()
    {
        return Ok(());
    }

    // Preserve the primary failure. A known listener followed by
    // its close distinguishes host connect timing from a surviving product
    // listener. Control/repeated attempts are diagnostics, never acceptance fallback.
    let control = std::net::TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| error.to_string())?;
    let control_address = control.local_addr().map_err(|error| error.to_string())?;
    let observed = cfw_windows_engine::observe_tcp_listeners_at_port(control_address.port())
        .map_err(|error| error.to_string())?;
    if !observed.contains(&(std::process::id(), control_address)) {
        return Err("native TCP table did not observe the live control listener".into());
    }
    drop(control);
    let control_before = listener_observation(control_address.port())?;
    let control_short = connect_observation(control_address, 2);
    let control_extended = connect_observation(control_address, 5);
    let target_extended = connect_observation(address, 5);
    write(
        receipts,
        "closed-listener-diagnostics.json",
        &serde_json::json!({
            "source": source, "primary": primary,
            "known_listener_while_open": observed, "known_listener_after_close": control_before,
            "control_short": control_short, "control_extended": control_extended,
            "target_extended": target_extended,
            "target_listeners_after": listener_observation(address.port())?,
            "control_listeners_after": listener_observation(control_address.port())?,
            "primary_failure_preserved": true, "release_accepted": false
        }),
    )?;
    Err(format!(
        "stopped GUI listener release is unproven: probe={primary}, before={before:?}, after={after:?}"
    ))
}

pub(super) fn proxy_snapshot() -> Result<ProxySettings> {
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let observed = (|| {
        let proxy =
            WindowsSystemProxy::new(&directory.path().join("proxy")).map_err(|e| e.to_string())?;
        proxy.snapshot().map_err(|e| e.to_string())
    })();
    let cleanup = directory.close().map_err(|e| e.to_string());
    match (observed, cleanup) {
        (Ok(snapshot), Ok(())) => Ok(snapshot),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; proxy observation cleanup: {cleanup}")),
    }
}

pub(super) fn proxy_digest(snapshot: &ProxySettings) -> Result<String> {
    Ok(cfw_singbox_config::sha256_hex(
        &serde_json::to_vec(snapshot).map_err(|e| e.to_string())?,
    ))
}

pub(super) fn probe(operation: &str, port: &str) -> Result<()> {
    if !["http", "closed"].contains(&operation) {
        return Err("unknown GUI network probe".into());
    }
    let (source, receipts) = validation_context()?;
    let port: u16 = port.parse().map_err(|_| "invalid GUI proxy port")?;
    if port == 0 {
        return Err("GUI proxy port must be nonzero".into());
    }
    let installed =
        cfw_windows_engine::runtime_host::InstalledRuntime::open().map_err(|e| e.to_string())?;
    let _image = installed.desktop().map_err(|e| e.to_string())?;
    let file = std::fs::File::open(receipts.join("launch.json")).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 {
        return Err("GUI launch receipt exceeds its bound".into());
    }
    let launch: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let pid = launch["process_id"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or("invalid GUI launch process")?;
    let gui = NativePeerProcess::open(pid).map_err(|e| e.to_string())?;
    let observer = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let expected_image = cfw_windows_engine::runtime_host::InstalledRuntime::desktop_path()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if launch["source"].as_str() != Some(source.as_str())
        || launch["process_creation_time"].as_u64() != Some(gui.identity().process_creation_time())
        || gui.identity().user_session() != observer.identity().user_session()
        || gui.identity().integrity_rid() != 0x2000
    {
        return Err("traffic observation does not match the launched GUI user session".into());
    }
    if gui
        .observed_image_path()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?
        != expected_image
    {
        return Err("network probe GUI image differs from the installed desktop".into());
    }
    let before = proxy_snapshot()?;
    let digest = proxy_digest(&before)?;
    if launch["user_proxy_before_sha256"].as_str() != Some(digest.as_str()) {
        return Err("LocalProxy changed the original user proxy options before traffic".into());
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    if operation == "http" {
        super::super::user_agent::traffic(address)?;
    } else {
        verify_closed_listener(&source, &receipts, address)?;
    }
    // This public observation revalidates identity/liveness on the retained
    // process object before and after querying its image, without reopening PID.
    if gui
        .observed_image_path()
        .map_err(|e| e.to_string())?
        .canonicalize()
        .map_err(|e| e.to_string())?
        != expected_image
    {
        return Err("network probe GUI image changed during observation".into());
    }
    if proxy_snapshot()? != before {
        return Err(format!(
            "LocalProxy changed user proxy options during the {operation} probe"
        ));
    }
    write(
        &receipts,
        &format!("{operation}-probe.json"),
        &serde_json::json!({
            "document": "cfw-installed-gui-network-probe-v1", "source": source,
            "operation": operation,
            "gui_process_id": pid, "gui_process_creation_time": gui.identity().process_creation_time(),
            "gui_same_user_session": true, "proxy_address": address.to_string(),
            "http_forwarding_verified": operation == "http", "listener_refused": operation == "closed",
            "user_proxy_sha256": digest,
            "user_proxy_unchanged": true, "release_accepted": false
        }),
    )
}
