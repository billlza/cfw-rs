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
    if !["http", "closed", "system-http"].contains(&operation) {
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
    let original_digest = launch["user_proxy_before_sha256"]
        .as_str()
        .ok_or("missing original user proxy digest")?;
    let system_proxy = operation == "system-http";
    let native_user_proxy = if system_proxy {
        let state =
            cfw_windows_engine::observe_lan_proxy_state().map_err(|error| error.to_string())?;
        let ports =
            cfw_windows_engine::observe_lan_proxy_ports().map_err(|error| error.to_string())?;
        if !state.manual_proxy_enabled
            || state.auto_config_enabled
            || state.auto_detect_enabled
            || ports != BTreeSet::from([port])
            || digest == original_digest
        {
            return Err(
                "GUI SystemProxy did not install the expected manual proxy endpoint".into(),
            );
        }
        Some(
            serde_json::json!({"manual_proxy_enabled":state.manual_proxy_enabled,
            "auto_config_enabled":state.auto_config_enabled,"auto_detect_enabled":state.auto_detect_enabled,
            "ports":ports}),
        )
    } else {
        if original_digest != digest {
            return Err("LocalProxy changed the original user proxy options before traffic".into());
        }
        None
    };
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let wininet_request_flags = if system_proxy {
        Some(super::super::user_agent::system_proxy_traffic()?)
    } else if operation == "http" {
        super::super::user_agent::traffic(address)?;
        None
    } else {
        verify_closed_listener(&source, &receipts, address)?;
        None
    };
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
            "user proxy options changed during the {operation} probe"
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
            "http_forwarding_verified": operation != "closed", "listener_refused": operation == "closed",
            "user_proxy_sha256": digest,
            "user_proxy_unchanged": !system_proxy, "original_user_proxy_sha256":original_digest,
            "system_proxy_applied":system_proxy,"applied_user_proxy_unchanged":system_proxy,
            "native_user_proxy":native_user_proxy,
            "wininet_request_flags":wininet_request_flags,"wininet_via_proxy_verified":system_proxy,
            "release_accepted": false
        }),
    )
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitNetworkExpectation {
    source: String,
    gui_process_id: u32,
    gui_process_creation_time: u64,
    proxy_port: u16,
    mode: String,
}

/// Called by the launcher only after its retained GUI process signaled with
/// exit code zero. A declared active-Quit case must also restore its original
/// proxy snapshot and release the selected listener; other scenarios omit it.
pub(super) fn verify_exit_network(
    source: &str,
    receipts: &Path,
    pid: u32,
    created: u64,
    original: &ProxySettings,
) -> Result<()> {
    let file = match std::fs::File::open(receipts.join("exit-network-expectation.json")) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Err("GUI exit network expectation exceeds its bound".into());
    }
    let expected: ExitNetworkExpectation =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if expected.source != source
        || expected.gui_process_id != pid
        || expected.gui_process_creation_time != created
        || expected.proxy_port == 0
        || expected.mode != "system_proxy"
    {
        return Err("active GUI exit observation differs from the retained process".into());
    }
    if proxy_snapshot()? != *original {
        return Err("active GUI exit did not restore the original user proxy".into());
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], expected.proxy_port));
    verify_closed_listener(source, receipts, address)?;
    if proxy_snapshot()? != *original {
        return Err("original user proxy changed during post-exit listener observation".into());
    }
    write(
        receipts,
        "exit-network.json",
        &serde_json::json!({
            "source":source,"gui_process_id":pid,"gui_process_creation_time":created,
            "mode":"system_proxy","proxy_address":address.to_string(),
            "observed_after_retained_gui_exit":true,"listener_refused":true,
            "original_user_proxy_restored":true,"user_proxy_sha256":proxy_digest(original)?,
            "release_accepted":false
        }),
    )
}
