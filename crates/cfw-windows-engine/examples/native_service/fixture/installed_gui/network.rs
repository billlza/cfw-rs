//! Real traffic through the listener selected by the installed GUI. Proxy
//! options are compared without putting raw proxy/PAC strings in artifacts.
use super::*;
use cfw_windows_engine::{ProxySettings, WindowsSystemProxy};
use std::io::Read;

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
        match std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
            Err(error) => {
                return Err(format!(
                    "stopped GUI listener could not be observed: {error}"
                ));
            }
            Ok(_) => return Err("stopped GUI proxy listener still accepts connections".into()),
        }
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
