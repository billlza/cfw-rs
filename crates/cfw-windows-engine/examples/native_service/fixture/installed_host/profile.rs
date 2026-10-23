use super::*;
use cfw_engine_api::{
    BackendErrorKind, CredentialProvision, CredentialProvisionRequest, ProfileDelayBackend,
    ProfileDelayTestRequest, ProfileProbeFailure,
};
use cfw_singbox_config::{
    CredentialAudience, CredentialKind, CredentialSecret, EngineSettings, ProjectionMode,
    ValidatedSingBoxProfile, sha256_hex,
};
use cfw_windows_engine::{backend::WindowsEngineBackend, runtime_host::InstalledDesktop};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROFILE: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const USER: &str = "installed-probe-user";
const PASSWORD: &str = "installed-probe-password";

pub(super) fn exercise(progress: &mut Progress) -> Result<serde_json::Value> {
    progress.record("profile_probe_open", 5)?;
    let desktop = Arc::new(InstalledDesktop::open().map_err(|e| e.to_string())?);
    let diagnostics = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(desktop.paths().root.join("installed-profile-probe.log"))
        .map_err(|e| e.to_string())?;
    let backend = WindowsEngineBackend::new(Arc::clone(&desktop), diagnostics);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(exercise_async(&desktop, &backend, progress))
}
fn candidate(
    profile: &ValidatedSingBoxProfile,
    names: Vec<String>,
    target: String,
    timeout: u16,
) -> Result<ProfileDelayTestRequest> {
    let projection = profile
        .project_proxy_probe(
            PROFILE,
            ProjectionMode::LocalProxy,
            &EngineSettings::default(),
        )
        .map_err(|e| e.to_string())?;
    Ok(ProfileDelayTestRequest {
        audience: projection.credential_audience().clone(),
        config_json: projection.as_json().into(),
        credential_slots: projection.credential_slots().to_vec(),
        proxies: names,
        timeout_ms: timeout,
        target_url: Some(target),
        expected_status: Some("204".into()),
    })
}
async fn header(socket: &mut tokio::net::TcpStream) -> Result<()> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = socket.read_u8().await.map_err(|e| e.to_string())?;
        bytes.push(byte);
        if bytes.len() > 8192 {
            return Err("probe HTTP header exceeded fixture bound".into());
        }
    }
    if !bytes.starts_with(b"HEAD /installed-probe HTTP/1.1\r\n") {
        return Err("probe did not use GA HEAD/path semantics".into());
    }
    Ok(())
}
async fn authenticated_peer(listener: tokio::net::TcpListener) -> Result<()> {
    let (mut socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
    let mut greeting = [0; 3];
    socket
        .read_exact(&mut greeting)
        .await
        .map_err(|e| e.to_string())?;
    if greeting != [5, 1, 2] {
        return Err("probe omitted SOCKS authentication".into());
    }
    socket.write_all(&[5, 2]).await.map_err(|e| e.to_string())?;
    if socket.read_u8().await.map_err(|e| e.to_string())? != 1 {
        return Err("probe SOCKS auth version differs".into());
    }
    let length = socket.read_u8().await.map_err(|e| e.to_string())?;
    let mut user = vec![0; length as usize];
    socket
        .read_exact(&mut user)
        .await
        .map_err(|e| e.to_string())?;
    let length = socket.read_u8().await.map_err(|e| e.to_string())?;
    let mut password = vec![0; length as usize];
    socket
        .read_exact(&mut password)
        .await
        .map_err(|e| e.to_string())?;
    if user != USER.as_bytes() || password != PASSWORD.as_bytes() {
        return Err("probe used different DPAPI material".into());
    }
    socket.write_all(&[1, 0]).await.map_err(|e| e.to_string())?;
    let mut connect = [0; 10];
    socket
        .read_exact(&mut connect)
        .await
        .map_err(|e| e.to_string())?;
    if connect != [5, 1, 0, 1, 192, 0, 2, 9, 0, 80] {
        return Err("probe SOCKS target differs".into());
    }
    socket
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
        .await
        .map_err(|e| e.to_string())?;
    header(&mut socket).await?;
    socket
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())
}
async fn exercise_async(
    desktop: &InstalledDesktop,
    backend: &WindowsEngineBackend,
    progress: &mut Progress,
) -> Result<serde_json::Value> {
    let before = checks::snapshot()?;
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    if before.state != cfw_engine_api::authority_v1::AuthorityState::Off || lineage.generation != 5
    {
        return Err("profile probe suite did not begin after verified generation five Off".into());
    }
    let original_proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let route = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    route
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(|e| e.to_string())?;
    let std::net::IpAddr::V4(address) = route.local_addr().map_err(|e| e.to_string())?.ip() else {
        return Err("fixture needs private IPv4 interface".into());
    };
    if !address.is_private() {
        return Err("fixture proxy endpoint is not private".into());
    }
    let peer = tokio::net::TcpListener::bind((address, 0))
        .await
        .map_err(|e| e.to_string())?;
    let address = peer.local_addr().map_err(|e| e.to_string())?;
    let profile=ValidatedSingBoxProfile::parse(&serde_json::json!({"outbounds":[{"type":"socks5","tag":"node",
        "server":address.ip().to_string(),"server_port":address.port(),"authentication":{
        "username_credential_ref":{"id":"33333333-3333-4333-8333-333333333333","kind":"socks5_username"},
        "password_credential_ref":{"id":"44444444-4444-4444-8444-444444444444","kind":"socks5_password"}}}]}).to_string()).map_err(|e|e.to_string())?;
    let references = profile.credential_references();
    let entries = references
        .iter()
        .map(|reference| {
            let value = match reference.kind() {
                CredentialKind::Socks5Username => USER,
                CredentialKind::Socks5Password => PASSWORD,
                _ => return Err("unexpected probe credential kind".to_owned()),
            };
            Ok(CredentialProvision::new(
                reference,
                CredentialSecret::new(value).map_err(|e| e.to_string())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    desktop
        .credentials()
        .provision(
            CredentialProvisionRequest::new(PROFILE, &profile, entries)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let request = candidate(
        &profile,
        vec!["node".into()],
        "http://192.0.2.9/installed-probe".into(),
        3000,
    )?;
    let mut foreign = request.clone();
    foreign.audience = CredentialAudience::new(
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        foreign.audience.profile_digest(),
    )
    .map_err(|e| e.to_string())?;
    let rejected = backend
        .test_profile_delays(foreign)
        .await
        .err()
        .ok_or("foreign probe audience was accepted")?;
    if rejected.kind != BackendErrorKind::ConfigurationRejected {
        return Err(format!("foreign probe rejection differs: {rejected}"));
    }
    progress.record("profile_probe_audience_rejected", 5)?;
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), authenticated_peer(peer))
            .await
            .map_err(|e| e.to_string())?
    });
    let rows = backend
        .test_profile_delays(request)
        .await
        .map_err(|e| e.to_string())?;
    server.await.map_err(|e| e.to_string())??;
    if rows.len() != 1
        || rows[0].name != "node"
        || !rows[0].delay.is_some_and(|delay| delay > 0)
        || rows[0].error_kind.is_some()
    {
        return Err("authenticated profile probe omitted its measured result".into());
    }
    let authenticated_result = rows[0].clone();
    progress.record("profile_probe_authenticated", 5)?;
    let origin = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let address = origin.local_addr().map_err(|e| e.to_string())?;
    let (seen, head_seen) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), async move {
            let (mut socket, _) = origin.accept().await.map_err(|e| e.to_string())?;
            header(&mut socket).await?;
            seen.send(())
                .map_err(|_| "probe head receiver disappeared".to_owned())?;
            let mut byte = [0];
            match socket.read(&mut byte).await {
                Ok(0) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
                other => Err(format!("cancelled probe socket was not retired: {other:?}")),
            }
        })
        .await
        .map_err(|e| e.to_string())?
    });
    let direct = ValidatedSingBoxProfile::direct();
    let request = candidate(
        &direct,
        vec!["direct".into()],
        format!("http://{address}/installed-probe"),
        10000,
    )?;
    let task_backend = backend.clone();
    let pending = tokio::spawn(async move { task_backend.test_profile_delays(request).await });
    tokio::time::timeout(Duration::from_secs(10), head_seen)
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    pending.abort();
    if !pending.await.is_err_and(|error| error.is_cancelled()) {
        return Err("probe future did not cancel".into());
    }
    server.await.map_err(|e| e.to_string())??;
    progress.record("profile_probe_cancellation", 5)?;
    let names: Vec<_> = (0..32)
        .map(|index| format!("{index}-{}", "n".repeat(500)))
        .collect();
    let request = candidate(
        &direct,
        names.clone(),
        "https://example.invalid/unused".into(),
        100,
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let rows = loop {
        match backend.test_profile_delays(request.clone()).await {
            Ok(rows) => break rows,
            Err(error)
                if error.kind == BackendErrorKind::ResourceExhausted
                    && Instant::now() < deadline =>
            {
                // Only an explicitly refused admission is retried. The
                // cancelled worker retains its sole slot through retirement.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    if rows.len() != 32
        || rows.iter().zip(&names).any(|(row, name)| {
            row.name != *name
                || row.delay.is_some()
                || row.error_kind != Some(ProfileProbeFailure::NotFound)
        })
    {
        return Err("large profile probe results lost ordering or failure semantics".into());
    }
    let encoded = serde_json::to_vec(&rows).map_err(|e| e.to_string())?;
    if encoded.len() <= 4096 || encoded.len() > 65536 {
        return Err("large profile probe did not exercise its bounded response".into());
    }
    let after = checks::snapshot()?;
    if after != before
        || desktop
            .generations()
            .load_lineage()
            .map_err(|e| e.to_string())?
            != lineage
        || desktop
            .storage()
            .proxy()
            .snapshot()
            .map_err(|e| e.to_string())?
            != original_proxy
        || std::fs::read_dir(desktop.paths().runtime.join("probe-engine-v1"))
            .map_err(|e| e.to_string())?
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err(
            "profile probes changed authority/lineage/proxy or retained worker files".into(),
        );
    }
    progress.record("profile_probe_complete", 5)?;
    Ok(
        serde_json::json!({"shared_profile_delay_backend":true,"authenticated_result":authenticated_result,
        "wrong_audience_rejected":true,"cancellation_observed":true,"capacity_reused":true,
        "large_result_count":rows.len(),"large_result_bytes":encoded.len(),"large_result_sha256":sha256_hex(&encoded),
        "authority_before":before,"authority_after":after,"authority_unchanged":true,"lineage_unchanged":true,
        "proxy_unchanged":true,"worker_directory_empty":true,"release_accepted":false}),
    )
}
