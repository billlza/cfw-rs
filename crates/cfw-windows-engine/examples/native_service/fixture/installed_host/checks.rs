use super::*;
use cfw_engine_api::{
    CredentialProvision, CredentialProvisionRequest, CredentialVaultError, EngineCommandContext,
    EngineStartRequest, TunnelNetworkOptions,
};
use cfw_singbox_config::{
    CredentialKind, CredentialSecret, EngineSettings, ProjectionMode, ValidatedSingBoxProfile,
    canonicalize_configuration_value, configuration_identity_digest, sha256_hex,
};
use cfw_windows_engine::{
    Error,
    credential_lifecycle::CredentialLifecycleError,
    runtime_host::{HostError, InstalledDesktop},
};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

pub(super) fn exercise(desktop: &InstalledDesktop) -> Result<serde_json::Value> {
    let before = snapshot()?;
    let lineage = desktop
        .generations()
        .load_lineage()
        .map_err(|e| e.to_string())?;
    let proxy = desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?;
    let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let controller = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let settings = EngineSettings {
        mixed_port: mixed.local_addr().map_err(|e| e.to_string())?.port(),
        controller_port: controller.local_addr().map_err(|e| e.to_string())?.port(),
        ..Default::default()
    };
    let context = EngineCommandContext {
        installation_id: lineage.session.installation_id.clone(),
        config_epoch: lineage.session.config_epoch,
        generation: lineage
            .generation
            .checked_add(1)
            .ok_or("candidate generation overflow")?,
    };
    let profile = ValidatedSingBoxProfile::parse(r#"{"outbounds":[{
        "type":"socks5","tag":"proxy","server":"example.com","server_port":1080,
        "authentication":{
            "username_credential_ref":{"id":"11111111-1111-4111-8111-111111111111","kind":"socks5_username"},
            "password_credential_ref":{"id":"22222222-2222-4222-8222-222222222222","kind":"socks5_password"}
        }}]}"#).map_err(|e| e.to_string())?;
    let references = profile.credential_references();
    let material = references
        .iter()
        .map(|reference| {
            let secret = match reference.kind() {
                CredentialKind::Socks5Username => "installed-check-user",
                CredentialKind::Socks5Password => "installed-check-password",
                _ => return Err("unexpected configuration-check credential kind".to_owned()),
            };
            Ok(CredentialProvision::new(
                reference,
                CredentialSecret::new(secret).map_err(|e| e.to_string())?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    desktop
        .credentials()
        .provision(
            CredentialProvisionRequest::new(PROFILE, &profile, material)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let mut checked_modes = Vec::new();
    for mode in [
        ProjectionMode::LocalProxy,
        ProjectionMode::SystemProxy,
        ProjectionMode::Tunnel,
        ProjectionMode::TunnelSystemProxy,
    ] {
        let request = candidate(&profile, PROFILE, mode, &settings, context.clone())?;
        let digest = request.config_digest.clone();
        let checked = desktop
            .check_configuration(request, Instant::now() + LIMIT)
            .map_err(|e| format!("installed native configuration check: {e}"))?;
        if checked.configuration_digest != digest || checked.process_id == 0 {
            return Err("installed check returned unrelated native identity".into());
        }
        checked_modes.push(serde_json::json!({"mode":mode,"configuration_digest":digest,"retired_worker_pid":checked.process_id}));
    }
    // A second profile cannot reuse the first profile's DPAPI bindings.
    let foreign = candidate(
        &profile,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        ProjectionMode::LocalProxy,
        &settings,
        context.clone(),
    )?;
    match desktop.check_configuration(foreign, Instant::now() + LIMIT) {
        Err(HostError::Credentials(CredentialLifecycleError::Vault(
            CredentialVaultError::InvalidMaterial,
        ))) => {}
        result => {
            return Err(format!(
                "foreign credential audience was not explicitly rejected: {}",
                outcome(result)
            ));
        }
    }
    let direct =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .map_err(|e| e.to_string())?;
    let normal = candidate(
        &direct,
        PROFILE,
        ProjectionMode::LocalProxy,
        &settings,
        context,
    )?;
    let mut invalid = normal.clone();
    let mut config: serde_json::Value =
        serde_json::from_str(&invalid.config_json).map_err(|e| e.to_string())?;
    config["outbounds"][0]["type"] = "cfw-invalid-native-check".into();
    invalid.config_json = serde_json::to_string(&canonicalize_configuration_value(config))
        .map_err(|e| e.to_string())?;
    invalid.config_content_digest = sha256_hex(invalid.config_json.as_bytes());
    invalid.config_digest = configuration_identity_digest(
        &invalid.config_content_digest,
        &invalid.credential_audience,
        &invalid.credential_slots,
        invalid.mode,
        &invalid.tunnel_options,
    )
    .map_err(|e| e.to_string())?;
    match desktop.check_configuration(invalid, Instant::now() + LIMIT) {
        Err(HostError::Executable(Error::Rejected("invalid_config" | "construct_failed"))) => {}
        result => {
            return Err(format!(
                "invalid native candidate did not reach parser rejection: {}",
                outcome(result)
            ));
        }
    }
    let mut wrong_epoch = normal.clone();
    wrong_epoch.context.config_epoch = wrong_epoch
        .context
        .config_epoch
        .checked_add(1)
        .ok_or("candidate epoch overflow")?;
    match desktop.check_configuration(wrong_epoch, Instant::now() + LIMIT) {
        Err(HostError::State("candidate belongs to another installation or epoch")) => {}
        result => {
            return Err(format!(
                "foreign epoch was not explicitly rejected: {}",
                outcome(result)
            ));
        }
    }
    match desktop.check_configuration(normal, Instant::now()) {
        Err(HostError::Executable(Error::Timeout)) => {}
        result => {
            return Err(format!(
                "expired configuration check was not rejected: {}",
                outcome(result)
            ));
        }
    }
    if snapshot()? != before
        || desktop
            .generations()
            .load_lineage()
            .map_err(|e| e.to_string())?
            != lineage
    {
        return Err(
            "configuration checking changed Authority state or reserved a generation".into(),
        );
    }
    if desktop
        .storage()
        .proxy()
        .snapshot()
        .map_err(|e| e.to_string())?
        != proxy
    {
        return Err("configuration checking changed WinINet settings".into());
    }
    if mixed.local_addr().map_err(|e| e.to_string())?.port() != settings.mixed_port
        || controller.local_addr().map_err(|e| e.to_string())?.port() != settings.controller_port
        || std::fs::read_dir(desktop.paths().runtime.join("check-engine-v1"))
            .map_err(|e| e.to_string())?
            .next()
            .transpose()
            .map_err(|e| e.to_string())?
            .is_some()
    {
        return Err("configuration check retained resources or changed occupied listeners".into());
    }
    Ok(
        serde_json::json!({"checked_modes":checked_modes,"authority_unchanged":true,"proxy_unchanged":true,
        "listeners_occupied_throughout":true,"check_directory_empty":true,"credential_audience_rejected":true,
        "native_parser_rejected_invalid_candidate":true,"foreign_epoch_rejected":true,"expired_check_rejected":true}),
    )
}
pub(super) fn candidate(
    profile: &ValidatedSingBoxProfile,
    id: &str,
    mode: ProjectionMode,
    settings: &EngineSettings,
    context: EngineCommandContext,
) -> Result<EngineStartRequest> {
    let projection = profile
        .project(id, mode, settings)
        .map_err(|e| e.to_string())?;
    Ok(EngineStartRequest {
        context,
        mode,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().to_owned(),
        config_content_digest: projection.configuration_digest().to_owned(),
        config_digest: projection.digest().to_owned(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: mode.has_tunnel().then(|| TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu: settings.tunnel_mtu,
            system_proxy_port: (mode == ProjectionMode::TunnelSystemProxy)
                .then_some(settings.mixed_port),
        }),
    })
}
fn outcome(
    result: std::result::Result<cfw_windows_engine::CheckedConfiguration, HostError>,
) -> String {
    match result {
        Ok(_) => "unexpected success".into(),
        Err(error) => error.to_string(),
    }
}
pub(super) fn snapshot() -> Result<cfw_windows_engine::authority::AuthoritySnapshot> {
    let installed = InstalledRuntime::open().map_err(|e| e.to_string())?;
    let mut channel = AuthorityChannel::connect(
        SERVICE_NAME,
        ServiceClientRole::Desktop,
        Arc::new(installed.runtime().map_err(|e| e.to_string())?),
    )
    .map_err(|e| e.to_string())?;
    match channel
        .request(
            Request::new(Command::Observe).map_err(|e| e.to_string())?,
            Instant::now() + LIMIT,
        )
        .map_err(|e| e.to_string())?
    {
        Response::Observed(snapshot) => Ok(snapshot),
        _ => Err("installed check omitted Authority observation".into()),
    }
}
