use cfw_engine_api::{
    CutoverPreflightRequest, CutoverPreflightRequestError, EngineCommandContext, EngineMode,
    EngineSessionIdentity, EngineStartRequest, EngineState, TunnelNetworkOptions,
};
use cfw_singbox_config::{
    EngineSettings, ProjectedConfig, ProjectionMode, ValidatedSingBoxProfile,
};

use crate::{EngineCoordinatorError, runtime::CoordinatorState};

pub(crate) fn prepare_cutover_request(
    state: &CoordinatorState,
    session: &EngineSessionIdentity,
    target: EngineMode,
    profile_id: &str,
    profile: &ValidatedSingBoxProfile,
    settings: &EngineSettings,
) -> Result<CutoverPreflightRequest, EngineCoordinatorError> {
    if target == EngineMode::Off {
        return Err(EngineCoordinatorError::InvalidCutoverPreparation(
            CutoverPreflightRequestError::ActiveTargetRequired,
        ));
    }
    if state.snapshot.desired_mode != EngineMode::Off
        || state.snapshot.state != EngineState::Off
        || state.native_lease.is_some()
    {
        return Err(EngineCoordinatorError::CutoverRequiresOff);
    }
    if !profile.routes_through_remote() {
        return Err(EngineCoordinatorError::CutoverRequiresRemoteOutbound);
    }

    let generation = state
        .snapshot
        .generation
        .checked_add(1)
        .ok_or(EngineCoordinatorError::GenerationExhausted)?;
    let context = EngineCommandContext::new(session, generation);
    let system_proxy = profile.project(profile_id, ProjectionMode::SystemProxy, settings)?;
    let tunnel = profile.project(profile_id, ProjectionMode::Tunnel, settings)?;
    CutoverPreflightRequest::new(
        target,
        start_request(&system_proxy, settings, context.clone()),
        start_request(&tunnel, settings, context),
    )
    .map_err(EngineCoordinatorError::InvalidCutoverPreparation)
}

pub(crate) fn start_request(
    projected: &ProjectedConfig,
    settings: &EngineSettings,
    context: EngineCommandContext,
) -> EngineStartRequest {
    EngineStartRequest {
        context,
        credential_audience: projected.credential_audience().clone(),
        config_json: projected.as_json().to_owned(),
        config_content_digest: projected.configuration_digest().to_owned(),
        config_digest: projected.digest().to_owned(),
        credential_slots: projected.credential_slots().to_vec(),
        tunnel_options: match projected.mode() {
            ProjectionMode::SystemProxy => None,
            ProjectionMode::Tunnel => Some(TunnelNetworkOptions {
                ipv6_enabled: settings.enable_ipv6,
                bypass_private_networks: settings.bypass_private_networks,
                direct_ipv4_hosts: projected.direct_ipv4_hosts(),
                mtu: settings.tunnel_mtu,
            }),
        },
    }
}
