//! Latency probes of saved nodes through a transient outbound-only engine.

use super::*;

pub(in crate::commands) struct ProbePolicy {
    pub url: String,
    pub timeout_ms: u16,
    pub concurrency: usize,
    pub expected_status: String,
}

pub(in crate::commands) async fn probe_saved_nodes(
    engine: &ManagedEngine,
    profiles: &crate::commands::ManagedProfiles,
    profile_id: Option<String>,
    proxies: Vec<String>,
    policy: ProbePolicy,
) -> Result<Vec<ProxyDelayResult>, String> {
    if proxies.is_empty()
        || proxies.len() > MAX_DELAY_PROXIES
        || proxies
            .iter()
            .any(|name| name.is_empty() || name.len() > MAX_CONTROLLER_NAME_BYTES)
    {
        return Err(ControllerCommandError::InvalidInput(
            "proxy delay target set is outside its bounds",
        )
        .to_ipc());
    }
    let timeout = policy.timeout_ms;
    if !(100..=10000).contains(&timeout) {
        return Err("probe timeout must be 100..=10000 milliseconds".into());
    }
    let limit = policy.concurrency.clamp(1, MAX_DELAY_CONCURRENCY);
    cfw_singbox_config::validate_expected_status(&policy.expected_status)
        .map_err(|error| error.to_string())?;
    let snapshot = engine.coordinator.snapshot();
    if snapshot.state == EngineState::Off
        && snapshot.desired_mode == cfw_engine_api::EngineMode::Off
    {
        if proxies.len() > MAX_DELAY_CONCURRENCY || !(100..=10_000).contains(&timeout) {
            return Err("offline latency batch or timeout exceeds its bounds".into());
        }
        let stored =
            crate::commands::profiles::read_repository(profiles.repository(), |repository| {
                repository
                    .require_selected()
                    .map_err(|error| error.to_string())
            })
            .await?;
        if profile_id.as_deref() != Some(stored.record.id.as_str()) {
            return Err("selected profile changed before the latency test".into());
        }
        let settings = engine.engine_settings()?;
        let probe = stored
            .profile
            .project_proxy_probe(
                &stored.record.id,
                cfw_singbox_config::ProjectionMode::SystemProxy,
                &settings,
            )
            .map_err(|error| error.to_string())?;
        // A Tailscale node keeps its tailnet registration with the running
        // core, so the offline probe reports it as unsupported instead of
        // registering a second node from its key.
        let (proxies, unsupported): (Vec<String>, Vec<String>) = proxies
            .into_iter()
            .partition(|name| !probe.excluded_tags().contains(name));
        let mut results = unsupported
            .into_iter()
            .map(|name| ProxyDelayResult {
                name,
                delay: None,
                error_kind: Some(cfw_controller::ProxyDelayFailureKind::Unsupported),
                error: Some("Tailscale nodes are tested by the running core".into()),
            })
            .collect::<Vec<_>>();
        if proxies.is_empty() {
            return Ok(results);
        }
        let request = cfw_engine_api::ProfileDelayTestRequest {
            audience: probe.credential_audience().clone(),
            config_json: probe.as_json().to_owned(),
            credential_slots: probe.credential_slots().to_vec(),
            proxies,
            timeout_ms: timeout,
            target_url: Some(policy.url),
            expected_status: Some(policy.expected_status),
        };
        let measured = engine
            .profile_delay_backend
            .test_profile_delays(request)
            .await
            .map_err(|error| format!("Profile latency test failed: {}", error.message))?;
        results.extend(measured.into_iter().map(|result| ProxyDelayResult {
            name: result.name,
            delay: result.delay,
            error_kind: result.error_kind.map(|kind| match kind {
                cfw_engine_api::ProfileProbeFailure::Timeout => {
                    cfw_controller::ProxyDelayFailureKind::Timeout
                }
                cfw_engine_api::ProfileProbeFailure::NotFound => {
                    cfw_controller::ProxyDelayFailureKind::NotFound
                }
                cfw_engine_api::ProfileProbeFailure::ProbeFailed => {
                    cfw_controller::ProxyDelayFailureKind::ProbeFailed
                }
            }),
            error: None,
        }));
        return Ok(results);
    }
    let client = controller_client(engine).map_err(|error| error.to_ipc())?;
    let accepted = engine
        .coordinator
        .restart_spec()
        .await
        .map_err(|error| error.to_string())?
        .ok_or("the runtime has no accepted profile source")?;
    if profile_id
        .as_deref()
        .is_some_and(|id| id != accepted.profile_id())
        || !accepted.matches_ready_snapshot(&engine.coordinator.snapshot())
    {
        return Err("the displayed profile no longer matches the running core".into());
    }
    Ok(futures_util::stream::iter(proxies)
        .map(|name| {
            let client = client.clone();
            let url = policy.url.clone();
            let status = policy.expected_status.clone();
            async move {
                match client
                    .proxy_delay_matching(&name, &url, timeout, &status)
                    .await
                {
                    Ok(delay) => ProxyDelayResult {
                        name,
                        delay: Some(delay),
                        error_kind: None,
                        error: None,
                    },
                    Err(error) => ProxyDelayResult {
                        name,
                        delay: None,
                        error_kind: Some(cfw_controller::ProxyDelayFailureKind::from(&error)),
                        error: Some(ipc_error(error)),
                    },
                }
            }
        })
        .buffer_unordered(limit)
        .collect()
        .await)
}

pub(super) fn resolve_delay_test_url(
    url: Option<String>,
) -> Result<String, ControllerCommandError> {
    match url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None | Some(DEFAULT_DELAY_TEST_URL) => Ok(DEFAULT_DELAY_TEST_URL.to_owned()),
        Some(_) => Err(ControllerCommandError::DelayTargetNotAllowed),
    }
}
