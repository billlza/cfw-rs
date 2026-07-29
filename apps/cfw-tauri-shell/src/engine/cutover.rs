use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cfw_engine_api::{
    CutoverPreflightAttestation, CutoverPreflightBackend, CutoverPreflightOutcome,
    CutoverPreflightRequest, EngineMode,
};
use cfw_singbox_config::{CredentialRef, EngineSettings};
use serde::Serialize;
use tauri::State;

use super::ManagedEngine;
use crate::commands::ManagedProfiles;
use crate::legacy::{LegacyRetirementGate, LegacyRetirementStatus};

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_RECEIPT_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Default)]
pub(super) struct CutoverPreparationGate {
    authority: Mutex<Option<CutoverAuthority>>,
}

#[derive(Debug, Clone)]
pub(crate) struct CutoverAuthority {
    receipt_id: String,
    received_at: Instant,
    expires_after: Duration,
    profile_id: String,
    profile_digest: String,
    settings: EngineSettings,
    request: CutoverPreflightRequest,
    attestation: CutoverPreflightAttestation,
}

impl CutoverAuthority {
    pub(crate) fn target(&self) -> EngineMode {
        self.request.target()
    }

    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    pub(crate) fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    pub(crate) fn request(&self) -> &CutoverPreflightRequest {
        &self.request
    }

    pub(crate) fn attestation(&self) -> &CutoverPreflightAttestation {
        &self.attestation
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum UiCutoverPreparation {
    AwaitingApproval {
        target: EngineMode,
    },
    Ready {
        receipt_id: String,
        target: EngineMode,
        profile_id: String,
        valid_for_millis: u64,
    },
}

impl CutoverPreparationGate {
    pub(super) fn invalidate(&self) -> Result<(), String> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| "cutover preparation state is unavailable".to_owned())?;
        *authority = None;
        Ok(())
    }

    fn store(
        &self,
        profile_id: String,
        profile_digest: String,
        settings: EngineSettings,
        request: CutoverPreflightRequest,
        attestation: CutoverPreflightAttestation,
        now: Instant,
    ) -> Result<UiCutoverPreparation, String> {
        validate_ready_binding(&request, &attestation)?;
        let expires_after =
            Duration::from_millis(u64::from(attestation.valid_for_millis)).min(MAX_RECEIPT_TTL);
        let receipt_id = uuid::Uuid::new_v4().hyphenated().to_string();
        let response = UiCutoverPreparation::Ready {
            receipt_id: receipt_id.clone(),
            target: request.target(),
            profile_id: profile_id.clone(),
            valid_for_millis: expires_after.as_millis() as u64,
        };
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| "cutover preparation state is unavailable".to_owned())?;
        *authority = Some(CutoverAuthority {
            receipt_id,
            received_at: now,
            expires_after,
            profile_id,
            profile_digest,
            settings,
            request,
            attestation,
        });
        Ok(response)
    }

    pub(super) fn take(&self, receipt_id: &str, now: Instant) -> Result<CutoverAuthority, String> {
        let mut stored = self
            .authority
            .lock()
            .map_err(|_| "cutover preparation state is unavailable".to_owned())?;
        let Some(authority) = stored.as_ref() else {
            return Err("CutoverReceiptMissing: run Prepare Cutover again".into());
        };
        if authority.receipt_id != receipt_id {
            return Err("CutoverReceiptMismatch: the one-shot receipt does not match".into());
        }
        if now
            .checked_duration_since(authority.received_at)
            .is_none_or(|elapsed| elapsed > authority.expires_after)
        {
            *stored = None;
            return Err("CutoverReceiptExpired: run Prepare Cutover again".into());
        }
        stored
            .take()
            .ok_or_else(|| "CutoverReceiptMissing: preparation disappeared".into())
    }

    pub(super) fn readiness(&self, now: Instant) -> Result<(bool, Option<String>), String> {
        let mut stored = self
            .authority
            .lock()
            .map_err(|_| "cutover preparation state is unavailable".to_owned())?;
        let Some(authority) = stored.as_ref() else {
            return Ok((
                false,
                Some("run Prepare Cutover and complete any System Extension approval".into()),
            ));
        };
        if now
            .checked_duration_since(authority.received_at)
            .is_none_or(|elapsed| elapsed > authority.expires_after)
        {
            *stored = None;
            return Ok((
                false,
                Some("the cutover preparation expired; run it again".into()),
            ));
        }
        Ok((true, None))
    }
}

pub(crate) async fn run_native_preflight(
    backend: &dyn CutoverPreflightBackend,
    request: CutoverPreflightRequest,
) -> Result<CutoverPreflightOutcome, String> {
    tokio::time::timeout(PREFLIGHT_TIMEOUT, backend.preflight_cutover(request))
        .await
        .map_err(|_| {
            "native cutover preflight exceeded 45 seconds; the legacy VPN was not changed"
                .to_owned()
        })?
        .map_err(|error| {
            format!("native cutover preflight failed; the legacy VPN was not changed: {error}")
        })
}

pub(crate) fn validate_outcome_binding(
    request: &CutoverPreflightRequest,
    outcome: &CutoverPreflightOutcome,
) -> Result<(), String> {
    match outcome {
        CutoverPreflightOutcome::Ready { attestation } => {
            validate_ready_binding(request, attestation)
        }
        CutoverPreflightOutcome::AwaitingApproval {
            target,
            context,
            system_proxy_config_digest,
            tunnel_config_digest,
            credential_audience,
        } if *target == request.target()
            && *context == request.system_proxy_request().context
            && system_proxy_config_digest == &request.system_proxy_request().config_digest
            && tunnel_config_digest == &request.tunnel_request().config_digest
            && credential_audience == &request.system_proxy_request().credential_audience =>
        {
            Ok(())
        }
        CutoverPreflightOutcome::AwaitingApproval { .. } => {
            Err("native cutover approval response does not match the requested replacement".into())
        }
    }
}

fn validate_ready_binding(
    request: &CutoverPreflightRequest,
    attestation: &CutoverPreflightAttestation,
) -> Result<(), String> {
    let references = request
        .system_proxy_request()
        .credential_slots
        .iter()
        .map(|slot| slot.reference().clone())
        .collect::<BTreeSet<CredentialRef>>()
        .into_iter()
        .collect::<Vec<_>>();
    if attestation.validate()
        && attestation.target == request.target()
        && attestation.context == request.system_proxy_request().context
        && attestation.system_proxy_config_digest == request.system_proxy_request().config_digest
        && attestation.tunnel_config_digest == request.tunnel_request().config_digest
        && attestation.credential_audience == request.system_proxy_request().credential_audience
        && attestation.credential_references == references
    {
        Ok(())
    } else {
        Err("native cutover attestation does not match the exact staged replacement".into())
    }
}

#[tauri::command]
pub(crate) async fn prepare_legacy_cutover(
    engine: State<'_, ManagedEngine>,
    retirement: State<'_, LegacyRetirementGate>,
    profiles: State<'_, ManagedProfiles>,
    launch: State<'_, crate::LaunchContext>,
    target: EngineMode,
) -> Result<UiCutoverPreparation, String> {
    if !launch.is_migration_handoff() {
        return Err(
            "legacy preparation requires launching 0.4.0 with --migration-handoff while the old GUI remains running"
                .into(),
        );
    }
    launch.require_renderer_ready_published()?;
    crate::legacy::require_canonical_handoff_candidate()?;
    if !matches!(
        retirement.status()?,
        LegacyRetirementStatus::AwaitingConfirmation
            | LegacyRetirementStatus::ManualCleanupRequired { .. }
    ) {
        return Err(
            "legacy cutover preparation is unavailable in the current retirement state".into(),
        );
    }
    engine.require_capability(target)?;
    let _maintenance = engine
        .reserve_profile_mutation()
        .map_err(|error| error.to_string())?;
    engine.cutover.invalidate()?;
    let selected = profiles
        .repository()
        .require_selected()
        .map_err(|error| error.to_string())?;
    let settings = engine.engine_settings().clone();
    let request = engine
        .coordinator
        .prepare_cutover(
            target,
            selected.record.id.clone(),
            selected.profile.clone(),
            settings.clone(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let outcome = run_native_preflight(engine.preflight_backend.as_ref(), request.clone()).await?;
    validate_outcome_binding(&request, &outcome)?;
    match outcome {
        CutoverPreflightOutcome::AwaitingApproval { .. } => {
            Ok(UiCutoverPreparation::AwaitingApproval { target })
        }
        CutoverPreflightOutcome::Ready { attestation } => engine.cutover.store(
            selected.record.id,
            selected.record.digest,
            settings,
            request,
            attestation,
            Instant::now(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use cfw_engine_api::{EngineCommandContext, EngineStartRequest, TunnelNetworkOptions};

    use super::*;

    fn request() -> CutoverPreflightRequest {
        let context = EngineCommandContext {
            installation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            config_epoch: 1,
            generation: 4,
        };
        let credential_audience = cfw_engine_api::CredentialAudience::new(
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "33".repeat(32),
        )
        .expect("audience");
        let proxy = EngineStartRequest {
            context: context.clone(),
            credential_audience: credential_audience.clone(),
            config_json: "{}".into(),
            config_content_digest: "10".repeat(32),
            config_digest: "11".repeat(32),
            credential_slots: Vec::new(),
            tunnel_options: None,
        };
        let tunnel = EngineStartRequest {
            context,
            credential_audience,
            config_json: "{}".into(),
            config_content_digest: "20".repeat(32),
            config_digest: "22".repeat(32),
            credential_slots: Vec::new(),
            tunnel_options: Some(TunnelNetworkOptions {
                ipv6_enabled: true,
                bypass_private_networks: true,
                mtu: 1500,
            }),
        };
        CutoverPreflightRequest::new(EngineMode::Tunnel, proxy, tunnel).expect("request")
    }

    fn attestation(
        request: &CutoverPreflightRequest,
        validity: u32,
    ) -> CutoverPreflightAttestation {
        CutoverPreflightAttestation {
            attestation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            target: request.target(),
            context: request.system_proxy_request().context.clone(),
            system_proxy_config_digest: request.system_proxy_request().config_digest.clone(),
            tunnel_config_digest: request.tunnel_request().config_digest.clone(),
            credential_audience: request.system_proxy_request().credential_audience.clone(),
            credential_references: Vec::new(),
            valid_for_millis: validity,
        }
    }

    fn ready_receipt_id(value: UiCutoverPreparation) -> String {
        match value {
            UiCutoverPreparation::Ready { receipt_id, .. } => receipt_id,
            UiCutoverPreparation::AwaitingApproval { .. } => panic!("expected ready receipt"),
        }
    }

    #[test]
    fn one_shot_receipt_preserves_authority_on_wrong_token_and_rejects_replay() {
        let gate = CutoverPreparationGate::default();
        let request = request();
        let now = Instant::now();
        let receipt = ready_receipt_id(
            gate.store(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                "33".repeat(32),
                EngineSettings::default(),
                request.clone(),
                attestation(&request, 300_000),
                now,
            )
            .expect("store"),
        );
        assert!(gate.take("wrong", now).is_err());
        let authority = gate.take(&receipt, now).expect("correct token");
        assert_eq!(authority.request(), &request);
        assert!(gate.take(&receipt, now).is_err(), "receipt is one-shot");
    }

    #[test]
    fn expiry_is_enforced_before_mutation_but_not_rechecked_after_authority_take() {
        let gate = CutoverPreparationGate::default();
        let request = request();
        let now = Instant::now();
        let created = now.checked_sub(Duration::from_secs(301)).expect("prior");
        let receipt = ready_receipt_id(
            gate.store(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                "33".repeat(32),
                EngineSettings::default(),
                request.clone(),
                attestation(&request, 300_000),
                created,
            )
            .expect("store"),
        );
        assert!(gate.take(&receipt, now).is_err());

        let receipt = ready_receipt_id(
            gate.store(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                "33".repeat(32),
                EngineSettings::default(),
                request.clone(),
                attestation(&request, 300_000),
                now,
            )
            .expect("store"),
        );
        let taken = gate.take(&receipt, now).expect("take before mutation");
        // Destructive cleanup may exceed the proof TTL. The live proof is
        // consumed before cleanup and start is never blocked by a later clock
        // check after the old network has already been retired.
        assert_eq!(taken.target(), EngineMode::Tunnel);
    }

    #[test]
    fn native_attestation_must_match_both_projection_digests() {
        let request = request();
        let mut wrong = attestation(&request, 300_000);
        wrong.tunnel_config_digest = "44".repeat(32);
        assert!(validate_ready_binding(&request, &wrong).is_err());
    }
}
