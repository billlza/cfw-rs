use cfw_singbox_config::{EngineSettings, ProjectionMode};

use super::*;
use crate::{
    TunnelNetworkOptions,
    test_support::{
        CREDENTIAL_ID, INSTALLATION_ID, PROFILE_ID, audience, context, trojan_profile,
        trojan_reference, uuid,
    },
};

const ATTESTATION_ID: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

fn request(mode: ProjectionMode) -> EngineStartRequest {
    let projected = trojan_profile(CREDENTIAL_ID, 443)
        .project(PROFILE_ID, mode, &EngineSettings::default())
        .expect("projection");
    EngineStartRequest {
        context: context(),
        mode,
        credential_audience: projected.credential_audience().clone(),
        config_json: "never-print-this-config".into(),
        config_content_digest: projected.configuration_digest().to_owned(),
        config_digest: projected.digest().to_owned(),
        credential_slots: projected.credential_slots().to_vec(),
        tunnel_options: (mode == ProjectionMode::Tunnel).then(|| TunnelNetworkOptions {
            ipv6_enabled: false,
            bypass_private_networks: true,
            direct_ipv4_hosts: projected.direct_ipv4_hosts(),
            mtu: 1_500,
            system_proxy_port: None,
        }),
    }
}

fn preflight(
    target: EngineMode,
    change: impl FnOnce(&mut EngineStartRequest, &mut EngineStartRequest),
) -> Result<CutoverPreflightRequest, CutoverPreflightRequestError> {
    let mut system_proxy = request(ProjectionMode::SystemProxy);
    let mut tunnel = request(ProjectionMode::Tunnel);
    change(&mut system_proxy, &mut tunnel);
    CutoverPreflightRequest::new(target, system_proxy, tunnel)
}

#[test]
fn a_preflight_pairs_both_replacement_runtimes_for_an_active_target() {
    for target in [EngineMode::SystemProxy, EngineMode::Tunnel] {
        let preflight = preflight(target, |_, _| {}).expect("preflight");
        assert_eq!(preflight.target(), target);
        assert_eq!(
            preflight.system_proxy_request(),
            &request(ProjectionMode::SystemProxy)
        );
        assert_eq!(preflight.tunnel_request(), &request(ProjectionMode::Tunnel));
        let debug = format!("{preflight:?}");
        assert!(debug.starts_with("CutoverPreflightRequest {"), "{debug}");
        assert!(!debug.contains("never-print-this-config"), "{debug}");
    }
    for target in [
        EngineMode::Off,
        EngineMode::LocalProxy,
        EngineMode::TunnelSystemProxy,
    ] {
        assert_eq!(
            preflight(target, |_, _| {}),
            Err(CutoverPreflightRequestError::ActiveTargetRequired)
        );
    }
}

#[test]
fn each_runtime_must_be_projected_for_its_own_slot() {
    let swapped = CutoverPreflightRequest::new(
        EngineMode::Tunnel,
        request(ProjectionMode::Tunnel),
        request(ProjectionMode::SystemProxy),
    );
    assert_eq!(
        swapped,
        Err(CutoverPreflightRequestError::ProjectionModeMismatch)
    );
    let options = request(ProjectionMode::Tunnel).tunnel_options;
    assert_eq!(
        preflight(EngineMode::Tunnel, |system_proxy, _| system_proxy
            .tunnel_options =
            options),
        Err(CutoverPreflightRequestError::ProjectionModeMismatch)
    );
    assert_eq!(
        preflight(EngineMode::Tunnel, |_, tunnel| tunnel.tunnel_options = None),
        Err(CutoverPreflightRequestError::ProjectionModeMismatch)
    );
}

#[test]
fn both_runtimes_share_one_nonzero_context() {
    assert_eq!(
        preflight(EngineMode::Tunnel, |_, tunnel| tunnel.context.generation =
            3),
        Err(CutoverPreflightRequestError::InvalidContext)
    );
    assert_eq!(
        preflight(EngineMode::Tunnel, |system_proxy, tunnel| {
            system_proxy.context.config_epoch = 0;
            tunnel.context.config_epoch = 0;
        }),
        Err(CutoverPreflightRequestError::InvalidContext)
    );
    assert_eq!(
        preflight(EngineMode::Tunnel, |system_proxy, tunnel| {
            system_proxy.context.generation = 0;
            tunnel.context.generation = 0;
        }),
        Err(CutoverPreflightRequestError::InvalidContext)
    );
}

#[test]
fn both_runtimes_resolve_the_same_credentials_for_the_same_profile() {
    assert_eq!(
        preflight(EngineMode::Tunnel, |_, tunnel| tunnel.credential_audience =
            audience(&uuid(9))),
        Err(CutoverPreflightRequestError::CredentialAudienceMismatch)
    );
    assert_eq!(
        preflight(EngineMode::Tunnel, |_, tunnel| tunnel
            .credential_slots
            .clear()),
        Err(CutoverPreflightRequestError::CredentialReferenceMismatch)
    );
}

fn attestation() -> CutoverPreflightAttestation {
    CutoverPreflightAttestation {
        attestation_id: ATTESTATION_ID.into(),
        target: EngineMode::Tunnel,
        context: context(),
        system_proxy_config_digest: "01".repeat(32),
        tunnel_config_digest: "02".repeat(32),
        credential_audience: audience(PROFILE_ID),
        credential_references: vec![
            trojan_reference("11111111-1111-4111-8111-111111111111"),
            trojan_reference("22222222-2222-4222-8222-222222222222"),
        ],
        valid_for_millis: 1_000,
    }
}

#[test]
fn an_attestation_is_valid_only_with_canonical_identities_digests_and_lifetime() {
    assert!(attestation().validate());
    let longest = CutoverPreflightAttestation {
        valid_for_millis: CutoverPreflightAttestation::MAXIMUM_VALIDITY_MILLIS,
        ..attestation()
    };
    assert!(longest.validate());
    let broken: [fn(&mut CutoverPreflightAttestation); 12] = [
        |attestation| attestation.attestation_id = ATTESTATION_ID.to_uppercase(),
        |attestation| attestation.context.installation_id = INSTALLATION_ID.to_uppercase(),
        |attestation| attestation.target = EngineMode::Off,
        |attestation| attestation.target = EngineMode::TunnelSystemProxy,
        |attestation| attestation.context.config_epoch = 0,
        |attestation| attestation.context.generation = 0,
        |attestation| attestation.system_proxy_config_digest = "0".repeat(63),
        |attestation| attestation.tunnel_config_digest = "AB".repeat(32),
        |attestation| attestation.valid_for_millis = 0,
        |attestation| {
            attestation.valid_for_millis = CutoverPreflightAttestation::MAXIMUM_VALIDITY_MILLIS + 1;
        },
        |attestation| attestation.credential_references.reverse(),
        |attestation| {
            let first = attestation.credential_references[0].clone();
            attestation.credential_references[1] = first;
        },
    ];
    for (index, change) in broken.into_iter().enumerate() {
        let mut attestation = attestation();
        change(&mut attestation);
        assert!(!attestation.validate(), "change {index} was accepted");
    }
}

#[test]
fn a_preflight_outcome_is_tagged_by_status() {
    let ready = CutoverPreflightOutcome::Ready {
        attestation: attestation(),
    };
    let wire = serde_json::to_value(&ready).expect("outcome");
    assert_eq!(wire["status"], "ready");
    assert_eq!(
        serde_json::from_value::<CutoverPreflightOutcome>(wire).expect("decode"),
        ready
    );
}
