use super::*;
use crate::{
    PreparedConfig,
    authority::{
        LeaseContext, OperationContext,
        wire::{BindRequest, TicketMaterial},
    },
    authority_journal::RecordedOwner,
};
use cfw_engine_api::authority_v1::{AuthorityMode, RootContext};
use cfw_singbox_config::{EngineSettings, ProjectionMode, ValidatedSingBoxProfile};
use uuid::Uuid;

fn owner() -> RecordedOwner {
    serde_json::from_value(
        serde_json::json!({"sid":[1,1,0,0,0,0,0,5,21,0,0,0],"authentication_id":99,"session_id":2}),
    )
    .unwrap()
}
fn bytes(hex: &str) -> [u8; 32] {
    std::array::from_fn(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
}
pub(super) fn inputs(mode: ProjectionMode) -> (BindRequest, PreparedConfig) {
    let projection =
        ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
            .unwrap()
            .project(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                mode,
                &EngineSettings::default(),
            )
            .unwrap();
    let config = match mode {
        ProjectionMode::LocalProxy => PreparedConfig::local_proxy(&projection, []).unwrap(),
        ProjectionMode::SystemProxy => {
            PreparedConfig::system_proxy_data_plane(&projection, []).unwrap()
        }
        _ => panic!("test proxy mode required"),
    };
    assert_eq!(
        config.configuration_digest(),
        projection.configuration_digest()
    );
    assert_eq!(config.digest(), projection.digest());
    assert_ne!(config.digest(), config.configuration_digest());
    let context = LeaseContext {
        operation: OperationContext {
            root: RootContext {
                installation_id: Uuid::from_u128(1),
                epoch: 1,
                generation: 1,
            },
            operation_id: Uuid::from_u128(2),
            mode: if mode == ProjectionMode::LocalProxy {
                AuthorityMode::LocalProxy
            } else {
                AuthorityMode::SystemProxy
            },
            config_sha256: bytes(config.configuration_digest()),
            identity_sha256: bytes(config.digest()),
            owner: owner(),
            prepared_revision: 2,
        },
        lease_id: Uuid::from_u128(3),
    };
    (
        BindRequest {
            context,
            ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
        },
        config,
    )
}
#[test]
fn runtime_plan_binds_both_configuration_and_product_identity_digests() {
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        let (binding, config) = inputs(mode);
        let context = binding.context.clone();
        let plan = UserAgentPlan::new(binding, config).unwrap();
        assert_eq!(plan.context(), &context);
        assert_eq!(plan.mode(), mode);
        for change in 0..3 {
            let (mut binding, config) = inputs(mode);
            match change {
                0 => binding.context.operation.config_sha256[0] ^= 1,
                1 => binding.context.operation.identity_sha256[0] ^= 1,
                _ => std::mem::swap(
                    &mut binding.context.operation.config_sha256,
                    &mut binding.context.operation.identity_sha256,
                ),
            };
            assert!(matches!(
                UserAgentPlan::new(binding, config),
                Err(UserAgentError::ConfigurationMismatch)
            ));
        }
    }
}
#[test]
fn runtime_plan_never_promotes_local_or_system_proxy_to_tunnel_ownership() {
    for mode in [ProjectionMode::LocalProxy, ProjectionMode::SystemProxy] {
        let (mut binding, config) = inputs(mode);
        binding.context.operation.mode = AuthorityMode::Tunnel;
        assert!(matches!(
            UserAgentPlan::new(binding, config),
            Err(UserAgentError::Mode)
        ));
    }
    let (mut binding, config) = inputs(ProjectionMode::LocalProxy);
    binding.context.operation.mode = AuthorityMode::SystemProxy;
    assert!(matches!(
        UserAgentPlan::new(binding, config),
        Err(UserAgentError::Mode)
    ));
    let (mut binding, config) = inputs(ProjectionMode::LocalProxy);
    binding.context.operation.root.installation_id = Uuid::nil();
    assert!(matches!(
        UserAgentPlan::new(binding, config),
        Err(UserAgentError::Wire(_))
    ));
}

#[cfg(windows)]
#[test]
fn shared_request_context_cannot_substitute_another_nonzero_generation_or_installation() {
    for change in 0..4 {
        let (binding, _) = inputs(ProjectionMode::LocalProxy);
        let projection =
            ValidatedSingBoxProfile::parse(r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#)
                .unwrap()
                .project(
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    ProjectionMode::LocalProxy,
                    &EngineSettings::default(),
                )
                .unwrap();
        let root = &binding.context.operation.root;
        let mut request = cfw_engine_api::EngineStartRequest {
            context: cfw_engine_api::EngineCommandContext {
                installation_id: root.installation_id.to_string(),
                config_epoch: root.epoch,
                generation: root.generation,
            },
            mode: ProjectionMode::LocalProxy,
            credential_audience: projection.credential_audience().clone(),
            config_json: projection.as_json().into(),
            config_content_digest: projection.configuration_digest().into(),
            config_digest: projection.digest().into(),
            credential_slots: projection.credential_slots().to_vec(),
            tunnel_options: None,
        };
        match change {
            0 => {}
            1 => request.context.config_epoch += 1,
            2 => request.context.generation += 1,
            3 => request.context.installation_id = Uuid::from_u128(90).to_string(),
            _ => unreachable!(),
        }
        // No native I/O is permitted while validating this plan. The path is
        // intentionally not provisioned or opened by these request-only tests.
        let vault = cfw_windows_credentials::WindowsCredentialStore::new(std::path::PathBuf::from(
            r"Z:\cfw-plan-validation-not-opened\vault",
        ));
        let result = UserAgentPlan::from_start_request(binding, request, vault);
        if change == 0 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(UserAgentError::ConfigurationMismatch)));
        }
    }
}
