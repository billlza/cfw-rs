//! Command contexts, start requests, the cutover request and every native
//! error code, shared by the crate's unit tests.

use cfw_engine_api::{
    BackendErrorKind, CutoverPreflightRequest, DirectIpv4HostRoutes, EngineCommandContext,
    EngineMode, EngineStartMode, EngineStartRequest, TunnelNetworkOptions,
};

use crate::NativeBridgeErrorCode;

pub(crate) fn context() -> EngineCommandContext {
    EngineCommandContext {
        installation_id: "60fb4b30-53da-47ca-a933-e98268ce5703".to_owned(),
        config_epoch: 4,
        generation: 9,
    }
}

pub(crate) fn tunnel_request() -> EngineStartRequest {
    EngineStartRequest {
        mode: cfw_engine_api::EngineStartMode::Tunnel,
        context: context(),
        credential_audience: cfw_engine_api::CredentialAudience::new(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "c".repeat(64),
        )
        .expect("audience"),
        config_json: "{\"inbounds\":[]}".to_owned(),
        config_content_digest: "b".repeat(64),
        config_digest: "a".repeat(64),
        credential_slots: Vec::new(),
        tunnel_options: Some(TunnelNetworkOptions {
            ipv6_enabled: true,
            bypass_private_networks: true,
            direct_ipv4_hosts: DirectIpv4HostRoutes::none(),
            mtu: 1_500,
            system_proxy_port: None,
        }),
    }
}

/// A cutover to the Tunnel whose System Proxy projection is the tunnel
/// request without tunnel options.
pub(crate) fn cutover_request() -> CutoverPreflightRequest {
    let tunnel = tunnel_request();
    let system_proxy = EngineStartRequest {
        mode: EngineStartMode::SystemProxy,
        tunnel_options: None,
        ..tunnel.clone()
    };
    CutoverPreflightRequest::new(EngineMode::Tunnel, system_proxy, tunnel)
        .expect("cutover preflight request")
}

/// Pairs every code with the backend kind of the same name. Each of the two
/// matches stops compiling when its enum gains a variant the list lacks.
macro_rules! code_kind_pairs {
    ($($name:ident),+ $(,)?) => {
        pub(crate) const CODE_KIND_PAIRS: &[(NativeBridgeErrorCode, BackendErrorKind)] =
            &[$((NativeBridgeErrorCode::$name, BackendErrorKind::$name)),+];

        pub(crate) fn listed_code(code: NativeBridgeErrorCode) {
            match code {
                $(NativeBridgeErrorCode::$name)|+ => {}
            }
        }

        pub(crate) fn listed_kind(kind: BackendErrorKind) {
            match kind {
                $(BackendErrorKind::$name)|+ => {}
            }
        }
    };
}

code_kind_pairs![
    Busy,
    ResourceExhausted,
    JournalCapacityExhausted,
    PermissionDenied,
    ApprovalDenied,
    ConfigurationRejected,
    SystemExtensionValidationFailed,
    SystemProxyConfigurationFailed,
    SystemProxyRuntimeFailed,
    EngineStartTimedOut,
    SystemProxyPreferencesFailed,
    SystemProxyJournalFailed,
    SystemProxyAuthorityFailed,
    ExistingSystemProxy,
    CredentialsUnavailable,
    CredentialConflict,
    CredentialVaultMissing,
    CredentialVaultCorrupt,
    CredentialMigrationRequired,
    CredentialGcConflict,
    ProxyAgentApprovalRequired,
    GlobalAuthorityUnavailable,
    GlobalAuthorityRegistrationRequired,
    GlobalAuthorityApprovalRequired,
    GlobalAuthorityIdentityRejected,
    GlobalAuthorityProtocolMismatch,
    GlobalAuthorityRecovering,
    GlobalAuthorityTimeout,
    GlobalAuthorityInterrupted,
    GlobalLeaseConflict,
    ReplayRejected,
    StaleOperation,
    TicketExpired,
    TicketAlreadyRedeemed,
    TicketInvalid,
    CompensationConflict,
    CleanupUnproven,
    Quarantined,
    InvalidMessage,
    SecretBoundsExceeded,
    SecretLifecycleViolation,
    JournalCorrupt,
    OwnerUnresponsive,
    IdentityRejected,
    Timeout,
    Unavailable,
    MixedEndpointInUse,
    ControllerEndpointInUse,
    Internal,
];
