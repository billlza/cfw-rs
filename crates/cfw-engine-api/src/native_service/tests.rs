use super::*;

#[test]
fn orphaned_retirement_receipt_is_not_an_off_proof() {
    let mut result = NativeServiceMaintenanceResult {
        action: NativeServiceMaintenanceAction::RetireOrphanedServices,
        engine_status: None,
        global_authority: NativeServiceRegistrationStatus::NotRegistered,
        off_proof_profile: None,
        proxy_agent: NativeServiceRegistrationStatus::NotRegistered,
    };
    assert!(result.validate());
    result.engine_status = Some(NativeServiceEngineStatus::Off);
    assert!(!result.validate());
    result.engine_status = None;
    result.off_proof_profile = Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1);
    assert!(!result.validate());
    result.off_proof_profile = None;
    result.proxy_agent = NativeServiceRegistrationStatus::Enabled;
    assert!(!result.validate());
    result.proxy_agent = NativeServiceRegistrationStatus::NotRegistered;
    result.global_authority = NativeServiceRegistrationStatus::Enabled;
    assert!(!result.validate());
}

#[test]
fn native_service_maintenance_result_contract_is_closed() {
    use NativeServiceMaintenanceAction as Action;
    use NativeServiceRegistrationStatus as Status;

    let valid = [
        NativeServiceMaintenanceResult {
            action: Action::Status,
            engine_status: None,
            global_authority: Status::Unknown,
            off_proof_profile: None,
            proxy_agent: Status::NotFound,
        },
        NativeServiceMaintenanceResult {
            action: Action::ProveOff,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::Enabled,
            off_proof_profile: Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1),
            proxy_agent: Status::Enabled,
        },
        NativeServiceMaintenanceResult {
            action: Action::ProveInstalled40019Off,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::Enabled,
            off_proof_profile: Some(
                NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0,
            ),
            proxy_agent: Status::Enabled,
        },
        NativeServiceMaintenanceResult {
            action: Action::UnregisterProxyAgent,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::Enabled,
            off_proof_profile: Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1),
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::UnregisterInstalled40019ProxyAgent,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::Enabled,
            off_proof_profile: Some(
                NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0,
            ),
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::UnregisterGlobalAuthority,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::NotRegistered,
            off_proof_profile: Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1),
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::UnregisterInstalled40019GlobalAuthority,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::NotRegistered,
            off_proof_profile: Some(
                NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0,
            ),
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::RecoverInstalled40019GlobalAuthority,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::NotRegistered,
            off_proof_profile: Some(
                NativeServiceOffProofProfile::Installed40019RecoveryCurrentAuthorityV1_1,
            ),
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::RegisterGlobalAuthority,
            engine_status: None,
            global_authority: Status::Enabled,
            off_proof_profile: None,
            proxy_agent: Status::NotRegistered,
        },
        NativeServiceMaintenanceResult {
            action: Action::RegisterProxyAgent,
            engine_status: Some(NativeServiceEngineStatus::Off),
            global_authority: Status::Enabled,
            off_proof_profile: Some(NativeServiceOffProofProfile::CurrentEngineV6AuthorityV1_1),
            proxy_agent: Status::Enabled,
        },
    ];
    assert!(valid.iter().all(NativeServiceMaintenanceResult::validate));

    for (action, off_proof_profile) in [
        (
            Action::UnregisterInstalled40019GlobalAuthority,
            NativeServiceOffProofProfile::Installed40019RecoveryCurrentAuthorityV1_1,
        ),
        (
            Action::RecoverInstalled40019GlobalAuthority,
            NativeServiceOffProofProfile::Installed40019EngineV5AuthorityV1_0,
        ),
    ] {
        assert!(
            !NativeServiceMaintenanceResult {
                action,
                engine_status: Some(NativeServiceEngineStatus::Off),
                global_authority: Status::NotRegistered,
                off_proof_profile: Some(off_proof_profile),
                proxy_agent: Status::NotRegistered,
            }
            .validate()
        );
    }

    for mut result in valid {
        result.engine_status = match result.engine_status {
            Some(_) => None,
            None => Some(NativeServiceEngineStatus::Off),
        };
        assert!(!result.validate());
    }
}
