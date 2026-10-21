use super::*;

fn session() -> NativeUserSession {
    NativeUserSession {
        user_sid: "S-1-5-21-123-456-789-1001".into(),
        binary_sid: vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 123, 0, 0, 0, 200, 1, 0, 0, 21, 3, 0, 0, 233, 3,
            0, 0,
        ],
        authentication_id: 0x1234_5678_90ab_cdef,
        session_id: 2,
    }
}

#[test]
fn console_admission_distinguishes_account_logon_and_session() {
    let console = session();
    for role in [ServiceClientRole::Desktop, ServiceClientRole::UserAgent] {
        authorize_identity(
            role,
            &console,
            &console,
            Some(&console),
            UserAgentLeaseRequirement::OwnedLease,
        )
        .unwrap();
        let mut different_account = console.clone();
        different_account.user_sid = "S-1-5-21-321-654-987-1001".into();
        let mut new_logon = console.clone();
        new_logon.authentication_id += 1;
        let mut other_session = console.clone();
        other_session.session_id += 1;
        for peer in [different_account, new_logon, other_session] {
            assert!(matches!(
                authorize_identity(
                    role,
                    &peer,
                    &console,
                    Some(&peer),
                    UserAgentLeaseRequirement::OwnedLease
                ),
                Err(ServiceAuthorizationError::NotConsoleOwner)
            ));
        }
    }
}

#[test]
fn agent_observation_never_authorizes_another_logons_lease() {
    let current = session();
    let mut prior = current.clone();
    prior.authentication_id -= 1;
    assert!(matches!(
        authorize_identity(
            ServiceClientRole::UserAgent,
            &current,
            &current,
            None,
            UserAgentLeaseRequirement::OwnedLease
        ),
        Err(ServiceAuthorizationError::LeaseRequired)
    ));
    authorize_identity(
        ServiceClientRole::UserAgent,
        &current,
        &current,
        None,
        UserAgentLeaseRequirement::OwnedLeaseOrNone,
    )
    .unwrap();
    for requirement in [
        UserAgentLeaseRequirement::OwnedLease,
        UserAgentLeaseRequirement::OwnedLeaseOrNone,
    ] {
        assert!(matches!(
            authorize_identity(
                ServiceClientRole::UserAgent,
                &current,
                &current,
                Some(&prior),
                requirement
            ),
            Err(ServiceAuthorizationError::LeaseOwnerMismatch)
        ));
        authorize_identity(
            ServiceClientRole::UserAgent,
            &current,
            &current,
            Some(&current),
            requirement,
        )
        .unwrap();
    }
    // A current desktop can inspect/reconcile an old owner. This grants no
    // permission to replace that owner's lease or return a fabricated Off.
    authorize_identity(
        ServiceClientRole::Desktop,
        &current,
        &current,
        Some(&prior),
        UserAgentLeaseRequirement::OwnedLease,
    )
    .unwrap();
}

#[test]
fn service_and_unassigned_sessions_cannot_become_console_owners() {
    let current = session();
    let mut invalid = Vec::new();
    for sid in ["S-1-5-18", "S-1-5-19", "S-1-5-20"] {
        let mut value = current.clone();
        value.user_sid = sid.into();
        invalid.push(value);
    }
    for session_id in [0, u32::MAX] {
        let mut value = current.clone();
        value.session_id = session_id;
        invalid.push(value);
    }
    for authentication_id in [0, u64::MAX] {
        let mut value = current.clone();
        value.authentication_id = authentication_id;
        invalid.push(value);
    }
    for value in invalid {
        assert!(matches!(
            authorize_identity(
                ServiceClientRole::Desktop,
                &value,
                &value,
                None,
                UserAgentLeaseRequirement::OwnedLeaseOrNone
            ),
            Err(ServiceAuthorizationError::NotConsoleOwner)
        ));
    }
    let debug = format!("{current:?}");
    assert!(!debug.contains(&current.user_sid));
    assert!(!debug.contains(&current.authentication_id.to_string()));
}

#[test]
fn ordinary_process_cannot_query_a_console_user_token_through_the_service_api() {
    let before = NativePeerProcess::open(std::process::id()).unwrap();
    assert!(!before.identity().is_local_system());
    assert!(matches!(
        LiveConsoleSession::observe(),
        Err(ServiceAuthorizationError::Observer(
            ServicePeerError::InvalidServiceProcessIdentity {
                local_system: false,
                ..
            }
        ))
    ));
    let after = NativePeerProcess::open(std::process::id()).unwrap();
    assert_eq!(before.identity(), after.identity());
}
