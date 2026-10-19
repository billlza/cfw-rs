use super::*;
use crate::authority_journal::RecordedOwner;
use cfw_engine_api::authority_v1::{AuthorityMode, RootContext};

fn owner() -> RecordedOwner {
    serde_json::from_value(
        serde_json::json!({"sid":[1,1,0,0,0,0,0,5,21,0,0,0],"authentication_id":99,"session_id":2}),
    )
    .unwrap()
}
fn context() -> LeaseContext {
    LeaseContext {
        operation: OperationContext {
            root: RootContext {
                installation_id: Uuid::from_u128(1),
                epoch: 1,
                generation: 1,
            },
            operation_id: Uuid::from_u128(2),
            mode: AuthorityMode::SystemProxy,
            config_sha256: [3; 32],
            identity_sha256: [4; 32],
            owner: owner(),
            prepared_revision: 2,
        },
        lease_id: Uuid::from_u128(5),
    }
}
fn prepare() -> Request {
    let op = context().operation;
    Request::new(Command::Prepare(PrepareRequest {
        root: op.root,
        operation_id: op.operation_id,
        mode: op.mode,
        config_sha256: op.config_sha256,
        identity_sha256: op.identity_sha256,
        expected_revision: 1,
    }))
    .unwrap()
}
fn observed(state: AuthorityState, revision: Option<u64>) -> Response {
    Response::Observed(AuthoritySnapshot {
        state,
        revision,
        root: None,
    })
}
fn grant() -> Response {
    Response::Prepared(PreparedGrant {
        context: context(),
        ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
    })
}

#[test]
fn commands_roundtrip_without_a_generic_secret_value_or_extra_fields() {
    let value = context();
    let stop = StopRequest {
        context: value.clone(),
        expected_revision: 4,
    };
    for command in [
        Command::Observe,
        Command::LoadLineage,
        Command::ReadRuntimeScope,
        Command::ReserveGeneration(crate::authority::AuthorityLineage {
            installation_id: Uuid::from_u128(1),
            config_epoch: 1,
            generation: 0,
        }),
        prepare().command,
        Command::BindUserAgent(BindRequest {
            context: value.clone(),
            ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
        }),
        Command::ConfirmRuntimeKeeper(KeeperRequest {
            context: value.clone(),
            handle: 4,
        }),
        Command::Ready(ReadyReport {
            context: value.clone(),
            runtime_digest: [4; 32],
            ready_flags: 7,
            packet_pump_limits: None,
            observed_millis: 1,
        }),
        Command::Heartbeat(value.clone()),
        Command::BeginStop(stop.clone()),
        Command::AbortPrepared(stop),
        Command::Stopped(StoppedReport {
            context: value,
            engine_stopped: true,
            transport_closed: true,
            os_restored: true,
            observed_millis: 1,
        }),
        Command::OwnedLease,
    ] {
        let request = Request::new(command).unwrap();
        let bytes = request.encode().unwrap();
        let decoded = Request::decode(bytes.as_bytes()).unwrap();
        let again = decoded.encode().unwrap();
        assert_eq!(bytes.as_bytes(), again.as_bytes());
        let mut malformed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        malformed["payload"]["extra"] = serde_json::json!(true);
        assert!(matches!(
            Request::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(WireError::Malformed)
        ));
    }
}

#[test]
fn keeper_confirmation_requires_the_exact_starting_revision_and_root() {
    let request = Request::new(Command::ConfirmRuntimeKeeper(KeeperRequest {
        context: context(),
        handle: 4,
    }))
    .unwrap();
    let expected = AuthoritySnapshot {
        state: AuthorityState::Starting,
        revision: Some(3),
        root: Some(context().operation.root),
    };
    let bytes = Response::Status(expected.clone())
        .encode(request.id)
        .unwrap();
    assert!(matches!(
        response(&request, bytes.as_bytes(), &owner()),
        Ok(Response::Status(_))
    ));
    for changed in [
        AuthoritySnapshot {
            state: AuthorityState::Active,
            ..expected.clone()
        },
        AuthoritySnapshot {
            revision: Some(2),
            ..expected.clone()
        },
        AuthoritySnapshot {
            revision: Some(4),
            ..expected.clone()
        },
        AuthoritySnapshot {
            root: Some(RootContext {
                generation: 2,
                ..context().operation.root
            }),
            ..expected
        },
    ] {
        let bytes = Response::Status(changed).encode(request.id).unwrap();
        assert!(matches!(
            response(&request, bytes.as_bytes(), &owner()),
            Err(WireError::Correlation)
        ));
    }
    for handle in [0, 1, 2, u64::MAX] {
        assert!(matches!(
            Request::new(Command::ConfirmRuntimeKeeper(KeeperRequest {
                context: context(),
                handle,
            })),
            Err(WireError::Malformed)
        ));
    }
}

#[test]
fn protocol_and_header_are_closed_before_dispatch() {
    let good = Request::new(Command::Observe).unwrap().encode().unwrap();
    let text = std::str::from_utf8(good.as_bytes()).unwrap();
    for altered in [
        text.replace("\"version\":3", "\"version\":1"),
        text.replace("\"version\":3", "\"version\":2"),
        text.replace("\"version\":3", "\"version\":4"),
        text.replace(PROTOCOL, "cfm.authority"),
    ] {
        assert!(matches!(
            Request::decode(altered.as_bytes()),
            Err(WireError::Version)
        ));
    }
    for altered in [
        text.replace("\"version\":3", "\"version\":3,\"version\":3"),
        text.replace("\"kind\":\"observe\"", "\"kind\":\"reconcile_off\""),
        text.replace("\"payload\":{}", "\"payload\":{\"ticket\":[1]}"),
        format!("{text}{{}}"),
        text.replace("\"version\":3", "\"unknown\":true,\"version\":3"),
    ] {
        assert!(Request::decode(altered.as_bytes()).is_err());
    }
    assert!(matches!(Request::decode(&[]), Err(WireError::Length)));
    assert!(matches!(
        Request::decode(&vec![b' '; MAX_MESSAGE_BYTES + 1]),
        Err(WireError::Length)
    ));
    assert!(matches!(
        encode(&vec![b'x'; MAX_MESSAGE_BYTES]),
        Err(WireError::Length)
    ));
}

#[test]
fn malformed_ticket_lengths_elements_and_truncations_never_decode() {
    for size in [0, 1, 31, 33, 1024] {
        assert!(decode::<TicketMaterial>(&serde_json::to_vec(&vec![7u8; size]).unwrap()).is_err());
    }
    for invalid in [
        b"null".as_slice(),
        b"\"secret-value\"",
        b"[256]",
        b"[-1]",
        b"[1.5]",
    ] {
        assert!(decode::<TicketMaterial>(invalid).is_err());
    }
    let message = encode(&TicketMaterial::from_slice(&[7; 32]).unwrap()).unwrap();
    for end in 0..message.as_bytes().len() {
        assert!(decode::<TicketMaterial>(&message.as_bytes()[..end]).is_err());
    }
    let decoded: TicketMaterial = decode(message.as_bytes()).unwrap();
    assert!(decoded.with_bytes(|bytes| bytes == [7; 32]));
}

#[test]
fn lease_contexts_reject_a_nil_installation_before_dispatch_or_reply_admission() {
    let mut invalid = context();
    invalid.operation.root.installation_id = Uuid::nil();
    assert!(matches!(
        Request::new(Command::Heartbeat(invalid.clone())),
        Err(WireError::Malformed)
    ));
    let query = Request::new(Command::OwnedLease).unwrap();
    let incoming = envelope(query.id, CommandTag::Heartbeat, &invalid).unwrap();
    assert!(matches!(
        Request::decode(incoming.as_bytes()),
        Err(WireError::Malformed)
    ));
    let message = Response::Lease(invalid).encode(query.id).unwrap();
    assert!(matches!(
        response(&query, message.as_bytes(), &owner()),
        Err(WireError::Malformed)
    ));
}

#[test]
fn a_ticket_reply_is_bound_to_the_exact_request_and_native_owner() {
    let request = prepare();
    let message = grant().encode(request.id).unwrap();
    let Response::Prepared(prepared) = response(&request, message.as_bytes(), &owner()).unwrap()
    else {
        panic!("wrong response")
    };
    assert_eq!(prepared.context(), &context());
    assert!(
        prepared
            .into_bind()
            .ticket
            .with_bytes(|bytes| bytes == [7; 32])
    );
    let other = prepare();
    assert!(matches!(
        response(&other, message.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
    let mut owner_json = serde_json::to_value(owner()).unwrap();
    owner_json["authentication_id"] = serde_json::json!(100);
    let foreign = serde_json::from_value(owner_json).unwrap();
    assert!(matches!(
        response(&request, message.as_bytes(), &foreign),
        Err(WireError::Correlation)
    ));
    for field in [
        "operation_id",
        "config_sha256",
        "identity_sha256",
        "prepared_revision",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(message.as_bytes()).unwrap();
        value["payload"]["context"]["operation"][field] = match field {
            "operation_id" => serde_json::json!(Uuid::from_u128(99)),
            "prepared_revision" => serde_json::json!(3),
            _ => serde_json::to_value([9u8; 32]).unwrap(),
        };
        assert!(matches!(
            response(&request, &serde_json::to_vec(&value).unwrap(), &owner()),
            Err(WireError::Correlation)
        ));
    }
}

#[test]
fn unrelated_success_and_unexpected_revisions_do_not_create_a_runtime_grant() {
    let request = Request::new(Command::BindUserAgent(BindRequest {
        context: context(),
        ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
    }))
    .unwrap();
    let reply = Response::Bound(BoundGrant {
        context: context(),
        committed_revision: 3,
        keeper_handle: 4,
        #[cfg(windows)]
        keeper: None,
    })
    .encode(request.id)
    .unwrap();
    let Response::Bound(bound) = response(&request, reply.as_bytes(), &owner()).unwrap() else {
        panic!("wrong response")
    };
    assert_eq!(bound.context(), &context());
    assert_eq!(bound.committed_revision(), 3);
    for revision in [0, 2, 4, u64::MAX] {
        let reply = Response::Bound(BoundGrant {
            context: context(),
            committed_revision: revision,
            keeper_handle: 4,
            #[cfg(windows)]
            keeper: None,
        })
        .encode(request.id)
        .unwrap();
        assert!(matches!(
            response(&request, reply.as_bytes(), &owner()),
            Err(WireError::Correlation)
        ));
    }
    let unrelated = observed(AuthorityState::Off, Some(1))
        .encode(request.id)
        .unwrap();
    assert!(matches!(
        response(&request, unrelated.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
}

#[test]
fn bound_keeper_receipts_reject_unsafe_values_and_never_adopt_from_the_codec() {
    let request = Request::new(Command::BindUserAgent(BindRequest {
        context: context(),
        ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
    }))
    .unwrap();
    let message = Response::Bound(BoundGrant {
        context: context(),
        committed_revision: 3,
        keeper_handle: 4,
        #[cfg(windows)]
        keeper: None,
    })
    .encode(request.id)
    .unwrap();
    let original: serde_json::Value = serde_json::from_slice(message.as_bytes()).unwrap();
    for value in [
        serde_json::json!(0),
        serde_json::json!(1),
        serde_json::json!(2),
        serde_json::json!(u64::MAX),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::Value::Null,
    ] {
        let mut changed = original.clone();
        changed["payload"]["keeper_handle"] = value;
        assert!(matches!(
            response(&request, &serde_json::to_vec(&changed).unwrap(), &owner()),
            Err(WireError::Malformed)
        ));
    }
    let mut missing = original.clone();
    missing["payload"]
        .as_object_mut()
        .unwrap()
        .remove("keeper_handle");
    assert!(matches!(
        response(&request, &serde_json::to_vec(&missing).unwrap(), &owner()),
        Err(WireError::Malformed)
    ));
    for version in [1, 2, 4] {
        let mut changed = original.clone();
        changed["version"] = serde_json::json!(version);
        assert!(matches!(
            response(&request, &serde_json::to_vec(&changed).unwrap(), &owner()),
            Err(WireError::Version)
        ));
    }
    let duplicate = std::str::from_utf8(message.as_bytes()).unwrap().replace(
        "\"keeper_handle\":4",
        "\"keeper_handle\":4,\"keeper_handle\":8",
    );
    assert!(matches!(
        response(&request, duplicate.as_bytes(), &owner()),
        Err(WireError::Malformed)
    ));
    let parsed = response(&request, message.as_bytes(), &owner()).unwrap();
    #[cfg(windows)]
    {
        let Response::Bound(bound) = parsed else {
            panic!("expected bound metadata")
        };
        assert!(matches!(bound.into_keeper(), Err(WireError::Correlation)));
    }
    #[cfg(not(windows))]
    assert!(matches!(parsed, Response::Bound(_)));
}

#[test]
fn errors_are_closed_codes_and_uncertain_state_is_not_revision_zero_or_off() {
    let request = Request::new(Command::Observe).unwrap();
    let rejected = rejection(request.id, &AuthorityError::Recovering).unwrap();
    assert!(matches!(
        response(&request, rejected.as_bytes(), &owner()),
        Err(WireError::Rejected(Rejection::Recovering))
    ));
    let unknown = std::str::from_utf8(rejected.as_bytes())
        .unwrap()
        .replace("\"recovering\"", "\"unrecognized\"");
    assert!(matches!(
        response(&request, unknown.as_bytes(), &owner()),
        Err(WireError::Malformed)
    ));
    let safe = observed(AuthorityState::Recovering, None)
        .encode(request.id)
        .unwrap();
    assert!(response(&request, safe.as_bytes(), &owner()).is_ok());
    for (state, revision) in [
        (AuthorityState::Off, None),
        (AuthorityState::Recovering, Some(0)),
        (AuthorityState::Active, Some(4)),
        (AuthorityState::Off, Some(6)),
    ] {
        let unsafe_reply = observed(state, revision).encode(request.id).unwrap();
        assert!(response(&request, unsafe_reply.as_bytes(), &owner()).is_err());
    }
}

#[test]
fn status_replies_cannot_fabricate_early_readiness_or_off_for_a_bound_lease() {
    let context = context();
    let heartbeat = Request::new(Command::Heartbeat(context.clone())).unwrap();
    for (state, revision, accepted) in [
        (AuthorityState::Starting, 3, true),
        (AuthorityState::Active, 4, true),
        (AuthorityState::Stopping, 4, true),
        (AuthorityState::Active, 3, false),
        (AuthorityState::Stopping, 3, false),
    ] {
        let reply = Response::Status(AuthoritySnapshot {
            state,
            revision: Some(revision),
            root: Some(context.operation.root.clone()),
        })
        .encode(heartbeat.id)
        .unwrap();
        assert_eq!(
            response(&heartbeat, reply.as_bytes(), &owner()).is_ok(),
            accepted
        );
    }
    for (expected, off_revision, accepted) in [(2, 4, true), (3, 5, false), (4, 6, false)] {
        let stop = Request::new(Command::BeginStop(StopRequest {
            context: context.clone(),
            expected_revision: expected,
        }))
        .unwrap();
        let reply = Response::Status(AuthoritySnapshot {
            state: AuthorityState::Off,
            revision: Some(off_revision),
            root: Some(context.operation.root.clone()),
        })
        .encode(stop.id)
        .unwrap();
        assert_eq!(
            response(&stop, reply.as_bytes(), &owner()).is_ok(),
            accepted
        );
    }
}

#[test]
fn lineage_allocation_reply_cannot_change_identity_skip_or_reuse_a_generation() {
    let expected = crate::authority::AuthorityLineage {
        installation_id: Uuid::from_u128(1),
        config_epoch: 1,
        generation: 7,
    };
    let request = Request::new(Command::ReserveGeneration(expected.clone())).unwrap();
    let mut next = expected.clone();
    next.generation += 1;
    let encoded = Response::Lineage(next.clone()).encode(request.id).unwrap();
    assert!(
        matches!(response(&request, encoded.as_bytes(), &owner()).unwrap(), Response::Lineage(value) if value == next)
    );
    for changed in [
        crate::authority::AuthorityLineage {
            installation_id: Uuid::from_u128(2),
            ..next.clone()
        },
        crate::authority::AuthorityLineage {
            config_epoch: 2,
            ..next.clone()
        },
        crate::authority::AuthorityLineage {
            generation: 7,
            ..next.clone()
        },
        crate::authority::AuthorityLineage {
            generation: 9,
            ..next.clone()
        },
    ] {
        let encoded = Response::Lineage(changed).encode(request.id).unwrap();
        assert!(matches!(
            response(&request, encoded.as_bytes(), &owner()),
            Err(WireError::Correlation)
        ));
    }
    let load = Request::new(Command::LoadLineage).unwrap();
    let unknown = Response::Observed(AuthoritySnapshot {
        state: AuthorityState::Recovering,
        revision: None,
        root: None,
    })
    .encode(load.id)
    .unwrap();
    assert!(matches!(
        response(&load, unknown.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
}

#[test]
fn lineage_values_require_a_real_installation_and_an_explicit_epoch() {
    let request = Request::new(Command::LoadLineage).unwrap();
    for (installation_id, config_epoch) in [(Uuid::nil(), 1), (Uuid::from_u128(1), 0)] {
        let value = crate::authority::AuthorityLineage {
            installation_id,
            config_epoch,
            generation: 0,
        };
        let encoded = Response::Lineage(value.clone()).encode(request.id).unwrap();
        assert!(matches!(
            response(&request, encoded.as_bytes(), &owner()),
            Err(WireError::Malformed)
        ));
        assert!(matches!(
            Request::new(Command::ReserveGeneration(value)),
            Err(WireError::Malformed)
        ));
    }
    let observed = Request::new(Command::Observe).unwrap();
    // Reservations may advance the revision before any runtime has existed.
    let snapshot = AuthoritySnapshot {
        state: AuthorityState::Off,
        revision: Some(3),
        root: Some(RootContext {
            installation_id: Uuid::from_u128(1),
            epoch: 0,
            generation: 0,
        }),
    };
    let encoded = Response::Observed(snapshot.clone())
        .encode(observed.id)
        .unwrap();
    assert!(
        matches!(response(&observed, encoded.as_bytes(), &owner()).unwrap(), Response::Observed(value) if value == snapshot)
    );
    let encoded = Response::Observed(AuthoritySnapshot {
        state: AuthorityState::Active,
        ..snapshot
    })
    .encode(observed.id)
    .unwrap();
    assert!(matches!(
        response(&observed, encoded.as_bytes(), &owner()),
        Err(WireError::Malformed)
    ));
}

fn recorded_scope(state: AuthorityState) -> RecordedRuntimeScope {
    RecordedRuntimeScope {
        snapshot: AuthoritySnapshot {
            state,
            revision: Some(5),
            root: Some(context().operation.root),
        },
        operation: Some(context().recorded().unwrap()),
    }
}

#[test]
fn recorded_scope_keeps_old_logon_metadata_readable_without_reusing_lease_authority() {
    let request = Request::new(Command::ReadRuntimeScope).unwrap();
    let original = recorded_scope(AuthorityState::Recovering);
    let mut value = serde_json::to_value(original.operation.as_ref().unwrap()).unwrap();
    value["owner"]["authentication_id"] = serde_json::json!(100);
    value["owner"]["session_id"] = serde_json::json!(3);
    let old: crate::authority_journal::JournalOperation = serde_json::from_value(value).unwrap();
    let scope = RecordedRuntimeScope {
        operation: Some(old.clone()),
        ..original
    };
    let encoded = Response::RuntimeScope(scope.clone())
        .encode(request.id)
        .unwrap();
    assert!(
        matches!(response(&request, encoded.as_bytes(), &owner()).unwrap(), Response::RuntimeScope(value) if value == scope)
    );
    let mut lease = context();
    lease.operation.owner = old.owner().clone();
    let owned_request = Request::new(Command::OwnedLease).unwrap();
    let encoded = Response::Lease(lease).encode(owned_request.id).unwrap();
    assert!(matches!(
        response(&owned_request, encoded.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
    let mut foreign = serde_json::to_value(&old).unwrap();
    foreign["owner"]["sid"][8] = serde_json::json!(22);
    let foreign = RecordedRuntimeScope {
        operation: Some(serde_json::from_value(foreign).unwrap()),
        ..scope
    };
    let encoded = Response::RuntimeScope(foreign).encode(request.id).unwrap();
    assert!(matches!(
        response(&request, encoded.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
}

#[test]
fn recorded_scope_requires_explicit_complete_state_and_operation_fields() {
    let request = Request::new(Command::ReadRuntimeScope).unwrap();
    let valid = Response::RuntimeScope(recorded_scope(AuthorityState::Active))
        .encode(request.id)
        .unwrap();
    assert!(matches!(
        response(&request, valid.as_bytes(), &owner()).unwrap(),
        Response::RuntimeScope(_)
    ));
    let original: serde_json::Value = serde_json::from_slice(valid.as_bytes()).unwrap();
    for field in ["identity_sha256", "operation_id", "lease_id", "owner"] {
        let mut malformed = original.clone();
        malformed["payload"]["operation"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(response(&request, &serde_json::to_vec(&malformed).unwrap(), &owner()).is_err());
    }
    let mut missing = original.clone();
    missing["payload"]
        .as_object_mut()
        .unwrap()
        .remove("operation");
    assert!(response(&request, &serde_json::to_vec(&missing).unwrap(), &owner()).is_err());
    for malformed in [
        RecordedRuntimeScope {
            operation: None,
            ..recorded_scope(AuthorityState::Active)
        },
        recorded_scope(AuthorityState::Off),
        RecordedRuntimeScope {
            snapshot: AuthoritySnapshot {
                state: AuthorityState::Recovering,
                revision: None,
                root: None,
            },
            operation: None,
        },
    ] {
        let encoded = Response::RuntimeScope(malformed)
            .encode(request.id)
            .unwrap();
        assert!(matches!(
            response(&request, encoded.as_bytes(), &owner()),
            Err(WireError::Malformed)
        ));
    }
    let empty = RecordedRuntimeScope {
        operation: None,
        ..recorded_scope(AuthorityState::Off)
    };
    let encoded = Response::RuntimeScope(empty.clone())
        .encode(request.id)
        .unwrap();
    assert!(
        matches!(response(&request, encoded.as_bytes(), &owner()).unwrap(), Response::RuntimeScope(value) if value == empty)
    );
    let mut missing = serde_json::to_value(&empty).unwrap();
    missing.as_object_mut().unwrap().remove("operation");
    let encoded = envelope(request.id, ResponseTag::RuntimeScope, &missing).unwrap();
    assert!(response(&request, encoded.as_bytes(), &owner()).is_err());
}

#[test]
fn unknown_publication_is_an_error_and_recorded_scope_cannot_answer_an_owned_lease_request() {
    let request = Request::new(Command::ReadRuntimeScope).unwrap();
    let rejected = rejection(request.id, &AuthorityError::Recovering).unwrap();
    assert!(matches!(
        response(&request, rejected.as_bytes(), &owner()),
        Err(WireError::Rejected(Rejection::Recovering))
    ));
    let lease_request = Request::new(Command::OwnedLease).unwrap();
    let recorded = Response::RuntimeScope(recorded_scope(AuthorityState::Active))
        .encode(lease_request.id)
        .unwrap();
    assert!(matches!(
        response(&lease_request, recorded.as_bytes(), &owner()),
        Err(WireError::Correlation)
    ));
}
