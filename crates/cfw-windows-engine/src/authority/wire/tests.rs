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
        prepare().command,
        Command::BindUserAgent(BindRequest {
            context: value.clone(),
            ticket: TicketMaterial::from_slice(&[7; 32]).unwrap(),
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
fn protocol_and_header_are_closed_before_dispatch() {
    let good = Request::new(Command::Observe).unwrap().encode().unwrap();
    let text = std::str::from_utf8(good.as_bytes()).unwrap();
    for altered in [
        text.replace("\"version\":1", "\"version\":2"),
        text.replace(PROTOCOL, "cfm.authority"),
    ] {
        assert!(matches!(
            Request::decode(altered.as_bytes()),
            Err(WireError::Version)
        ));
    }
    for altered in [
        text.replace("\"version\":1", "\"version\":1,\"version\":1"),
        text.replace("\"kind\":\"observe\"", "\"kind\":\"reconcile_off\""),
        text.replace("\"payload\":{}", "\"payload\":{\"ticket\":[1]}"),
        format!("{text}{{}}"),
        text.replace("\"version\":1", "\"unknown\":true,\"version\":1"),
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
