//! The combined run on the wire: named like the other modes, with one
//! command of its own.
use super::*;

fn combined_context() -> LeaseContext {
    let mut value = context();
    value.operation.mode = RunMode::TunnelSystemProxy;
    value
}

#[test]
fn only_a_combined_lease_has_its_adapter_routed_before_ready() {
    let request = Request::new(Command::RouteTunnel(combined_context())).unwrap();
    let bytes = request.encode().unwrap();
    let decoded = Request::decode(bytes.as_bytes()).unwrap();
    assert_eq!(bytes.as_bytes(), decoded.encode().unwrap().as_bytes());
    assert!(matches!(
        decoded.command(),
        Command::RouteTunnel(context) if *context == combined_context()
    ));
    let mut padded: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    padded["payload"]["extra"] = serde_json::json!(true);
    assert!(matches!(
        Request::decode(&serde_json::to_vec(&padded).unwrap()),
        Err(WireError::Malformed)
    ));
    // A proxy lease owns no adapter, and a Tunnel lease is routed when its
    // Ready is accepted: neither asks, even in a request encoded by hand.
    for mode in [RunMode::LocalProxy, RunMode::SystemProxy, RunMode::Tunnel] {
        let mut other = combined_context();
        other.operation.mode = mode;
        assert!(
            matches!(
                Request::new(Command::RouteTunnel(other)),
                Err(WireError::Malformed)
            ),
            "{mode:?}"
        );
        let mut forged: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(
            forged["payload"]["operation"]["mode"],
            serde_json::json!("tunnel_system_proxy")
        );
        forged["payload"]["operation"]["mode"] = serde_json::to_value(mode).unwrap();
        assert!(
            matches!(
                Request::decode(&serde_json::to_vec(&forged).unwrap()),
                Err(WireError::Malformed)
            ),
            "{mode:?}"
        );
    }
}

#[test]
fn the_route_reply_is_the_starting_status_of_that_lease_and_owner() {
    let request = Request::new(Command::RouteTunnel(combined_context())).unwrap();
    let expected = AuthoritySnapshot {
        state: AuthorityState::Starting,
        revision: Some(3),
        root: Some(combined_context().operation.root),
    };
    let bytes = Response::Status(expected.clone())
        .encode(request.id)
        .unwrap();
    assert!(matches!(
        response(&request, bytes.as_bytes(), &owner()),
        Ok(Response::Status(value)) if value == expected
    ));
    for changed in [
        // Routes never make a run Active: only its accepted Ready does.
        AuthoritySnapshot {
            state: AuthorityState::Active,
            revision: Some(4),
            ..expected.clone()
        },
        AuthoritySnapshot {
            state: AuthorityState::Stopping,
            ..expected.clone()
        },
        AuthoritySnapshot {
            revision: Some(4),
            ..expected.clone()
        },
        AuthoritySnapshot {
            root: Some(RootContext {
                generation: 2,
                ..combined_context().operation.root
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
    for reply in [
        Response::TunnelPending.encode(request.id).unwrap(),
        Response::TunnelOffered(offer(1500))
            .encode(request.id)
            .unwrap(),
    ] {
        assert!(matches!(
            response(&request, reply.as_bytes(), &owner()),
            Err(WireError::Correlation)
        ));
    }
}

#[test]
fn a_combined_lease_opens_and_confirms_its_tunnel_as_a_tunnel_lease_does() {
    let mut open = tunnel_open(1500);
    open.context = combined_context();
    for command in [
        Command::OpenTunnel(open),
        Command::ConfirmTunnelEndpoint(KeeperRequest {
            context: combined_context(),
            handle: 4,
        }),
    ] {
        let request = Request::new(command).unwrap();
        let bytes = request.encode().unwrap();
        let decoded = Request::decode(bytes.as_bytes()).unwrap();
        assert_eq!(bytes.as_bytes(), decoded.encode().unwrap().as_bytes());
    }
}
