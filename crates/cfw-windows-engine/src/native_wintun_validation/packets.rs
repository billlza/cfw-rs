//! Actual Windows UDP -> Wintun receive -> Wintun send -> Windows UDP.
//! The endpoint is generated inside this process; no external server or mock
//! engine can satisfy this driver-boundary observation.
use super::{
    Result,
    library::{self, Library},
    record,
};
use crate::tunnel::Session;
use serde_json::{Value, json};
use std::{
    net::{SocketAddrV4, UdpSocket},
    path::Path,
    time::{Duration, Instant},
};
mod codec;
mod network;

pub(super) fn run(dll: &Path, output: &Path, source: &str) -> Result<()> {
    if !dll.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("invalid Wintun packet validation paths".into());
    }
    std::fs::create_dir(output).map_err(|error| error.to_string())?;
    let peer =
        crate::NativePeerProcess::open(std::process::id()).map_err(|error| error.to_string())?;
    record(
        output,
        "initial.json",
        &json!({"source":source,"process_id":peer.process_id(),
        "process_creation_time":peer.identity().process_creation_time(),
        "integrity_rid":peer.identity().integrity_rid(),"local_system":peer.identity().is_local_system(),
        "dll_sha256":crate::runtime_host::wintun_image_pin().map_err(|error| error.to_string())?.sha256,
        "release_accepted":false}),
    )?;
    let mut cases = Vec::new();
    let result = (|| {
        let library = Library::load_for_validation(dll).map_err(|error| error.to_string())?;
        let operation = (|| {
            for mtu in [1280, 1500, 9000] {
                cases.push(roundtrip(&library, mtu, output, source)?);
            }
            Ok(())
        })();
        combine(
            operation,
            library.close().map_err(|error| error.to_string()),
        )
    })();
    let saved = record(
        output,
        "result.json",
        &json!({"source":source,"success":result.is_ok(),
        "failure":result.as_ref().err(),"cases":cases,"packet_traffic_verified":result.is_ok(),
        "ip_families":["ipv4"],"owned_host_route":"192.0.2.123/32","owned_address":"192.0.2.10/32",
        "default_routes_modified":false,"dns_modified":false,"firewall_modified":false,
        "engine_forwarding_verified":false,"product_tunnel_backend_exercised":false,"release_accepted":false}),
    );
    combine(result, saved)
}

fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}

fn roundtrip(library: &Library, mtu: u16, output: &Path, source: &str) -> Result<Value> {
    let id = uuid::Uuid::new_v4();
    let adapter = library.create(id).map_err(|error| error.to_string())?;
    let luid = adapter.luid();
    let name = adapter.name().to_owned();
    record(
        output,
        &format!("mtu-{mtu}-created.json"),
        &json!({"source":source,"mtu":mtu,
        "interface_guid":id,"luid":luid,"name":name,"adapter_created":true}),
    )?;
    let operation = (|| {
        let session = adapter.session(mtu).map_err(|error| error.to_string())?;
        let mut network = network::OwnedNetwork::configure(&adapter, id, mtu)?;
        let original_mtu = network.original_mtu();
        let traffic = exchange(&session, output, source, mtu, id, luid, &name);
        let restored = network.restore();
        let mut receipt = combine(traffic, restored)?;
        receipt["original_mtu"] = json!(original_mtu);
        receipt["owned_route_address_mtu_restored"] = json!(true);
        Ok(receipt)
    })();
    drop(adapter);
    let absent = library::wait_absent(luid, &name).map_err(|error| error.to_string());
    let mut receipt = combine(operation, absent)?;
    network::require_unused_addresses_and_route()?;
    receipt["adapter_absence_observed"] = json!(true);
    receipt["fixture_addresses_and_host_route_absent"] = json!(true);
    record(output, &format!("mtu-{mtu}-complete.json"), &receipt)?;
    Ok(receipt)
}

fn exchange(
    session: &Session<'_>,
    output: &Path,
    source: &str,
    mtu: u16,
    id: uuid::Uuid,
    luid: u64,
    name: &str,
) -> Result<Value> {
    if session.mtu() != mtu {
        return Err("packet session MTU differs".into());
    }
    let socket =
        UdpSocket::bind(SocketAddrV4::new(network::LOCAL, 0)).map_err(|error| error.to_string())?;
    socket
        .connect(SocketAddrV4::new(network::REMOTE, 54321))
        .map_err(|error| error.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let local = socket.local_addr().map_err(|error| error.to_string())?;
    let seed = format!("cfw-wintun-{id}-{mtu}");
    let payload: Vec<_> = seed.bytes().cycle().take(usize::from(mtu) - 28).collect();
    let mut expected = payload.clone();
    expected[0] ^= 0xff;
    let deadline = Instant::now() + Duration::from_secs(10);
    if socket.send(&payload).map_err(|error| error.to_string())? != payload.len() {
        return Err("Windows UDP send did not accept the complete request".into());
    }
    let mut buffer = vec![0u8; usize::from(mtu)];
    let mut other_packets = 0;
    let (request, response) = loop {
        if Instant::now() >= deadline || other_packets >= 64 {
            return Err("Windows UDP request did not reach the bounded Wintun receive ring".into());
        }
        let Some(length) = session
            .receive(&mut buffer)
            .map_err(|error| error.to_string())?
        else {
            session
                .wait_readable(Duration::from_millis(100))
                .map_err(|error| error.to_string())?;
            continue;
        };
        let request = &buffer[..length];
        let reply = codec::reply(
            request,
            network::LOCAL.octets(),
            network::REMOTE.octets(),
            local.port(),
            54321,
            &payload,
        );
        match reply {
            Ok(Some(response)) => break (request.to_vec(), response),
            Ok(None) => other_packets += 1,
            Err(error) => {
                std::fs::write(output.join(format!("mtu-{mtu}-rejected.bin")), request)
                    .map_err(|error| error.to_string())?;
                return Err(error);
            }
        }
    };
    if request.len() != usize::from(mtu) || response.len() != usize::from(mtu) {
        return Err("native roundtrip did not exercise the full selected MTU".into());
    }
    std::fs::write(output.join(format!("mtu-{mtu}-request.bin")), &request)
        .map_err(|error| error.to_string())?;
    std::fs::write(output.join(format!("mtu-{mtu}-response.bin")), &response)
        .map_err(|error| error.to_string())?;
    session.send(&response).map_err(|error| error.to_string())?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or("packet roundtrip exceeded its deadline")?;
    socket
        .set_read_timeout(Some(remaining))
        .map_err(|error| error.to_string())?;
    let received = socket
        .recv(&mut buffer)
        .map_err(|error| error.to_string())?;
    if buffer[..received] != expected {
        return Err("Windows UDP did not receive the exact injected response".into());
    }
    Ok(
        json!({"source":source,"mtu":mtu,"interface_guid":id,"luid":luid,"name":name,
        "local_address":local.to_string(),"remote_address":"192.0.2.123:54321",
        "request_packet_bytes":request.len(),"response_packet_bytes":response.len(),
        "payload_bytes":payload.len(),"received_payload_bytes":received,"other_packets":other_packets,
        "request_sha256":cfw_singbox_config::sha256_hex(&request),"response_sha256":cfw_singbox_config::sha256_hex(&response),
        "windows_udp_to_wintun_verified":true,"wintun_to_windows_udp_verified":true,
        "request_response_payloads_differ":true,"release_accepted":false}),
    )
}
