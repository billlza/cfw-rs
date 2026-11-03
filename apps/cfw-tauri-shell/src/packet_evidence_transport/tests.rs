use super::app::{run_app_protocol, wire_snapshot};
use super::control_socket::{SocketIdentity, remove_stale_control_socket_with};
use super::launcher_ticket::launcher_ticket_pending_filename;
use super::proxy::{
    handle_collector_test_submit_error, validate_host_aborted, validate_host_baseline,
    validate_host_completed, validate_host_restored, validate_host_test,
};
use super::*;
use std::io::{Read, Write};
use std::os::fd::IntoRawFd;

use cfw_engine_api::{
    EngineCommandContext, EngineMode, EngineOwner, EngineSnapshot, EngineState, RuntimeIdentity,
};
use tempfile::tempdir;

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).expect("length");
    let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).expect("body");
    body
}

fn write_body(stream: &mut UnixStream, body: &[u8]) {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .expect("length");
    stream.write_all(body).expect("body");
}

fn session(now: u64) -> CollectorHello {
    CollectorHello {
        collector_pid: std::process::id(),
        collector_uid: unsafe { libc::geteuid() },
        document: "cfw-packet-collector-hello-v5".to_owned(),
        expires_at_unix_ms: now + SESSION_LIFETIME_MS,
        issued_at_unix_ms: now,
        schema_version: PROTOCOL_VERSION,
        session_id: "a".repeat(64),
    }
}

fn snapshot_receipt(generation: u64, digest: char) -> PacketEvidenceSnapshotReceipt {
    let config_digest = digest.to_string().repeat(64);
    PacketEvidenceSnapshotReceipt::from_exact(
        &EngineSnapshot {
            desired_mode: EngineMode::Tunnel,
            state: EngineState::TunnelActive {
                runtime: RuntimeIdentity {
                    owner: EngineOwner::PacketTunnelSystemExtension,
                    context: EngineCommandContext {
                        installation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
                        config_epoch: 1,
                        generation,
                    },
                    config_digest: config_digest.clone(),
                    ready: true,
                },
            },
            generation,
            config_digest: Some(config_digest),
        },
        true,
    )
    .expect("exact receipt")
}

fn ticket_store(root: &Path) -> LauncherTicketStore {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("private ticket root");
    LauncherTicketStore::open(root).expect("ticket store")
}

fn app_ticket_request(now: u64, peer: PeerIdentity, session_id: &str) -> AppTicketRequest {
    let collector_pid = unsafe { libc::getppid() };
    let collector = process_bsd_info(collector_pid).expect("live collector parent");
    let binding = LauncherBinding {
        case_id: "dns-a-primary".to_owned(),
        collector_audit_token: "a".repeat(64),
        collector_pid: u32::try_from(collector_pid).expect("collector pid"),
        collector_start_time_unix_us: process_start_time_unix_us(&collector)
            .expect("collector start"),
        collector_uid: collector.pbi_uid,
        expires_at_unix_ms: now + SESSION_LIFETIME_MS,
        issued_at_unix_ms: now,
        proxy_pid: peer.pid,
        proxy_start_time_unix_us: peer.start_time_unix_us,
        proxy_uid: peer.uid,
        session_id: session_id.to_owned(),
    };
    AppTicketRequest {
        binding,
        document: "cfw-packet-app-ticket-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
    }
}

async fn send_ticketed_app_request(
    collector: &mut AsyncPacketEvidenceChannel,
    request: &AppTicketRequest,
) {
    collector.send(request).await.expect("ticket request");
    let issued: HostTicketIssued = collector.receive().await.expect("ticket issued");
    validate_ticket_issued(&issued, &request.binding).expect("exact ticket");
    collector
        .send(&AppRequest {
            binding: request.binding.clone(),
            document: "cfw-packet-app-request-v5".to_owned(),
            schema_version: PROTOCOL_VERSION,
            sequence: REQUEST_SEQUENCE,
            ticket_id: issued.ticket_id,
        })
        .await
        .expect("ticket consumption request");
}

fn async_pair() -> (
    AsyncPacketEvidenceChannel,
    AsyncPacketEvidenceChannel,
    PeerIdentity,
) {
    let (app, collector) = UnixStream::pair().expect("pair");
    let peer = validate_connected_unix_stream(app.as_raw_fd()).expect("peer");
    app.set_nonblocking(true).expect("app nonblocking");
    collector
        .set_nonblocking(true)
        .expect("collector nonblocking");
    (
        AsyncPacketEvidenceChannel::new(tokio::net::UnixStream::from_std(app).expect("async app")),
        AsyncPacketEvidenceChannel::new(
            tokio::net::UnixStream::from_std(collector).expect("async collector"),
        ),
        peer,
    )
}

mod app_protocol;
mod collector_admission;
mod control_endpoint;
mod framing;
mod launcher_tickets;
