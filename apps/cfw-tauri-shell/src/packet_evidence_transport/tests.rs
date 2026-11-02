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

#[tokio::test]
async fn app_protocol_happy_path_returns_only_the_closed_receipt() {
    let now = now_unix_ms().expect("time");
    let session_id = "c".repeat(64);
    let (app, mut collector, peer) = async_pair();
    let request = app_ticket_request(now, peer, &session_id);
    let ticket_root = tempdir().expect("ticket root");
    let ticket_store = ticket_store(ticket_root.path());
    let mut replay = SessionReplayGuard::default();
    let app_side = run_app_protocol(
        app,
        peer,
        &mut replay,
        &ticket_store,
        u32::MAX,
        |case, stages| async move {
            let PacketEvidenceStages {
                begin_capture,
                exercise_test,
                finish_capture,
            } = stages;
            let baseline = snapshot_receipt(7, 'a');
            let test = snapshot_receipt(8, 'b');
            begin_capture(PacketEvidenceBaselineReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
            })
            .await?;
            exercise_test(PacketEvidenceTestReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
                test: test.clone(),
                test_observation_sequence: 11,
            })
            .await?;
            let restore = snapshot_receipt(9, 'a');
            finish_capture(PacketEvidenceCaptureTerminal::Restored(
                PacketEvidenceCaptureFinalizing {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                    test: Some(test.clone()),
                    test_observation_sequence: Some(11),
                    restore: restore.clone(),
                    restore_observation_sequence: 12,
                },
            ))
            .await?;
            Ok(PacketEvidenceTransactionOutcome {
                baseline,
                baseline_observation_sequence: 10,
                test,
                test_observation_sequence: 11,
                restore,
                restore_observation_sequence: 12,
                candidate_observation_sequence: 11,
            })
        },
    );
    let collector_side = async {
        send_ticketed_app_request(&mut collector, &request).await;
        let baseline: HostBaselineObserved =
            tokio::time::timeout(Duration::from_secs(2), collector.receive())
                .await
                .expect("baseline timeout")
                .expect("baseline");
        validate_host_baseline(&baseline, &session_id, "dns-a-primary").expect("exact baseline");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-started-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_STARTED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("capture started");
        let test: HostTestObserved = collector.receive().await.expect("test");
        validate_host_test(&test, &baseline, &session_id, "dns-a-primary").expect("exact test");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-test-submitted-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: TEST_SUBMITTED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("test submitted");
        let restored: HostBaselineRestored = collector.receive().await.expect("restore");
        validate_host_restored(
            &restored,
            &baseline,
            Some(&test),
            &session_id,
            "dns-a-primary",
        )
        .expect("exact restore");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_COMPLETED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("capture complete");
        let completed: HostFinalResponse =
            tokio::time::timeout(Duration::from_secs(2), collector.receive())
                .await
                .expect("completed timeout")
                .expect("completed");
        let HostFinalResponse::Completed(completed) = completed else {
            panic!("transaction unexpectedly failed");
        };
        validate_host_completed(
            &completed,
            &baseline,
            &test,
            &restored,
            &session_id,
            "dns-a-primary",
        )
        .expect("exact completion");
        assert_eq!(completed.candidate_observation_sequence, 11);
    };
    let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(app_side, collector_side)
    })
    .await
    .expect("complete protocol timeout");
    app_result.expect("app protocol");
}

#[tokio::test]
async fn duplicate_request_in_capture_slot_is_typed_and_cannot_skip_restore() {
    let now = now_unix_ms().expect("time");
    let session_id = "d".repeat(64);
    let (app, mut collector, peer) = async_pair();
    let request = app_ticket_request(now, peer, &session_id);
    let duplicate = CollectorRequest {
        case_id: request.binding.case_id.clone(),
        document: "cfw-packet-collector-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: REQUEST_SEQUENCE,
        session_id: session_id.clone(),
    };
    let ticket_root = tempdir().expect("ticket root");
    let ticket_store = ticket_store(ticket_root.path());
    let mut replay = SessionReplayGuard::default();
    let app_side = run_app_protocol(
        app,
        peer,
        &mut replay,
        &ticket_store,
        u32::MAX,
        |case, stages| async move {
            let PacketEvidenceStages {
                begin_capture,
                finish_capture,
                ..
            } = stages;
            let baseline = snapshot_receipt(7, 'a');
            let failure = begin_capture(PacketEvidenceBaselineReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
            })
            .await
            .expect_err("duplicate frame was not rejected");
            assert_eq!(failure, PacketEvidenceCaptureFailure::ControlChannelFailed);
            finish_capture(PacketEvidenceCaptureTerminal::Restored(
                PacketEvidenceCaptureFinalizing {
                    case,
                    baseline: baseline.clone(),
                    baseline_observation_sequence: 10,
                    test: None,
                    test_observation_sequence: None,
                    restore: baseline,
                    restore_observation_sequence: 11,
                },
            ))
            .await?;
            Err(PacketEvidenceTransactionError::Capture(failure))
        },
    );
    let collector_side = async {
        send_ticketed_app_request(&mut collector, &request).await;
        let baseline: HostBaselineObserved =
            tokio::time::timeout(Duration::from_secs(2), collector.receive())
                .await
                .expect("baseline timeout")
                .expect("baseline");
        collector.send(&duplicate).await.expect("duplicate");
        let restored: HostBaselineRestored = collector.receive().await.expect("restore");
        validate_host_restored(&restored, &baseline, None, &session_id, "dns-a-primary")
            .expect("exact ambiguous-begin restore");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_COMPLETED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("terminal cleanup");
        let failed: HostFinalResponse =
            tokio::time::timeout(Duration::from_secs(2), collector.receive())
                .await
                .expect("failure timeout")
                .expect("failed");
        let HostFinalResponse::Failed(failed) = failed else {
            panic!("duplicate frame unexpectedly succeeded");
        };
        assert_eq!(failed.code, "capture_control_failed");
    };
    let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(app_side, collector_side)
    })
    .await
    .expect("duplicate protocol timeout");
    app_result.expect("typed final failure");
}

#[tokio::test]
async fn semantic_test_stage_failure_restores_and_reaches_terminal_cleanup() {
    let now = now_unix_ms().expect("time");
    let session_id = "f".repeat(64);
    let (app, mut collector, peer) = async_pair();
    let request = app_ticket_request(now, peer, &session_id);
    let ticket_root = tempdir().expect("ticket root");
    let ticket_store = ticket_store(ticket_root.path());
    let mut replay = SessionReplayGuard::default();
    let app_side = run_app_protocol(
        app,
        peer,
        &mut replay,
        &ticket_store,
        u32::MAX,
        |case, stages| async move {
            let PacketEvidenceStages {
                begin_capture,
                exercise_test,
                finish_capture,
            } = stages;
            let baseline = snapshot_receipt(7, 'a');
            let test = snapshot_receipt(8, 'b');
            begin_capture(PacketEvidenceBaselineReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
            })
            .await?;
            let failure = exercise_test(PacketEvidenceTestReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
                test: test.clone(),
                test_observation_sequence: 11,
            })
            .await
            .expect_err("semantically invalid stage response");
            assert_eq!(failure, PacketEvidenceCaptureFailure::ControlChannelFailed);
            let restore = snapshot_receipt(9, 'a');
            finish_capture(PacketEvidenceCaptureTerminal::Restored(
                PacketEvidenceCaptureFinalizing {
                    case,
                    baseline,
                    baseline_observation_sequence: 10,
                    test: Some(test),
                    test_observation_sequence: Some(11),
                    restore,
                    restore_observation_sequence: 12,
                },
            ))
            .await?;
            Err(PacketEvidenceTransactionError::Capture(failure))
        },
    );
    let collector_side = async {
        send_ticketed_app_request(&mut collector, &request).await;
        let _baseline: HostBaselineObserved = collector.receive().await.expect("baseline");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-started-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_STARTED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("capture started");
        let _test: HostTestObserved = collector.receive().await.expect("test");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-started-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: TEST_SUBMITTED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("semantic test-stage failure");
        let _restored: HostBaselineRestored = collector.receive().await.expect("restored baseline");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_COMPLETED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("terminal cleanup");
        let final_response: HostFinalResponse = collector.receive().await.expect("final");
        let HostFinalResponse::Failed(failed) = final_response else {
            panic!("invalid test-stage response unexpectedly succeeded");
        };
        assert_eq!(failed.code, "capture_control_failed");
    };
    let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(app_side, collector_side)
    })
    .await
    .expect("semantic failure protocol hard timeout");
    app_result.expect("typed semantic failure");
}

#[tokio::test]
async fn aborted_engine_path_requires_collector_terminal_cleanup_before_failure() {
    let now = now_unix_ms().expect("time");
    let session_id = "e".repeat(64);
    let (app, mut collector, peer) = async_pair();
    let request = app_ticket_request(now, peer, &session_id);
    let ticket_root = tempdir().expect("ticket root");
    let ticket_store = ticket_store(ticket_root.path());
    let mut replay = SessionReplayGuard::default();
    let app_side = run_app_protocol(
        app,
        peer,
        &mut replay,
        &ticket_store,
        u32::MAX,
        |case, stages| async move {
            let PacketEvidenceStages {
                begin_capture,
                finish_capture,
                ..
            } = stages;
            let baseline = snapshot_receipt(7, 'a');
            begin_capture(PacketEvidenceBaselineReady {
                case,
                baseline: baseline.clone(),
                baseline_observation_sequence: 10,
            })
            .await?;
            finish_capture(PacketEvidenceCaptureTerminal::Aborted(
                PacketEvidenceCaptureAborted {
                    case,
                    baseline,
                    baseline_observation_sequence: 10,
                    reason: PacketEvidenceAbortReason::ObservationFailed,
                },
            ))
            .await?;
            Err(PacketEvidenceTransactionError::Observation(
                "injected observation failure".to_owned(),
            ))
        },
    );
    let collector_side = async {
        send_ticketed_app_request(&mut collector, &request).await;
        let baseline: HostBaselineObserved = collector.receive().await.expect("baseline");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-started-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_STARTED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("capture started");
        let aborted: HostCaptureAborted = collector.receive().await.expect("abort");
        validate_host_aborted(&aborted, &baseline, &session_id, "dns-a-primary")
            .expect("exact abort");
        collector
            .send(&CollectorStageResponse::Complete(CollectorStageComplete {
                case_id: "dns-a-primary".to_owned(),
                document: "cfw-packet-collector-capture-completed-v5".to_owned(),
                schema_version: PROTOCOL_VERSION,
                sequence: CAPTURE_COMPLETED_SEQUENCE,
                session_id: session_id.clone(),
            }))
            .await
            .expect("terminal cleanup");
        let final_response: HostFinalResponse = collector.receive().await.expect("final");
        let HostFinalResponse::Failed(failed) = final_response else {
            panic!("aborted transaction unexpectedly completed");
        };
        assert_eq!(failed.code, "observation_failed");
    };
    let (app_result, ()) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(app_side, collector_side)
    })
    .await
    .expect("aborted protocol hard timeout");
    app_result.expect("typed aborted protocol");
}

#[test]
fn collector_test_submit_error_relays_host_abort_and_drains_finalization() {
    let session_id = "g".repeat(64);
    let case_id = "dns-a-primary";
    let baseline_receipt = snapshot_receipt(7, 'a');
    let test_receipt = snapshot_receipt(8, 'b');
    let baseline = HostBaselineObserved {
        baseline: wire_snapshot(&baseline_receipt),
        baseline_observation_sequence: 10,
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-baseline-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: BASELINE_SEQUENCE,
        session_id: session_id.clone(),
    };
    let test = HostTestObserved {
        case_id: case_id.to_owned(),
        document: "cfw-packet-host-test-observed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TEST_SEQUENCE,
        session_id: session_id.clone(),
        test: wire_snapshot(&test_receipt),
        test_observation_sequence: 11,
    };
    let aborted = HostCaptureAborted {
        baseline: baseline.baseline.clone(),
        baseline_observation_sequence: baseline.baseline_observation_sequence,
        case_id: case_id.to_owned(),
        code: "restore_unproven_quarantined".to_owned(),
        document: "cfw-packet-host-capture-aborted-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: RESTORED_SEQUENCE,
        session_id: session_id.clone(),
    };
    let final_response =
        HostFinalResponse::Failed(host_failed(&session_id, case_id, &aborted.code));
    let terminal_cleanup = CollectorStageResponse::Complete(CollectorStageComplete {
        case_id: case_id.to_owned(),
        document: "cfw-packet-collector-capture-completed-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: CAPTURE_COMPLETED_SEQUENCE,
        session_id: session_id.clone(),
    });
    let (app_proxy, app_host) = UnixStream::pair().expect("app pair");
    let (collector_proxy, collector_peer) = UnixStream::pair().expect("collector pair");
    let mut app = PacketEvidenceChannel::from_fd(app_proxy.into_raw_fd()).expect("app");
    let mut collector =
        PacketEvidenceChannel::from_fd(collector_proxy.into_raw_fd()).expect("collector");
    let mut host = PacketEvidenceChannel::from_fd(app_host.into_raw_fd()).expect("host");
    let mut collector_peer =
        PacketEvidenceChannel::from_fd(collector_peer.into_raw_fd()).expect("peer");

    std::thread::scope(|scope| {
        let host_aborted = aborted.clone();
        let host_final = final_response.clone();
        let host_case_id = case_id.to_owned();
        let host_session_id = session_id.clone();
        let host_thread = scope.spawn(move || {
            host.send(&host_aborted).expect("host abort");
            let received: CollectorStageResponse = host.receive().expect("host cleanup");
            let CollectorStageResponse::Complete(received) = received else {
                panic!("host did not receive terminal cleanup");
            };
            assert_eq!(received.case_id, host_case_id);
            assert_eq!(
                received.document,
                "cfw-packet-collector-capture-completed-v5"
            );
            assert_eq!(received.schema_version, PROTOCOL_VERSION);
            assert_eq!(received.sequence, CAPTURE_COMPLETED_SEQUENCE);
            assert_eq!(received.session_id, host_session_id);
            host.send(&host_final).expect("host final");
        });

        let peer_baseline = baseline.clone();
        let peer_cleanup = terminal_cleanup.clone();
        let peer_session_id = session_id.clone();
        let peer_case_id = case_id.to_owned();
        let peer_thread = scope.spawn(move || {
            let received: HostCaptureAborted = collector_peer.receive().expect("collector abort");
            validate_host_aborted(&received, &peer_baseline, &peer_session_id, &peer_case_id)
                .expect("exact relayed abort");
            assert_eq!(received.code, "restore_unproven_quarantined");
            collector_peer
                .send(&peer_cleanup)
                .expect("collector cleanup");
            let received_final: HostFinalResponse =
                collector_peer.receive().expect("collector final");
            let HostFinalResponse::Failed(received_final) = received_final else {
                panic!("collector did not receive typed final failure");
            };
            assert_eq!(received_final.code, "restore_unproven_quarantined");
        });

        handle_collector_test_submit_error(
            &mut app,
            &mut collector,
            &baseline,
            &test,
            &session_id,
            case_id,
            PacketEvidenceTransportError::TruncatedFrame,
        )
        .expect("aborted response was relayed after collector read failure");

        host_thread.join().expect("host thread");
        peer_thread.join().expect("collector thread");
    });
}

#[tokio::test]
async fn async_readiness_wait_yields_to_the_outer_deadline() {
    let (mut app, _collector, _peer) = async_pair();
    let result =
        tokio::time::timeout(Duration::from_millis(25), app.receive::<CollectorRequest>()).await;
    assert!(result.is_err(), "idle read must yield to Tokio's timer");
}

#[tokio::test]
async fn async_truncated_body_reaches_eof_without_blocking() {
    let (app, mut collector) = UnixStream::pair().expect("pair");
    app.set_nonblocking(true).expect("app nonblocking");
    collector
        .write_all(&10_u32.to_be_bytes())
        .expect("declared length");
    collector.write_all(b"{}").expect("partial body");
    collector
        .shutdown(std::net::Shutdown::Write)
        .expect("collector shutdown");
    let mut app =
        AsyncPacketEvidenceChannel::new(tokio::net::UnixStream::from_std(app).expect("async app"));
    let result = tokio::time::timeout(Duration::from_secs(1), app.receive::<CollectorRequest>())
        .await
        .expect("EOF timeout");
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::TruncatedFrame)
    ));
}

#[test]
fn exact_collector_identity_session_and_case_are_closed() {
    let now = 1_700_000_000_000;
    let peer = PeerIdentity {
        audit_token: [0; 32],
        pid: std::process::id(),
        start_time_unix_us: 1,
        uid: unsafe { libc::geteuid() },
    };
    let hello = session(now);
    validate_collector_hello(&hello, peer, now).expect("exact hello");
    let request = CollectorRequest {
        case_id: "dns-aaaa-secondary".to_owned(),
        document: "cfw-packet-collector-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: REQUEST_SEQUENCE,
        session_id: hello.session_id.clone(),
    };
    assert_eq!(
        validate_collector_request(&request, &hello)
            .expect("fixed case")
            .1,
        ReleasePacketEvidenceCase::DnsAaaaSecondary
    );

    let mut wrong_pid = session(now);
    wrong_pid.collector_pid = peer.pid.saturating_add(1);
    assert!(matches!(
        validate_collector_hello(&wrong_pid, peer, now),
        Err(PacketEvidenceTransportError::InvalidPeer)
    ));
    let expired = session(now);
    assert!(matches!(
        validate_collector_hello(&expired, peer, now + SESSION_LIFETIME_MS + 1),
        Err(PacketEvidenceTransportError::InvalidSession)
    ));
    let mut unknown = request;
    unknown.case_id = "dns-caller-address".to_owned();
    assert!(matches!(
        validate_collector_request(&unknown, &hello),
        Err(PacketEvidenceTransportError::InvalidCase)
    ));
}

#[test]
fn unbound_audit_token_cannot_satisfy_the_release_host_requirement() {
    let peer = PeerIdentity {
        audit_token: [0; 32],
        pid: std::process::id(),
        start_time_unix_us: 1,
        uid: unsafe { libc::geteuid() },
    };
    assert!(matches!(
        validate_signed_peer(peer),
        Err(PacketEvidenceTransportError::InvalidPeerCodeIdentity)
    ));
}

#[test]
fn duplicate_sessions_remain_rejected_until_expiry() {
    let now = 1_700_000_000_000;
    let mut replay = SessionReplayGuard::default();
    replay
        .admit("a".repeat(64).as_str(), now + SESSION_LIFETIME_MS, now)
        .expect("first admission");
    assert!(matches!(
        replay.admit("a".repeat(64).as_str(), now + SESSION_LIFETIME_MS, now),
        Err(PacketEvidenceTransportError::ReplayedSession)
    ));
    replay
        .admit(
            "a".repeat(64).as_str(),
            now + (2 * SESSION_LIFETIME_MS),
            now + SESSION_LIFETIME_MS + 1,
        )
        .expect("expired session removed");
}

#[test]
fn durable_launcher_ticket_rejects_replay_after_store_restart() {
    let now = 1_700_000_000_000;
    let session_id = "7".repeat(64);
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let binding = app_ticket_request(now, peer, &session_id).binding;
    let root = tempdir().expect("ticket root");
    {
        let store = ticket_store(root.path());
        store
            .consume(&binding, &"8".repeat(64), now)
            .expect("first durable consumption");
    }
    let restarted = LauncherTicketStore::open(root.path()).expect("restarted ticket store");
    assert!(matches!(
        restarted.consume(&binding, &"9".repeat(64), now + 1),
        Err(PacketEvidenceTransportError::LauncherTicketReplayed)
    ));
    let records = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
        .expect("ticket records")
        .collect::<Result<Vec<_>, _>>()
        .expect("ticket entries");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].file_name(),
        OsString::from(format!("consumed-{session_id}.json"))
    );
}

#[test]
fn zero_byte_pending_ticket_is_swept_without_poisoning_store() {
    let now = 1_700_000_000_000;
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let root = tempdir().expect("ticket root");
    let store = ticket_store(root.path());
    let pending_id = "a".repeat(64);
    let pending_name = launcher_ticket_pending_filename(&pending_id).expect("pending name");
    let descriptor = unsafe {
        libc::openat(
            store.directory.as_raw_fd(),
            pending_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert_ne!(descriptor, -1, "create interrupted pending ticket");
    drop(unsafe { File::from_raw_fd(descriptor) });

    let binding = app_ticket_request(now, peer, &"b".repeat(64)).binding;
    store
        .consume(&binding, &"c".repeat(64), now)
        .expect("pending sweep followed by durable consumption");
    let names = fs::read_dir(root.path().join(LAUNCHER_TICKET_DIRECTORY))
        .expect("ticket records")
        .map(|entry| entry.expect("ticket entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![OsString::from(format!("consumed-{}.json", "b".repeat(64)))]
    );
}

#[test]
fn expired_launcher_ticket_is_durably_swept_before_session_reuse() {
    let now = 1_700_000_000_000;
    let later = now + SESSION_LIFETIME_MS + SESSION_CLOCK_SKEW_MS + 1;
    let session_id = "d".repeat(64);
    let (proxy, _dashboard) = UnixStream::pair().expect("identity pair");
    let peer = validate_connected_unix_stream(proxy.as_raw_fd()).expect("proxy identity");
    let root = tempdir().expect("ticket root");
    let store = ticket_store(root.path());
    let first = app_ticket_request(now, peer, &session_id).binding;
    store
        .consume(&first, &"e".repeat(64), now)
        .expect("first durable ticket");
    let renewed = app_ticket_request(later, peer, &session_id).binding;
    store
        .consume(&renewed, &"f".repeat(64), later)
        .expect("expired tombstone swept before renewed session");
    let name = format!("consumed-{session_id}.json");
    let _lock = store.lock().expect("ticket read lock");
    let record = store
        .read_record_locked(&name)
        .expect("renewed durable ticket");
    assert_eq!(record.binding.issued_at_unix_ms, later);
    assert_eq!(record.ticket_id, "f".repeat(64));
}

#[test]
fn noncanonical_unknown_and_oversized_frames_fail_closed() {
    for (body, expected) in [
            (
                br#"{ "case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
            (
                br#"{"case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","extra":true,"schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
        ] {
            let (host, mut collector) = UnixStream::pair().expect("pair");
            collector
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("collector timeout");
            write_body(&mut collector, body);
            let mut channel =
                PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
            let result: Result<CollectorRequest, _> = channel.receive();
            assert!(matches!(
                result,
                Err(PacketEvidenceTransportError::InvalidFrame)
            ));
            assert_eq!(expected, "invalid");
        }

    let (host, mut collector) = UnixStream::pair().expect("pair");
    collector
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .expect("oversized length");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    let result: Result<CollectorRequest, _> = channel.receive();
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::FrameBound)
    ));
}

#[test]
fn ancillary_descriptors_are_closed_and_rejected() {
    let (host, collector) = UnixStream::pair().expect("pair");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    let descriptor = fs::File::open("/dev/null").expect("sentinel");
    let payload = [descriptor.as_raw_fd()];
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let bytes = b"\0\0\0\x02{}";
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0_usize; 8];
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
        *libc::CMSG_DATA(header).cast::<RawFd>() = payload[0];
        assert_eq!(
            libc::sendmsg(collector.as_raw_fd(), &message, 0),
            bytes.len() as isize
        );
    }
    let result: Result<CollectorRequest, _> = channel.receive();
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::AncillaryData)
    ));
}

#[test]
fn host_frames_are_canonical_and_do_not_expose_error_text() {
    let (host, mut collector) = UnixStream::pair().expect("pair");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    channel
        .send(&host_failed(
            &"a".repeat(64),
            "dns-a-primary",
            "baseline_mismatch",
        ))
        .expect("failure");
    let body = read_frame(&mut collector);
    assert_eq!(
            body,
            br#"{"case_id":"dns-a-primary","code":"baseline_mismatch","document":"cfw-packet-host-failed-v5","schema_version":5,"sequence":8,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
        );
}

#[test]
fn endpoint_guard_unlinks_only_the_exact_bound_socket_inode() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        path: path.clone(),
    };
    drop(listener);
    fs::remove_file(&path).expect("remove original");
    let replacement = UnixListener::bind(&path).expect("replacement");
    drop(guard);
    assert!(path.exists(), "a replacement inode must never be unlinked");
    drop(replacement);
}

#[test]
fn endpoint_guard_unlinks_its_own_socket_on_clean_shutdown() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let guard = ControlSocketGuard {
        identity: SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        path: path.clone(),
    };
    drop(listener);
    drop(guard);
    assert!(!path.exists(), "the exact endpoint inode must be unlinked");
}

#[test]
fn synchronous_setup_registers_control_listener_inside_tauri_runtime() {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the regression requires a setup-equivalent thread without a Tokio reactor"
    );
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");

    let listener = register_control_endpoint(listener)
        .expect("Tauri runtime registration outside a current reactor");
    let client = UnixStream::connect(&path).expect("queued client");
    let accepted = tauri::async_runtime::block_on(async {
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("bounded accept")
            .expect("accepted client")
    });

    drop(accepted);
    drop(client);
}

#[test]
fn endpoint_cleanup_failure_remains_typed_for_the_next_startup() {
    let root = tempdir().expect("root");
    let path = root.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let metadata = fs::symlink_metadata(&path).expect("metadata");
    let stale = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    let result = remove_stale_control_socket_with(&path, stale, |_| {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected exact-inode unlink failure",
        ))
    });

    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::EndpointCleanupFailed)
    ));
    assert!(
        path.exists(),
        "failed cleanup must retain the exact inode for startup diagnosis"
    );
    drop(listener);
    fs::remove_file(path).expect("remove test socket");
}
