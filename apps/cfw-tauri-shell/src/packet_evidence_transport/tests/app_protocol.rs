//! The app's side of the staged protocol over a socket pair: the happy path,
//! a duplicate request in the capture slot, a failed test stage, an aborted
//! engine path, and the Host abort relayed after a failed test submit.

use super::*;

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
