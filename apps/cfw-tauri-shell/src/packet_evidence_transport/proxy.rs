//! The collector side: proxying the authenticated transaction between the
//! collector and the Host, and relaying a Host abort or failure to both.

use super::*;

mod host_answers;

#[cfg(test)]
pub(super) use host_answers::validate_host_completed;
use host_answers::{receive_and_validate_final, validate_host_failed};
pub(super) use host_answers::{
    validate_host_aborted, validate_host_baseline, validate_host_restored, validate_host_test,
};

pub(super) fn cancellation(
    session_id: &str,
    case_id: &str,
    sequence: u32,
    document: &str,
) -> CollectorStageResponse {
    CollectorStageResponse::Failed(CollectorStageFailed {
        case_id: case_id.to_owned(),
        code: "cancelled".to_owned(),
        document: document.to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence,
        session_id: session_id.to_owned(),
    })
}

pub(super) fn proxy_failure_code(error: &PacketEvidenceTransportError) -> &'static str {
    match error {
        PacketEvidenceTransportError::EndpointUnavailable
        | PacketEvidenceTransportError::EndpointUnsafe
        | PacketEvidenceTransportError::EndpointActive
        | PacketEvidenceTransportError::EndpointCleanupFailed => "app_control_unavailable",
        PacketEvidenceTransportError::InvalidPeer
        | PacketEvidenceTransportError::InvalidPeerExecutable
        | PacketEvidenceTransportError::InvalidPeerCodeIdentity
        | PacketEvidenceTransportError::InvalidCandidate => "app_identity_invalid",
        PacketEvidenceTransportError::InvalidFrame
        | PacketEvidenceTransportError::InvalidResponse
        | PacketEvidenceTransportError::FrameBound
        | PacketEvidenceTransportError::AncillaryData
        | PacketEvidenceTransportError::AncillaryCleanup
        | PacketEvidenceTransportError::InvalidSession
        | PacketEvidenceTransportError::ReplayedSession
        | PacketEvidenceTransportError::SessionCapacity
        | PacketEvidenceTransportError::LauncherTicketReplayed
        | PacketEvidenceTransportError::LauncherTicketCapacity
        | PacketEvidenceTransportError::InvalidCase => "app_control_invalid",
        PacketEvidenceTransportError::InvalidDescriptor
        | PacketEvidenceTransportError::TruncatedFrame
        | PacketEvidenceTransportError::WriteFailed
        | PacketEvidenceTransportError::LauncherTicketUnsafe
        | PacketEvidenceTransportError::LauncherTicketCommitUncertain => "app_control_failed",
    }
}

pub(super) fn relay_aborted_finalization(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    aborted: HostCaptureAborted,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    validate_host_aborted(&aborted, baseline, session_id, case_id)?;
    if let Err(error) = collector.send(&aborted) {
        // The collector may have timed out its prior stage while keeping the
        // channel open, or it may have already exited. Either way, the Host
        // finish callback is still waiting for one terminal frame. Unblock
        // that callback before returning the collector-side failure so the
        // actor-owned restore/final result can reach a terminal state.
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(error);
    }
    let final_capture: CollectorStageResponse = match collector.receive() {
        Ok(response) => response,
        Err(error) => {
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final =
                receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
            return Err(error);
        }
    };
    let cleanup_result = stage_result(
        &final_capture,
        session_id,
        case_id,
        CAPTURE_COMPLETED_SEQUENCE,
        "cfw-packet-collector-capture-completed-v5",
        "cfw-packet-collector-capture-complete-failed-v5",
    );
    if cleanup_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
        app.send(&cancellation(
            session_id,
            case_id,
            CAPTURE_COMPLETED_SEQUENCE,
            "cfw-packet-collector-capture-complete-failed-v5",
        ))?;
        let _final = receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
        return Err(PacketEvidenceTransportError::InvalidFrame);
    }
    app.send(&final_capture)?;
    let final_response =
        receive_and_validate_final(app, baseline, None, None, session_id, case_id)?;
    let HostFinalResponse::Failed(failed) = &final_response else {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    };
    let expected_code = match cleanup_result {
        Ok(()) => aborted.code.as_str(),
        Err(error) => capture_failure_code(error),
    };
    if failed.code != expected_code {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    collector.send(&final_response)
}

pub(super) fn handle_collector_test_submit_error(
    app: &mut PacketEvidenceChannel,
    collector: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    session_id: &str,
    case_id: &str,
    original: PacketEvidenceTransportError,
) -> Result<(), PacketEvidenceTransportError> {
    let restored_response: HostRestoreResponse = app.receive()?;
    match restored_response {
        HostRestoreResponse::Failed(failed) => {
            validate_host_failed(&failed, session_id, case_id)?;
            collector.send(&failed)
        }
        HostRestoreResponse::Aborted(aborted) => {
            // A collector read timeout does not prove that the collector
            // process exited. Relay the Host abort and give it the same
            // terminal cleanup opportunity as the normal response path.
            relay_aborted_finalization(app, collector, baseline, aborted, session_id, case_id)
        }
        HostRestoreResponse::Restored(restored) => {
            validate_host_restored(&restored, baseline, Some(test), session_id, case_id)?;
            app.send(&cancellation(
                session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-complete-failed-v5",
            ))?;
            let _final = receive_and_validate_final(
                app,
                baseline,
                Some(test),
                Some(&restored),
                session_id,
                case_id,
            )?;
            Err(original)
        }
    }
}

pub(super) fn proxy_authenticated_transaction(
    collector: &mut PacketEvidenceChannel,
    hello: &CollectorHello,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let mut app = PacketEvidenceChannel::connect(&control_socket_path()?)?;
    if app.peer.pid == std::process::id() {
        return Err(PacketEvidenceTransportError::InvalidPeer);
    }
    validate_same_executable_peer(app.peer)?;
    validate_signed_peer(app.peer)?;
    let proxy = process_bsd_info(
        libc::pid_t::try_from(std::process::id())
            .map_err(|_| PacketEvidenceTransportError::InvalidPeer)?,
    )?;
    let binding = LauncherBinding {
        case_id: case_id.to_owned(),
        collector_audit_token: encode_identity(&collector.peer.audit_token),
        collector_pid: collector.peer.pid,
        collector_start_time_unix_us: collector.peer.start_time_unix_us,
        collector_uid: collector.peer.uid,
        expires_at_unix_ms: hello.expires_at_unix_ms,
        issued_at_unix_ms: hello.issued_at_unix_ms,
        proxy_pid: std::process::id(),
        proxy_start_time_unix_us: process_start_time_unix_us(&proxy)?,
        proxy_uid: unsafe { libc::geteuid() },
        session_id: hello.session_id.clone(),
    };
    app.send(&AppTicketRequest {
        binding: binding.clone(),
        document: "cfw-packet-app-ticket-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: TICKET_SEQUENCE,
    })?;
    let ticket_response: HostTicketResponse = app.receive()?;
    let ticket = match ticket_response {
        HostTicketResponse::Issued(ticket) => ticket,
        HostTicketResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            return collector.send(&failed);
        }
    };
    validate_ticket_issued(&ticket, &binding)?;
    app.send(&AppRequest {
        binding,
        document: "cfw-packet-app-request-v5".to_owned(),
        schema_version: PROTOCOL_VERSION,
        sequence: REQUEST_SEQUENCE,
        ticket_id: ticket.ticket_id,
    })?;
    app.set_transaction_timeout()?;
    collector.set_transaction_timeout()?;

    let first: HostBaselineResponse = app.receive()?;
    match first {
        HostBaselineResponse::Failed(failed) => {
            validate_host_failed(&failed, &hello.session_id, case_id)?;
            collector.send(&failed)
        }
        HostBaselineResponse::Observed(baseline) => {
            validate_host_baseline(&baseline, &hello.session_id, case_id)?;
            collector.send(&baseline)?;
            let capture_started: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_STARTED_SEQUENCE,
                        "cfw-packet-collector-capture-start-failed-v5",
                    ))?;
                    let terminal: HostTestResponse = app.receive()?;
                    let restored = match terminal {
                        HostTestResponse::Restored(restored) => {
                            validate_host_restored(
                                &restored,
                                &baseline,
                                None,
                                &hello.session_id,
                                case_id,
                            )?;
                            Some(restored)
                        }
                        HostTestResponse::Aborted(aborted) => {
                            validate_host_aborted(&aborted, &baseline, &hello.session_id, case_id)?;
                            None
                        }
                        HostTestResponse::Failed(failed) => {
                            validate_host_failed(&failed, &hello.session_id, case_id)?;
                            return Err(error);
                        }
                        HostTestResponse::Observed(_) => {
                            return Err(PacketEvidenceTransportError::InvalidResponse);
                        }
                    };
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        restored.as_ref(),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let capture_start_result = stage_result(
                &capture_started,
                &hello.session_id,
                case_id,
                CAPTURE_STARTED_SEQUENCE,
                "cfw-packet-collector-capture-started-v5",
                "cfw-packet-collector-capture-start-failed-v5",
            );
            // The actor-owning Host must see every exact bounded stage frame,
            // including one whose semantics are invalid. Begin may already
            // have produced a collector side effect, so only the Host can
            // restore and drive the take-once terminal cleanup.
            app.send(&capture_started)?;

            let test_response: HostTestResponse = app.receive()?;
            let test = match test_response {
                HostTestResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostTestResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostTestResponse::Restored(restored) => {
                    validate_host_restored(&restored, &baseline, None, &hello.session_id, case_id)?;
                    collector.send(&restored)?;
                    let final_capture: CollectorStageResponse = collector.receive()?;
                    let final_result = stage_result(
                        &final_capture,
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-completed-v5",
                        "cfw-packet-collector-capture-complete-failed-v5",
                    );
                    if final_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                        app.send(&cancellation(
                            &hello.session_id,
                            case_id,
                            CAPTURE_COMPLETED_SEQUENCE,
                            "cfw-packet-collector-capture-complete-failed-v5",
                        ))?;
                        let _final = receive_and_validate_final(
                            &mut app,
                            &baseline,
                            None,
                            Some(&restored),
                            &hello.session_id,
                            case_id,
                        )?;
                        return Err(PacketEvidenceTransportError::InvalidFrame);
                    }
                    app.send(&final_capture)?;
                    let final_response = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        None,
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    let expected_failure = match final_result {
                        Err(error) => Some(capture_failure_code(error)),
                        Ok(()) => capture_start_result.err().map(capture_failure_code),
                    };
                    if let Some(expected_failure) = expected_failure
                        && !matches!(
                            &final_response,
                            HostFinalResponse::Failed(failed) if failed.code == expected_failure
                        )
                    {
                        return Err(PacketEvidenceTransportError::InvalidResponse);
                    }
                    return collector.send(&final_response);
                }
                HostTestResponse::Observed(test) => test,
            };
            validate_host_test(&test, &baseline, &hello.session_id, case_id)?;
            collector.send(&test)?;
            let test_submitted: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        TEST_SUBMITTED_SEQUENCE,
                        "cfw-packet-collector-test-submit-failed-v5",
                    ))?;
                    return handle_collector_test_submit_error(
                        &mut app,
                        collector,
                        &baseline,
                        &test,
                        &hello.session_id,
                        case_id,
                        error,
                    );
                }
            };
            let test_submit_result = stage_result(
                &test_submitted,
                &hello.session_id,
                case_id,
                TEST_SUBMITTED_SEQUENCE,
                "cfw-packet-collector-test-submitted-v5",
                "cfw-packet-collector-test-submit-failed-v5",
            );
            // Forward an exact, bounded frame even when its stage semantics are
            // invalid. The actor-owning Host independently maps it to a typed
            // control-channel failure, restores the baseline, and invokes the
            // one terminal collector cleanup. Returning here would strand a
            // capture that was already acknowledged as started.
            app.send(&test_submitted)?;

            let restored_response: HostRestoreResponse = app.receive()?;
            let restored = match restored_response {
                HostRestoreResponse::Failed(failed) => {
                    validate_host_failed(&failed, &hello.session_id, case_id)?;
                    return collector.send(&failed);
                }
                HostRestoreResponse::Aborted(aborted) => {
                    return relay_aborted_finalization(
                        &mut app,
                        collector,
                        &baseline,
                        aborted,
                        &hello.session_id,
                        case_id,
                    );
                }
                HostRestoreResponse::Restored(restored) => restored,
            };
            validate_host_restored(
                &restored,
                &baseline,
                Some(&test),
                &hello.session_id,
                case_id,
            )?;
            collector.send(&restored)?;
            let final_capture: CollectorStageResponse = match collector.receive() {
                Ok(response) => response,
                Err(error) => {
                    app.send(&cancellation(
                        &hello.session_id,
                        case_id,
                        CAPTURE_COMPLETED_SEQUENCE,
                        "cfw-packet-collector-capture-complete-failed-v5",
                    ))?;
                    let _final = receive_and_validate_final(
                        &mut app,
                        &baseline,
                        Some(&test),
                        Some(&restored),
                        &hello.session_id,
                        case_id,
                    )?;
                    return Err(error);
                }
            };
            let final_capture_result = stage_result(
                &final_capture,
                &hello.session_id,
                case_id,
                CAPTURE_COMPLETED_SEQUENCE,
                "cfw-packet-collector-capture-completed-v5",
                "cfw-packet-collector-capture-complete-failed-v5",
            );
            if final_capture_result == Err(PacketEvidenceCaptureFailure::ControlChannelFailed) {
                app.send(&cancellation(
                    &hello.session_id,
                    case_id,
                    CAPTURE_COMPLETED_SEQUENCE,
                    "cfw-packet-collector-capture-complete-failed-v5",
                ))?;
                let _final = receive_and_validate_final(
                    &mut app,
                    &baseline,
                    Some(&test),
                    Some(&restored),
                    &hello.session_id,
                    case_id,
                )?;
                return Err(PacketEvidenceTransportError::InvalidFrame);
            }
            app.send(&final_capture)?;
            let final_response = receive_and_validate_final(
                &mut app,
                &baseline,
                Some(&test),
                Some(&restored),
                &hello.session_id,
                case_id,
            )?;
            let expected_failure = match final_capture_result {
                Err(error) => Some(capture_failure_code(error)),
                Ok(()) => test_submit_result.err().map(capture_failure_code),
            };
            if let Some(expected_failure) = expected_failure
                && !matches!(
                    &final_response,
                    HostFinalResponse::Failed(failed) if failed.code == expected_failure
                )
            {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            }
            collector.send(&final_response)
        }
    }
}
