//! Validating the Host's answers to the collector's stages: the baseline, the
//! test, the restore, an abort, a failure and the completion.

use super::*;

fn exact_tunnel(snapshot: &WireSnapshot, ipv6_enabled: bool) -> bool {
    snapshot.desired_mode == EngineMode::Tunnel
        && snapshot.generation > 0
        && snapshot
            .config_digest
            .as_deref()
            .is_some_and(canonical_session_id)
        && snapshot.ipv6_enabled == ipv6_enabled
        && snapshot.owner == Some(EngineOwner::PacketTunnelSystemExtension)
        && snapshot.phase == "tunnel_active"
        && snapshot.ready
}

fn exact_off(snapshot: &WireSnapshot) -> bool {
    snapshot.desired_mode == EngineMode::Off
        && snapshot.generation > 0
        && snapshot.config_digest.is_none()
        && !snapshot.ipv6_enabled
        && snapshot.owner.is_none()
        && snapshot.phase == "off"
        && !snapshot.ready
}

pub(in crate::packet_evidence_transport) fn validate_host_baseline(
    observed: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-baseline-observed-v5"
        || observed.sequence != BASELINE_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.baseline_observation_sequence == 0
        || !exact_tunnel(&observed.baseline, true)
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(in crate::packet_evidence_transport) fn validate_host_test(
    observed: &HostTestObserved,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let (_, case) = parse_case(case_id)?;
    let exact_case_state = match case {
        ReleasePacketEvidenceCase::StopCleanup => exact_off(&observed.test),
        ReleasePacketEvidenceCase::Ipv6DisabledAbsence => exact_tunnel(&observed.test, false),
        _ => exact_tunnel(&observed.test, true),
    };
    if observed.schema_version != PROTOCOL_VERSION
        || observed.document != "cfw-packet-host-test-observed-v5"
        || observed.sequence != TEST_SEQUENCE
        || observed.session_id != session_id
        || observed.case_id != case_id
        || observed.test_observation_sequence == 0
        || observed.test.generation <= baseline.baseline.generation
        || observed.test.config_digest == baseline.baseline.config_digest
        || !exact_case_state
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(in crate::packet_evidence_transport) fn validate_host_restored(
    restored: &HostBaselineRestored,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    let test_identity_matches = match (test, restored.test.as_ref()) {
        (Some(test), Some(restored_test)) => {
            restored_test == &test.test
                && restored.test_observation_sequence == Some(test.test_observation_sequence)
                && test.test.generation < restored.restore.generation
        }
        (None, None) => {
            restored.test_observation_sequence.is_none()
                && baseline.baseline.generation <= restored.restore.generation
        }
        _ => false,
    };
    if restored.schema_version != PROTOCOL_VERSION
        || restored.document != "cfw-packet-host-baseline-restored-v5"
        || restored.sequence != RESTORED_SEQUENCE
        || restored.session_id != session_id
        || restored.case_id != case_id
        || restored.baseline != baseline.baseline
        || restored.baseline_observation_sequence != baseline.baseline_observation_sequence
        || restored.restore_observation_sequence == 0
        || !exact_tunnel(&restored.restore, true)
        || restored.restore.config_digest != baseline.baseline.config_digest
        || !test_identity_matches
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(in crate::packet_evidence_transport) fn validate_host_aborted(
    aborted: &HostCaptureAborted,
    baseline: &HostBaselineObserved,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if aborted.schema_version != PROTOCOL_VERSION
        || aborted.document != "cfw-packet-host-capture-aborted-v5"
        || aborted.sequence != RESTORED_SEQUENCE
        || aborted.session_id != session_id
        || aborted.case_id != case_id
        || aborted.baseline != baseline.baseline
        || aborted.baseline_observation_sequence != baseline.baseline_observation_sequence
        || !matches!(
            aborted.code.as_str(),
            "test_apply_failed"
                | "test_snapshot_invalid"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn validate_host_failed(
    failed: &HostFailed,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if failed.schema_version != PROTOCOL_VERSION
        || failed.document != "cfw-packet-host-failed-v5"
        || failed.sequence != RESULT_SEQUENCE
        || failed.session_id != session_id
        || failed.case_id != case_id
        || !matches!(
            failed.code.as_str(),
            "maintenance_busy"
                | "legacy_retirement_blocked"
                | "tunnel_unavailable"
                | "baseline_unavailable"
                | "baseline_mismatch"
                | "projection_failed"
                | "test_apply_failed"
                | "test_snapshot_invalid"
                | "capture_command_failed"
                | "capture_evidence_rejected"
                | "capture_archive_failed"
                | "capture_cancelled"
                | "capture_control_failed"
                | "capture_timeout"
                | "capture_panicked"
                | "restore_unproven_quarantined"
                | "restore_mismatch_quarantined"
                | "restore_quarantine_failed"
                | "observation_failed"
                | "completion_closed"
                | "session_replayed"
                | "session_capacity_exhausted"
                | "session_invalid"
                | "launcher_ticket_replayed"
                | "launcher_ticket_capacity_exhausted"
                | "launcher_ticket_invalid"
                | "launcher_ticket_store_unavailable"
                | "app_control_unavailable"
                | "app_identity_invalid"
                | "app_control_invalid"
                | "app_control_failed"
        )
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(in crate::packet_evidence_transport) fn validate_host_completed(
    completed: &HostCompleted,
    baseline: &HostBaselineObserved,
    test: &HostTestObserved,
    restored: &HostBaselineRestored,
    session_id: &str,
    case_id: &str,
) -> Result<(), PacketEvidenceTransportError> {
    if completed.schema_version != PROTOCOL_VERSION
        || completed.document != "cfw-packet-host-completed-v5"
        || completed.sequence != RESULT_SEQUENCE
        || completed.session_id != session_id
        || completed.case_id != case_id
        || completed.candidate_observation_sequence == 0
        || completed.candidate_observation_sequence != completed.test_observation_sequence
        || completed.baseline != baseline.baseline
        || completed.baseline_observation_sequence != baseline.baseline_observation_sequence
        || completed.test != test.test
        || completed.test_observation_sequence != test.test_observation_sequence
        || completed.restore != restored.restore
        || completed.restore_observation_sequence != restored.restore_observation_sequence
    {
        return Err(PacketEvidenceTransportError::InvalidResponse);
    }
    Ok(())
}

pub(super) fn receive_and_validate_final(
    app: &mut PacketEvidenceChannel,
    baseline: &HostBaselineObserved,
    test: Option<&HostTestObserved>,
    restored: Option<&HostBaselineRestored>,
    session_id: &str,
    case_id: &str,
) -> Result<HostFinalResponse, PacketEvidenceTransportError> {
    let response: HostFinalResponse = app.receive()?;
    match &response {
        HostFinalResponse::Completed(completed) => {
            let (Some(test), Some(restored)) = (test, restored) else {
                return Err(PacketEvidenceTransportError::InvalidResponse);
            };
            validate_host_completed(completed, baseline, test, restored, session_id, case_id)?;
            Ok(response)
        }
        HostFinalResponse::Failed(failed) => {
            validate_host_failed(failed, session_id, case_id)?;
            Ok(response)
        }
    }
}
