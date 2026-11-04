import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

// The server result: version 5, its fixture shared with the Python
// validator, and the rejected version 4.
extension PeerLifecycleAndMacProbeTests {
  @Test("server result v5 keeps pair-required evidence non-claimable and canonical")
  func serverResultV5() throws {
    let sessionID = String(repeating: "1", count: 64)
    var tracker = PeerCompletionTracker()
    _ = try recordAccepted(.tcpSink, in: &tracker, sessionID: sessionID)
    _ = try recordPairRequired(
      .tls13Echo,
      completion: .unobserved,
      in: &tracker,
      sessionID: sessionID
    )
    #expect(
      try recordPairRequired(
        .quicEcho,
        completion: .processed,
        in: &tracker,
        sessionID: sessionID
      ) == .pairRequired
    )

    let receipt = serverResult(status: .pairRequired, outcomes: tracker.outcomes)
    try receipt.validate()
    let canonical = try ExactJSON.encode(receipt)
    let object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    #expect(object["schema_version"] as? Int == 5)
    #expect(object["document"] as? String == "cfm-ios-transport-peer-result-v5")
    #expect(object["evidence_role"] as? String == "server_observation_only")
    #expect(object["claim_eligible"] as? Bool == false)
    #expect(object["status"] as? String == "pair_required")
    #expect(object["failure_phase"] as? String == "none")
    #expect(object["failed_service"] as? String == "none")
    #expect(object["failure_reason"] as? String == "none")
    #expect(object["phase_reached"] as? String == "completed")
    #expect(object["blocking_service"] is NSNull)
    #expect(object["blocking_phase"] is NSNull)
    #expect(object["blocking_admission_sequence"] is NSNull)
    #expect(object["incoming_admission_sequence"] is NSNull)
    #expect(object["incoming_matches_blocker_object"] is NSNull)
    #expect(object["blocking_quic_stream_identifier"] is NSNull)
    let connections = try #require(object["connections"] as? [String: Any])
    let tls = try #require(connections["tls13_echo"] as? [String: Any])
    #expect(tls["accepted"] as? Int == 0)
    #expect(tls["evidence_disposition"] as? String == "pair_required")
    #expect(tls["delivery_confirmation_completion"] as? String == "unobserved")
    #expect(tls["peer_terminal_observed"] as? Bool == false)
    #expect(tls["delivery_acknowledgement_final_context_observed"] as? Bool == true)
    #expect(tls["control_bytes_submitted"] as? Int == 1)
    #expect(tls["control_bytes_sent"] == nil)

    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .none,
        outcomes: tracker.outcomes
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(status: .closed, outcomes: tracker.outcomes).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .pairRequired,
        outcomes: tracker.outcomes,
        schemaVersion: 2,
        document: "cfm-ios-transport-peer-result-v2"
      ).validate()
    }

    let failed = serverResult(
      status: .failed,
      failurePhase: .deliveryEvidence,
      outcomes: ConnectionOutcomes(),
      listenersClosed: false,
      failedService: .quicEcho,
      failureReason: .unexpectedTrailingBytes,
      phaseReached: .deliveryConfirmationSubmitted
    )
    try failed.validate()
    let failedObject = try #require(
      JSONSerialization.jsonObject(with: ExactJSON.encode(failed).dropLast())
        as? [String: Any]
    )
    #expect(failedObject["failure_phase"] as? String == "delivery_evidence")
    #expect(failedObject["failed_service"] as? String == "quic_echo")
    #expect(failedObject["failure_reason"] as? String == "unexpected_trailing_bytes")
    #expect(
      failedObject["phase_reached"] as? String == "delivery_confirmation_submitted"
    )

    let acknowledgementNotFinal = serverResult(
      status: .failed,
      failurePhase: .deliveryEvidence,
      outcomes: ConnectionOutcomes(),
      listenersClosed: false,
      failedService: .tls13Echo,
      failureReason: .acknowledgementNotFinal,
      phaseReached: .echoCompleted
    )
    try acknowledgementNotFinal.validate()
    var arbitraryFailureObject = failedObject
    arbitraryFailureObject["failure_reason"] = "arbitrary network error text"
    let arbitraryFailureData = try JSONSerialization.data(
      withJSONObject: arbitraryFailureObject,
      options: [.sortedKeys]
    )
    #expect(throws: DecodingError.self) {
      try JSONDecoder().decode(ResultReceipt.self, from: arbitraryFailureData)
    }

    try serverResult(
      status: .failed,
      failurePhase: .completionValidation,
      outcomes: ConnectionOutcomes(),
      failedService: .runtime,
      failureReason: .completionEvidenceInvalid,
      phaseReached: .completionResolved
    ).validate()

    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .deliveryEvidence,
        outcomes: ConnectionOutcomes(),
        failedService: PeerFailedService.none,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .deliveryEvidence,
        outcomes: ConnectionOutcomes(),
        failedService: .runtime,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .pairRequired,
        outcomes: tracker.outcomes,
        failedService: .quicEcho,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
  }

  @Test("result v5 fixture is shared with the Python validator")
  func sharedResultV5Fixture() throws {
    let packageRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let fixture =
      packageRoot
      .appendingPathComponent("Fixtures", isDirectory: true)
      .appendingPathComponent("result-v5-pair-required.json")
    let data = try Data(contentsOf: fixture)
    let receipt = try JSONDecoder().decode(ResultReceipt.self, from: data)
    try receipt.validate()
    #expect(receipt.status == .pairRequired)
    #expect(receipt.connections.quicEcho.evidenceDisposition == .pairRequired)
    #expect(try ExactJSON.encode(receipt) == data)
  }

  @Test("legacy server result v4 is rejected by the v5 model")
  func legacyServerResultV4Rejected() throws {
    let packageRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let fixture =
      packageRoot
      .appendingPathComponent("Fixtures", isDirectory: true)
      .appendingPathComponent("result-v4-pair-required.json")
    let data = try Data(contentsOf: fixture)
    let legacy = try JSONDecoder().decode(ResultReceipt.self, from: data)
    #expect(throws: PeerContractError.self) {
      try legacy.validate()
    }
  }
}
