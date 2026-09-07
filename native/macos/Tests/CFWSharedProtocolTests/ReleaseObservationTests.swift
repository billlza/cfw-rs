import Foundation
import Testing

@testable import CFWSharedProtocol

@Suite("Release observation")
struct ReleaseObservationTests {
  @Test("candidate build number accepts ASCII decimal digits only")
  func candidateBuildNumberIsASCIIDecimal() throws {
    #expect(
      try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "40005")
        == ReleaseObservationCandidate(version: "0.4.0", buildNumber: "40005"))
    #expect(throws: ReleaseObservationError.invalidCandidate) {
      _ = try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "４０００５")
    }
    #expect(throws: ReleaseObservationError.invalidCandidate) {
      _ = try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "4٠٠٠٥")
    }
  }

  @Test("peer decision is canonical, closed and non-sensitive")
  func peerDecisionEncoding() throws {
    let state = String(repeating: "a", count: 64)
    let payload = try ReleaseObservationPeerDecision(
      role: .host,
      peerPID: 42,
      effectiveUserIdentifier: 501,
      auditSessionIdentifier: 100_001,
      connectionIdentitySHA256: String(repeating: "b", count: 64),
      accepted: true,
      actualCode: .accepted,
      preStateSHA256: state,
      postStateSHA256: state,
      cleanupState: .off)
    let message = try ReleaseObservationLogger.encodeAuthorityPeerDecision(
      payload,
      candidate: try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "40005"),
      process: try ReleaseObservationProcess(pid: 7, startUnixMilliseconds: 1_000),
      sequence: 1,
      recordedUnixMilliseconds: 2_000)
    #expect(message.hasPrefix(ReleaseObservationLogger.messagePrefix))
    let body = String(message.dropFirst(ReleaseObservationLogger.messagePrefix.count))
    let value = try #require(
      JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
    #expect(
      Set(value.keys) == [
        "candidate", "component", "document", "event", "payload", "process",
        "recorded_unix_ms", "schema_version", "sequence",
      ])
    #expect(value["component"] as? String == "global_authority")
    #expect(value["event"] as? String == "peer_authorization_decision")
    #expect(!message.contains("ticket"))
    #expect(!message.contains("secret"))
  }

  @Test("decision and identity digest cannot disagree")
  func decisionIdentityBinding() throws {
    let digest = String(repeating: "a", count: 64)
    #expect(throws: ReleaseObservationError.self) {
      _ = try ReleaseObservationPeerDecision(
        role: .host,
        peerPID: 42,
        effectiveUserIdentifier: 501,
        auditSessionIdentifier: 100_001,
        connectionIdentitySHA256: digest,
        accepted: false,
        actualCode: .globalAuthorityIdentityRejected,
        preStateSHA256: digest,
        postStateSHA256: digest,
        cleanupState: .off)
    }
  }

  @Test("authenticated operation decision retains raw request and peer identity")
  func authenticatedOperationDecisionEncoding() throws {
    let state = String(repeating: "a", count: 64)
    let payload = try ReleaseObservationAuthenticatedDecision(
      role: .host,
      peerPID: 42,
      effectiveUserIdentifier: 501,
      auditSessionIdentifier: 100_001,
      connectionIdentitySHA256: String(repeating: "b", count: 64),
      requestSHA256: String(repeating: "c", count: 64),
      accepted: false,
      actualCode: .replayRejected,
      preStateSHA256: state,
      postStateSHA256: state,
      cleanupState: .off)
    let message = try ReleaseObservationLogger.encodeAuthorityOperationDecision(
      payload,
      candidate: try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "40005"),
      process: try ReleaseObservationProcess(pid: 7, startUnixMilliseconds: 1_000),
      sequence: 2,
      recordedUnixMilliseconds: 2_001)
    let body = String(message.dropFirst(ReleaseObservationLogger.messagePrefix.count))
    let value = try #require(
      JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
    let encodedPayload = try #require(value["payload"] as? [String: Any])
    #expect(value["event"] as? String == "operation_decision")
    #expect(encodedPayload["actual_code"] as? String == "replay_rejected")
    #expect(encodedPayload["request_sha256"] as? String == String(repeating: "c", count: 64))
    #expect(
      Set(encodedPayload.keys) == [
        "accepted", "actual_code", "audit_session_id", "cleanup_state",
        "connection_identity_sha256", "euid", "peer_pid", "post_state_sha256",
        "pre_state_sha256", "request_sha256", "role",
      ])
  }

  @Test("authenticated decision cannot claim a mismatched stable code")
  func authenticatedDecisionCodeBinding() throws {
    let digest = String(repeating: "a", count: 64)
    #expect(throws: ReleaseObservationError.self) {
      _ = try ReleaseObservationAuthenticatedDecision(
        role: .host,
        peerPID: 42,
        effectiveUserIdentifier: 501,
        auditSessionIdentifier: 100_001,
        connectionIdentitySHA256: digest,
        requestSHA256: digest,
        accepted: false,
        actualCode: .accepted,
        preStateSHA256: digest,
        postStateSHA256: digest,
        cleanupState: .off)
    }
  }

  @Test("journal decision is a closed corrupt-to-quarantined event")
  func journalDecisionEncoding() throws {
    let digest = String(repeating: "d", count: 64)
    let payload = try ReleaseObservationJournalDecision(
      journalInputSHA256: digest,
      actualCode: .journalCorrupt,
      preStateSHA256: String(repeating: "a", count: 64),
      postStateSHA256: String(repeating: "b", count: 64),
      cleanupState: .quarantined)
    let message = try ReleaseObservationLogger.encodeAuthorityJournalDecision(
      payload,
      candidate: try ReleaseObservationCandidate(version: "0.4.0", buildNumber: "40005"),
      process: try ReleaseObservationProcess(pid: 7, startUnixMilliseconds: 1_000),
      sequence: 3,
      recordedUnixMilliseconds: 2_002)
    #expect(message.contains("\"event\":\"journal_integrity_decision\""))
    #expect(message.contains("\"actual_code\":\"journal_corrupt\""))
    #expect(!message.contains("secret"))
  }

  @Test("authority state digest is stable and sensitive-value free")
  func authorityStateDigest() throws {
    let first = try ReleaseObservationLogger.authorityStateSHA256(
      state: .active, revision: 9, leaseOwnerUID: 501)
    let second = try ReleaseObservationLogger.authorityStateSHA256(
      state: .active, revision: 9, leaseOwnerUID: 501)
    let off = try ReleaseObservationLogger.authorityStateSHA256(
      state: .off, revision: 9, leaseOwnerUID: nil)
    #expect(first == second)
    #expect(first.count == 64)
    #expect(first != off)
  }
}
