import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation

private let probeDocument = "cfw-adversarial-probe-result-v1"
private let resetDocument = "cfw-adversarial-reset-result-v1"
private let childDocument = "cfw-adversarial-peer-result-v1"
private let preconditionDocument = "cfw-adversarial-precondition-unavailable-v1"
private let variantRoot =
  "/Library/Application Support/Clash for Mac/ReleaseVerification/Adversarial/IdentityVariants"
private let maximumChildOutputBytes = 64 * 1_024
private let childTimeout: DispatchTimeInterval = .seconds(15)

private enum ProbeError: String, Error {
  case invalidArguments = "invalid_arguments"
  case caseNotCompiled = "case_not_compiled"
  case childFailed = "child_failed"
  case identityWasAccepted = "identity_was_accepted"
  case authorityResponseInvalid = "authority_response_invalid"
  case authorityStateNotOff = "authority_state_not_off"
  case malformedMessageAccepted = "malformed_message_accepted"
  case processIdentityUnavailable = "process_identity_unavailable"
  case outputEncodingFailed = "output_encoding_failed"
}

private struct PhysicalPreconditionUnavailable: Error {
  let caseID: CaseID
  let fixtureID: String
}

private enum CaseID: String, CaseIterable {
  case baseline
  case authorityJournalSymlink = "authority-journal-symlink"
  case authorityJournalTamper = "authority-journal-tamper"
  case authorityJournalTruncation = "authority-journal-truncation"
  case deepMessage = "deep-message"
  case duplicateRedemption = "duplicate-redemption"
  case eventQueueSaturation = "event-queue-saturation"
  case fastUserSwitchingRace = "fast-user-switching-race"
  case heartbeatLoss = "heartbeat-loss"
  case inFlightSaturation = "in-flight-saturation"
  case inactiveConsoleUser = "inactive-console-user"
  case lateCallback = "late-callback"
  case noncanonicalMessage = "noncanonical-message"
  case oversizeMessage = "oversize-message"
  case replayCursorRollback = "replay-cursor-rollback"
  case replayedOperation = "replayed-operation"
  case replayedStartTicket = "replayed-start-ticket"
  case requestFlood = "request-flood"
  case sameTeamUnknownBundle = "same-team-unknown-bundle"
  case secretExtractionCrashRecords = "secret-extraction-crash-records"
  case secretExtractionEvidence = "secret-extraction-evidence"
  case secretExtractionJournal = "secret-extraction-journal"
  case secretExtractionLogs = "secret-extraction-logs"
  case secretExtractionPreferences = "secret-extraction-preferences"
  case secretExtractionSnapshots = "secret-extraction-snapshots"
  case staleAuditEvidence = "stale-audit-evidence"
  case stalePIDEvidence = "stale-pid-evidence"
  case wrongAuditSession = "wrong-audit-session"
  case wrongBundleIdentifier = "wrong-bundle-identifier"
  case wrongDesignatedRequirement = "wrong-designated-requirement"
  case wrongEntitlement = "wrong-entitlement"
  case wrongTeamID = "wrong-team-id"
  case wrongUID = "wrong-uid"

  var isRequirementVariant: Bool {
    switch self {
    case .wrongTeamID, .wrongBundleIdentifier, .wrongDesignatedRequirement,
      .wrongEntitlement, .sameTeamUnknownBundle:
      true
    default:
      false
    }
  }

  var isMalformedProtocolCase: Bool {
    switch self {
    case .oversizeMessage, .deepMessage, .noncanonicalMessage:
      true
    default:
      false
    }
  }

  /// Source-fixed fixture ownership for cases that cannot be synthesized by
  /// this signed process.  The Python collector independently checks this
  /// mapping before exposing a typed precondition failure to the operator.
  var unavailableFixtureID: String? {
    switch self {
    case .wrongUID:
      "root-owned-uid-launcher"
    case .wrongAuditSession, .staleAuditEvidence:
      "isolated-audit-session-controller"
    case .stalePIDEvidence:
      "pid-reuse-window-controller"
    case .inactiveConsoleUser:
      "isolated-console-session-controller"
    case .replayedOperation, .replayedStartTicket, .duplicateRedemption:
      "authority-operation-replay-controller"
    case .replayCursorRollback, .authorityJournalSymlink, .authorityJournalTamper,
      .authorityJournalTruncation:
      "root-owned-authority-journal-snapshot"
    case .requestFlood, .inFlightSaturation, .eventQueueSaturation:
      "bounded-authority-load-controller"
    case .heartbeatLoss, .lateCallback:
      "signed-owner-liveness-controller"
    case .fastUserSwitchingRace:
      "fast-user-switch-controller"
    case .secretExtractionCrashRecords, .secretExtractionEvidence,
      .secretExtractionJournal, .secretExtractionLogs,
      .secretExtractionPreferences, .secretExtractionSnapshots:
      "root-owned-secret-canary-scanner"
    case .baseline, .wrongTeamID, .wrongBundleIdentifier,
      .wrongDesignatedRequirement, .wrongEntitlement, .sameTeamUnknownBundle,
      .oversizeMessage, .deepMessage, .noncanonicalMessage:
      nil
    }
  }
}

private let compiledVariant: CaseID? = {
  #if CFW_ADVERSARIAL_WRONG_TEAM_ID
    .wrongTeamID
  #elseif CFW_ADVERSARIAL_WRONG_BUNDLE_IDENTIFIER
    .wrongBundleIdentifier
  #elseif CFW_ADVERSARIAL_WRONG_DESIGNATED_REQUIREMENT
    .wrongDesignatedRequirement
  #elseif CFW_ADVERSARIAL_WRONG_ENTITLEMENT
    .wrongEntitlement
  #elseif CFW_ADVERSARIAL_SAME_TEAM_UNKNOWN_BUNDLE
    .sameTeamUnknownBundle
  #else
    nil
  #endif
}()

private struct EmptyObject: Encodable {}

private struct ProcessObservation: Codable, Equatable {
  let pid: UInt32
  let startUnixMilliseconds: UInt64

  enum CodingKeys: String, CodingKey {
    case pid
    case startUnixMilliseconds = "start_unix_ms"
  }
}

private struct XPCBoundaryEvidence: Codable, Equatable {
  let connectionOutcome: String
  let transportErrorCode: String

  enum CodingKeys: String, CodingKey {
    case connectionOutcome = "connection_outcome"
    case transportErrorCode = "transport_error_code"
  }
}

private struct ChildResult: Codable {
  let schemaVersion: UInt16
  let document: String
  let caseID: String
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
  let connectionOutcome: String
  let transportErrorCode: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case caseID = "case_id"
    case requestSHA256 = "request_sha256"
    case process
    case effectiveUserIdentifier = "euid"
    case auditSessionIdentifier = "audit_session_id"
    case connectionOutcome = "connection_outcome"
    case transportErrorCode = "transport_error_code"
  }
}

private struct ProbeResult<Boundary: Encodable, Coverage: Encodable>: Encodable {
  let schemaVersion: UInt16
  let document: String
  let caseID: String
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
  let preStateSHA256: String
  let postStateSHA256: String
  let cleanupState: String
  let boundaryEvidence: Boundary
  let secretCoverage: Coverage
  let preResetStateSHA256: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case caseID = "case_id"
    case requestSHA256 = "request_sha256"
    case process
    case effectiveUserIdentifier = "euid"
    case auditSessionIdentifier = "audit_session_id"
    case preStateSHA256 = "pre_state_sha256"
    case postStateSHA256 = "post_state_sha256"
    case cleanupState = "cleanup_state"
    case boundaryEvidence = "boundary_evidence"
    case secretCoverage = "secret_coverage"
    case preResetStateSHA256 = "pre_reset_state_sha256"
  }
}

private struct ResetResult: Encodable {
  let schemaVersion: UInt16
  let document: String
  let caseID: String
  let postResetStateSHA256: String
  let cleanupState: String
  let contaminationDetected: Bool

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case caseID = "case_id"
    case postResetStateSHA256 = "post_reset_state_sha256"
    case cleanupState = "cleanup_state"
    case contaminationDetected = "contamination_detected"
  }
}

private struct PreconditionFailure: Encodable {
  let schemaVersion: UInt16
  let document: String
  let code: String
  let caseID: String
  let fixtureID: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case code
    case caseID = "case_id"
    case fixtureID = "fixture_id"
  }
}

private struct SnapshotObservation {
  let snapshot: AuthoritySnapshot
  let request: Data

  var stateSHA256: String {
    get throws {
      try ReleaseObservationLogger.authorityStateSHA256(
        state: snapshot.state,
        revision: snapshot.revision,
        leaseOwnerUID: snapshot.leaseView?.operation.ownerUID)
    }
  }
}

private struct AuthoritySession {
  let remote = NSXPCGlobalAuthorityRemote(role: .host, timeout: .seconds(5))

  func snapshot() async throws -> SnapshotObservation {
    let handshakeID = AuthorityIdentifier(UUID())
    let handshake = try AuthorityRequestEnvelope(
      requestID: handshakeID,
      command: .handshake(HandshakeRequest(version: try AuthorityProtocolVersion())))
    let handshakeData = try AuthorityV1Codec.encode(handshake)
    let handshakeReply = try await remote.call(
      method: .handshake,
      request: handshakeData,
      configuration: nil,
      secretPayload: nil)
    let decodedHandshake = try AuthorityV1Codec.decodeResponse(
      HandshakeResponse.self, from: handshakeReply.response)
    guard decodedHandshake.requestID == handshakeID,
      decodedHandshake.operationID == nil,
      decodedHandshake.result == (try HandshakeResponse.v1())
    else { throw ProbeError.authorityResponseInvalid }

    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .snapshot(SnapshotRequest()))
    let request = try AuthorityV1Codec.encode(envelope)
    let reply = try await remote.call(
      method: .snapshot,
      request: request,
      configuration: nil,
      secretPayload: nil)
    let decoded = try AuthorityV1Codec.decodeResponse(
      AuthoritySnapshot.self, from: reply.response)
    guard decoded.requestID == requestID, decoded.operationID == nil else {
      throw ProbeError.authorityResponseInvalid
    }
    await remote.invalidate()
    return SnapshotObservation(snapshot: decoded.result, request: request)
  }
}

private func processObservation() throws -> ProcessObservation {
  let pid = getpid()
  guard pid > 0 else { throw ProbeError.processIdentityUnavailable }
  var info = proc_bsdinfo()
  let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
  let observed = withUnsafeMutablePointer(to: &info) { pointer in
    proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, expected)
  }
  guard observed == expected else { throw ProbeError.processIdentityUnavailable }
  let (seconds, firstOverflow) = info.pbi_start_tvsec.multipliedReportingOverflow(by: 1_000)
  let (milliseconds, secondOverflow) = seconds.addingReportingOverflow(
    info.pbi_start_tvusec / 1_000)
  guard !firstOverflow, !secondOverflow else {
    throw ProbeError.processIdentityUnavailable
  }
  return ProcessObservation(
    pid: UInt32(bitPattern: pid), startUnixMilliseconds: milliseconds)
}

private func sha256(_ data: Data) -> String {
  SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func writeCanonical<T: Encodable>(_ value: T) throws {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let data = try encoder.encode(value)
  guard data.count <= maximumChildOutputBytes else { throw ProbeError.outputEncodingFailed }
  FileHandle.standardOutput.write(data)
  FileHandle.standardOutput.write(Data([0x0A]))
}

private func runIdentityChild(_ caseID: CaseID) throws -> ChildResult {
  let path = URL(
    fileURLWithPath: variantRoot, isDirectory: true
  ).appendingPathComponent(caseID.rawValue, isDirectory: true)
    .appendingPathComponent("CFWAdversarialProbe", isDirectory: false)
  let process = Process()
  process.executableURL = path
  process.arguments = ["peer", caseID.rawValue]
  process.environment = [
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
  ]
  let output = Pipe()
  let errors = Pipe()
  process.standardInput = FileHandle.nullDevice
  process.standardOutput = output
  process.standardError = errors
  let finished = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in finished.signal() }
  try process.run()
  guard finished.wait(timeout: .now() + childTimeout) == .success else {
    process.terminate()
    if finished.wait(timeout: .now() + .seconds(1)) != .success {
      guard kill(process.processIdentifier, SIGKILL) == 0,
        finished.wait(timeout: .now() + .seconds(1)) == .success
      else { throw ProbeError.childFailed }
    }
    throw ProbeError.childFailed
  }
  let data = output.fileHandleForReading.readDataToEndOfFile()
  let errorData = errors.fileHandleForReading.readDataToEndOfFile()
  guard process.terminationStatus == 0,
    data.count <= maximumChildOutputBytes,
    errorData.isEmpty
  else { throw ProbeError.childFailed }
  return try JSONDecoder().decode(ChildResult.self, from: data)
}

private func executeIdentityVariant(_ caseID: CaseID) async throws {
  guard compiledVariant == caseID else { throw ProbeError.caseNotCompiled }
  let process = try processObservation()
  let requestID = AuthorityIdentifier(UUID())
  let envelope = try AuthorityRequestEnvelope(
    requestID: requestID,
    command: .handshake(HandshakeRequest(version: try AuthorityProtocolVersion())))
  let request = try AuthorityV1Codec.encode(envelope)
  let remote = NSXPCGlobalAuthorityRemote(role: .host, timeout: .seconds(5))
  let transportErrorCode: AuthorityErrorCode
  do {
    _ = try await remote.call(
      method: .handshake,
      request: request,
      configuration: nil,
      secretPayload: nil)
    await remote.invalidate()
    throw ProbeError.identityWasAccepted
  } catch let error as AuthorityDomainError {
    await remote.invalidate()
    guard error.code == .globalAuthorityInterrupted else { throw error }
    transportErrorCode = error.code
  }
  try writeCanonical(
    ChildResult(
      schemaVersion: 1,
      document: childDocument,
      caseID: caseID.rawValue,
      requestSHA256: sha256(request),
      process: process,
      effectiveUserIdentifier: UInt32(geteuid()),
      auditSessionIdentifier: audit_session_self(),
      connectionOutcome: "invalidated_before_export",
      transportErrorCode: transportErrorCode.rawValue))
}

private func executeBaseline() async throws {
  let observation = try await AuthoritySession().snapshot()
  guard observation.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  let state = try observation.stateSHA256
  try writeCanonical(
    ProbeResult(
      schemaVersion: 1,
      document: probeDocument,
      caseID: CaseID.baseline.rawValue,
      requestSHA256: sha256(observation.request),
      process: try processObservation(),
      effectiveUserIdentifier: UInt32(geteuid()),
      auditSessionIdentifier: audit_session_self(),
      preStateSHA256: state,
      postStateSHA256: state,
      cleanupState: AuthorityState.off.rawValue,
      boundaryEvidence: EmptyObject(),
      secretCoverage: EmptyObject(),
      preResetStateSHA256: ""))
}

private func executeRequirementCase(_ caseID: CaseID) async throws {
  let before = try await AuthoritySession().snapshot()
  guard before.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  let child = try runIdentityChild(caseID)
  guard child.schemaVersion == 1,
    child.document == childDocument,
    child.caseID == caseID.rawValue,
    child.connectionOutcome == "invalidated_before_export",
    child.transportErrorCode == AuthorityErrorCode.globalAuthorityInterrupted.rawValue
  else { throw ProbeError.childFailed }
  let after = try await AuthoritySession().snapshot()
  guard after.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  try writeCanonical(
    ProbeResult(
      schemaVersion: 1,
      document: probeDocument,
      caseID: caseID.rawValue,
      requestSHA256: child.requestSHA256,
      process: child.process,
      effectiveUserIdentifier: child.effectiveUserIdentifier,
      auditSessionIdentifier: child.auditSessionIdentifier,
      preStateSHA256: try before.stateSHA256,
      postStateSHA256: try after.stateSHA256,
      cleanupState: AuthorityState.off.rawValue,
      boundaryEvidence: XPCBoundaryEvidence(
        connectionOutcome: child.connectionOutcome,
        transportErrorCode: child.transportErrorCode),
      secretCoverage: EmptyObject(),
      preResetStateSHA256: ""))
}

private func malformedProtocolRequest(_ caseID: CaseID) throws -> Data {
  switch caseID {
  case .oversizeMessage:
    return Data(repeating: 0x20, count: AuthorityV1Limits.maximumEnvelopeBytes + 1)
  case .deepMessage:
    let requestID = UUID().uuidString.lowercased()
    let nesting = AuthorityV1Codec.maximumNestingDepth + 1
    let prefix =
      "{\"command\":{\"kind\":\"snapshot\",\"payload\":{\"nested\":"
      + String(repeating: "[", count: nesting)
    let suffix =
      String(repeating: "]", count: nesting)
      + "}},\"major\":1,\"minor\":\(AuthorityV1Limits.minor),\"request_id\":\"\(requestID)\","
      + "\"required_feature_bits\":0}"
    guard let data = (prefix + suffix).data(using: .utf8),
      data.count <= AuthorityV1Limits.maximumEnvelopeBytes
    else { throw ProbeError.outputEncodingFailed }
    return data
  case .noncanonicalMessage:
    let request = try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest()))
    var data = try AuthorityV1Codec.encode(request)
    data.append(0x0A)
    return data
  default:
    throw ProbeError.invalidArguments
  }
}

private func executeMalformedProtocolCase(_ caseID: CaseID) async throws {
  let before = try await AuthoritySession().snapshot()
  guard before.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  let request = try malformedProtocolRequest(caseID)
  let remote = NSXPCGlobalAuthorityRemote(role: .host, timeout: .seconds(5))
  do {
    _ = try await remote.call(
      method: .snapshot,
      request: request,
      configuration: nil,
      secretPayload: nil)
    await remote.invalidate()
    throw ProbeError.malformedMessageAccepted
  } catch let error as AuthorityDomainError {
    await remote.invalidate()
    guard error.code == .invalidMessage else { throw error }
  }
  let after = try await AuthoritySession().snapshot()
  guard after.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  try writeCanonical(
    ProbeResult(
      schemaVersion: 1,
      document: probeDocument,
      caseID: caseID.rawValue,
      requestSHA256: sha256(request),
      process: try processObservation(),
      effectiveUserIdentifier: UInt32(geteuid()),
      auditSessionIdentifier: audit_session_self(),
      preStateSHA256: try before.stateSHA256,
      postStateSHA256: try after.stateSHA256,
      cleanupState: AuthorityState.off.rawValue,
      boundaryEvidence: EmptyObject(),
      secretCoverage: EmptyObject(),
      preResetStateSHA256: ""))
}

private func execute(_ caseID: CaseID) async throws {
  if caseID == .baseline {
    try await executeBaseline()
  } else if caseID.isRequirementVariant {
    try await executeRequirementCase(caseID)
  } else if caseID.isMalformedProtocolCase {
    try await executeMalformedProtocolCase(caseID)
  } else if let fixtureID = caseID.unavailableFixtureID {
    throw PhysicalPreconditionUnavailable(caseID: caseID, fixtureID: fixtureID)
  } else {
    throw ProbeError.caseNotCompiled
  }
}

private func reset(_ caseID: CaseID) async throws {
  let observation = try await AuthoritySession().snapshot()
  guard observation.snapshot.state == .off else { throw ProbeError.authorityStateNotOff }
  try writeCanonical(
    ResetResult(
      schemaVersion: 1,
      document: resetDocument,
      caseID: caseID.rawValue,
      postResetStateSHA256: try observation.stateSHA256,
      cleanupState: AuthorityState.off.rawValue,
      contaminationDetected: false))
}

@main
private enum Main {
  static func main() async {
    do {
      let arguments = CommandLine.arguments
      guard arguments.count == 3, let caseID = CaseID(rawValue: arguments[2]) else {
        throw ProbeError.invalidArguments
      }
      switch arguments[1] {
      case "execute":
        guard compiledVariant == nil else { throw ProbeError.invalidArguments }
        try await execute(caseID)
      case "peer":
        try await executeIdentityVariant(caseID)
      case "reset":
        guard compiledVariant == nil else { throw ProbeError.invalidArguments }
        try await reset(caseID)
      default:
        throw ProbeError.invalidArguments
      }
    } catch let error as PhysicalPreconditionUnavailable {
      do {
        try writeCanonical(
          PreconditionFailure(
            schemaVersion: 1,
            document: preconditionDocument,
            code: "physical_precondition_unavailable",
            caseID: error.caseID.rawValue,
            fixtureID: error.fixtureID))
        exit(EX_UNAVAILABLE)
      } catch {
        FileHandle.standardError.write(Data("precondition_encoding_failed\n".utf8))
        exit(EX_SOFTWARE)
      }
    } catch let error as ProbeError {
      FileHandle.standardError.write(Data((error.rawValue + "\n").utf8))
      exit(EX_SOFTWARE)
    } catch {
      FileHandle.standardError.write(Data("probe_failed\n".utf8))
      exit(EX_SOFTWARE)
    }
  }
}
