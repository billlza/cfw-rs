import CryptoKit
import Darwin
import Foundation
import OSLog

public enum ReleaseObservationError: Error, Equatable, Sendable {
  case invalidCandidate
  case invalidProcessIdentity
  case invalidSequence
  case encodingFailed
  case messageTooLarge
}

public enum ReleaseObservationOutcome: String, Codable, Sendable {
  case accepted
  case busy
  case cleanupUnproven = "cleanup_unproven"
  case compensationConflict = "compensation_conflict"
  case globalAuthorityApprovalRequired = "global_authority_approval_required"
  case globalAuthorityIdentityRejected = "global_authority_identity_rejected"
  case globalAuthorityInterrupted = "global_authority_interrupted"
  case globalAuthorityProtocolMismatch = "global_authority_protocol_mismatch"
  case globalAuthorityRecovering = "global_authority_recovering"
  case globalAuthorityRegistrationRequired = "global_authority_registration_required"
  case globalAuthorityTimeout = "global_authority_timeout"
  case globalAuthorityUnavailable = "global_authority_unavailable"
  case globalLeaseConflict = "global_lease_conflict"
  case invalidMessage = "invalid_message"
  case journalCapacityExhausted = "journal_capacity_exhausted"
  case journalCorrupt = "journal_corrupt"
  case ownerUnresponsive = "owner_unresponsive"
  case quarantined
  case replayRejected = "replay_rejected"
  case resourceExhausted = "resource_exhausted"
  case secretAbsent = "secret_absent"
  case secretBoundsExceeded = "secret_bounds_exceeded"
  case secretLifecycleViolation = "secret_lifecycle_violation"
  case staleOperation = "stale_operation"
  case ticketExpired = "ticket_expired"
  case ticketAlreadyRedeemed = "ticket_already_redeemed"
  case ticketInvalid = "ticket_invalid"

  public init(authorityErrorCode: AuthorityErrorCode) throws {
    guard let value = Self(rawValue: authorityErrorCode.rawValue) else {
      throw ReleaseObservationError.encodingFailed
    }
    self = value
  }
}

public struct ReleaseObservationAuthenticatedDecision: Codable, Equatable, Sendable {
  public let role: AuthorityRole
  public let peerPID: Int32
  public let effectiveUserIdentifier: UInt32
  public let auditSessionIdentifier: UInt32
  public let connectionIdentitySHA256: String
  public let requestSHA256: String
  public let accepted: Bool
  public let actualCode: ReleaseObservationOutcome
  public let preStateSHA256: String
  public let postStateSHA256: String
  public let cleanupState: AuthorityState

  public init(
    role: AuthorityRole,
    peerPID: Int32,
    effectiveUserIdentifier: UInt32,
    auditSessionIdentifier: UInt32,
    connectionIdentitySHA256: String,
    requestSHA256: String,
    accepted: Bool,
    actualCode: ReleaseObservationOutcome,
    preStateSHA256: String,
    postStateSHA256: String,
    cleanupState: AuthorityState
  ) throws {
    guard peerPID > 0,
      Self.isSHA256(connectionIdentitySHA256), Self.isSHA256(requestSHA256),
      Self.isSHA256(preStateSHA256), Self.isSHA256(postStateSHA256),
      accepted == (actualCode == .accepted)
    else { throw ReleaseObservationError.encodingFailed }
    self.role = role
    self.peerPID = peerPID
    self.effectiveUserIdentifier = effectiveUserIdentifier
    self.auditSessionIdentifier = auditSessionIdentifier
    self.connectionIdentitySHA256 = connectionIdentitySHA256
    self.requestSHA256 = requestSHA256
    self.accepted = accepted
    self.actualCode = actualCode
    self.preStateSHA256 = preStateSHA256
    self.postStateSHA256 = postStateSHA256
    self.cleanupState = cleanupState
  }

  private static func isSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
          || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0)
      }
  }

  enum CodingKeys: String, CodingKey {
    case role
    case peerPID = "peer_pid"
    case effectiveUserIdentifier = "euid"
    case auditSessionIdentifier = "audit_session_id"
    case connectionIdentitySHA256 = "connection_identity_sha256"
    case requestSHA256 = "request_sha256"
    case accepted
    case actualCode = "actual_code"
    case preStateSHA256 = "pre_state_sha256"
    case postStateSHA256 = "post_state_sha256"
    case cleanupState = "cleanup_state"
  }
}

public struct ReleaseObservationJournalDecision: Codable, Equatable, Sendable {
  public let journalInputSHA256: String
  public let actualCode: ReleaseObservationOutcome
  public let preStateSHA256: String
  public let postStateSHA256: String
  public let cleanupState: AuthorityState

  public init(
    journalInputSHA256: String,
    actualCode: ReleaseObservationOutcome,
    preStateSHA256: String,
    postStateSHA256: String,
    cleanupState: AuthorityState
  ) throws {
    guard actualCode == .journalCorrupt,
      Self.isSHA256(journalInputSHA256), Self.isSHA256(preStateSHA256),
      Self.isSHA256(postStateSHA256), cleanupState == .quarantined
    else { throw ReleaseObservationError.encodingFailed }
    self.journalInputSHA256 = journalInputSHA256
    self.actualCode = actualCode
    self.preStateSHA256 = preStateSHA256
    self.postStateSHA256 = postStateSHA256
    self.cleanupState = cleanupState
  }

  private static func isSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
          || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0)
      }
  }

  enum CodingKeys: String, CodingKey {
    case journalInputSHA256 = "journal_input_sha256"
    case actualCode = "actual_code"
    case preStateSHA256 = "pre_state_sha256"
    case postStateSHA256 = "post_state_sha256"
    case cleanupState = "cleanup_state"
  }
}

public struct ReleaseObservationCandidate: Codable, Equatable, Sendable {
  public let version: String
  public let buildNumber: String

  public init(version: String, buildNumber: String) throws {
    guard version == "0.4.0",
      !buildNumber.isEmpty, buildNumber.count <= 18,
      buildNumber.first != "0",
      buildNumber.utf8.allSatisfy({
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
      })
    else { throw ReleaseObservationError.invalidCandidate }
    self.version = version
    self.buildNumber = buildNumber
  }

  enum CodingKeys: String, CodingKey {
    case version
    case buildNumber = "build_number"
  }
}

public struct ReleaseObservationProcess: Codable, Equatable, Sendable {
  public let pid: UInt32
  public let startUnixMilliseconds: UInt64

  public init(pid: UInt32, startUnixMilliseconds: UInt64) throws {
    guard pid > 0, startUnixMilliseconds > 0 else {
      throw ReleaseObservationError.invalidProcessIdentity
    }
    self.pid = pid
    self.startUnixMilliseconds = startUnixMilliseconds
  }

  enum CodingKeys: String, CodingKey {
    case pid
    case startUnixMilliseconds = "start_unix_ms"
  }
}

/// A listener admission observation contains only kernel-populated public
/// identity attributes and the Authority's stable decision. Signing Team,
/// bundle and entitlement evidence remains the collector's independent
/// codesign assessment; raw audit tokens are never logged.
public struct ReleaseObservationPeerDecision: Codable, Equatable, Sendable {
  public let role: AuthorityRole
  public let peerPID: Int32
  public let effectiveUserIdentifier: UInt32
  public let auditSessionIdentifier: UInt32
  public let connectionIdentitySHA256: String?
  public let accepted: Bool
  public let actualCode: ReleaseObservationOutcome
  public let preStateSHA256: String
  public let postStateSHA256: String
  public let cleanupState: AuthorityState

  public init(
    role: AuthorityRole,
    peerPID: Int32,
    effectiveUserIdentifier: UInt32,
    auditSessionIdentifier: UInt32,
    connectionIdentitySHA256: String?,
    accepted: Bool,
    actualCode: ReleaseObservationOutcome,
    preStateSHA256: String,
    postStateSHA256: String,
    cleanupState: AuthorityState
  ) throws {
    guard peerPID > 0,
      Self.isSHA256(preStateSHA256), Self.isSHA256(postStateSHA256),
      connectionIdentitySHA256.map(Self.isSHA256) ?? true,
      accepted == (actualCode == .accepted),
      accepted == (connectionIdentitySHA256 != nil)
    else { throw ReleaseObservationError.encodingFailed }
    self.role = role
    self.peerPID = peerPID
    self.effectiveUserIdentifier = effectiveUserIdentifier
    self.auditSessionIdentifier = auditSessionIdentifier
    self.connectionIdentitySHA256 = connectionIdentitySHA256
    self.accepted = accepted
    self.actualCode = actualCode
    self.preStateSHA256 = preStateSHA256
    self.postStateSHA256 = postStateSHA256
    self.cleanupState = cleanupState
  }

  private static func isSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
          || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains($0)
      }
  }

  enum CodingKeys: String, CodingKey {
    case role
    case peerPID = "peer_pid"
    case effectiveUserIdentifier = "euid"
    case auditSessionIdentifier = "audit_session_id"
    case connectionIdentitySHA256 = "connection_identity_sha256"
    case accepted
    case actualCode = "actual_code"
    case preStateSHA256 = "pre_state_sha256"
    case postStateSHA256 = "post_state_sha256"
    case cleanupState = "cleanup_state"
  }
}

private struct ReleaseObservationEnvelope<Payload: Encodable & Sendable>: Encodable, Sendable {
  let schemaVersion: UInt16
  let document: String
  let component: String
  let event: String
  let sequence: UInt64
  let recordedUnixMilliseconds: UInt64
  let process: ReleaseObservationProcess
  let candidate: ReleaseObservationCandidate
  let payload: Payload

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document, component, event, sequence
    case recordedUnixMilliseconds = "recorded_unix_ms"
    case process, candidate, payload
  }
}

private final class ReleaseObservationRuntime: @unchecked Sendable {
  private let lock = NSLock()
  private var sequence: UInt64 = 0
  let candidate: Result<ReleaseObservationCandidate, Error>
  let process: Result<ReleaseObservationProcess, Error>

  init(bundle: Bundle = .main) {
    candidate = Result {
      guard
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
      else { throw ReleaseObservationError.invalidCandidate }
      return try ReleaseObservationCandidate(version: version, buildNumber: build)
    }
    process = Result { try Self.currentProcess() }
  }

  func nextSequence() throws -> UInt64 {
    try lock.withLock {
      let (next, overflow) = sequence.addingReportingOverflow(1)
      guard !overflow, next > 0 else { throw ReleaseObservationError.invalidSequence }
      sequence = next
      return next
    }
  }

  private static func currentProcess() throws -> ReleaseObservationProcess {
    let pid = getpid()
    guard pid > 0 else { throw ReleaseObservationError.invalidProcessIdentity }
    var info = proc_bsdinfo()
    let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
    let observed = withUnsafeMutablePointer(to: &info) { pointer in
      proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, expected)
    }
    guard observed == expected else { throw ReleaseObservationError.invalidProcessIdentity }
    let (seconds, secondsOverflow) = info.pbi_start_tvsec.multipliedReportingOverflow(by: 1_000)
    let (milliseconds, millisecondsOverflow) = seconds.addingReportingOverflow(
      info.pbi_start_tvusec / 1_000)
    guard !secondsOverflow, !millisecondsOverflow else {
      throw ReleaseObservationError.invalidProcessIdentity
    }
    return try ReleaseObservationProcess(
      pid: UInt32(bitPattern: pid),
      startUnixMilliseconds: milliseconds)
  }
}

public enum ReleaseObservationLogger {
  public static let subsystem = "com.bill.clashformac"
  public static let category = "release-observation"
  public static let messagePrefix = "cfw-release-observation-v1 "
  public static let document = "cfw-product-observation-event-v1"
  public static let maximumMessageBytes = 8 * 1_024

  private static let logger = Logger(subsystem: subsystem, category: category)
  private static let runtime = ReleaseObservationRuntime()

  public static func emitAuthorityPeerDecision(
    _ payload: ReleaseObservationPeerDecision
  ) throws {
    try emit(payload, event: "peer_authorization_decision")
  }

  public static func emitAuthorityOperationDecision(
    _ payload: ReleaseObservationAuthenticatedDecision
  ) throws {
    try emit(payload, event: "operation_decision")
  }

  public static func emitAuthorityLeaseLivenessDecision(
    _ payload: ReleaseObservationAuthenticatedDecision
  ) throws {
    try emit(payload, event: "lease_liveness_decision")
  }

  public static func emitAuthorityJournalDecision(
    _ payload: ReleaseObservationJournalDecision
  ) throws {
    try emit(payload, event: "journal_integrity_decision")
  }

  private static func emit<Payload: Encodable & Sendable>(
    _ payload: Payload,
    event: String
  ) throws {
    let candidate = try runtime.candidate.get()
    let process = try runtime.process.get()
    let sequence = try runtime.nextSequence()
    let timestamp = try currentUnixMilliseconds()
    let message = try encode(
      payload,
      event: event,
      candidate: candidate,
      process: process,
      sequence: sequence,
      recordedUnixMilliseconds: timestamp)
    logger.info("\(message, privacy: .public)")
  }

  public static func authorityStateSHA256(
    state: AuthorityState,
    revision: UInt64,
    leaseOwnerUID: UInt32?
  ) throws -> String {
    struct State: Encodable {
      let state: AuthorityState
      let revision: UInt64
      let leaseOwnerUID: UInt32?

      enum CodingKeys: String, CodingKey {
        case state, revision
        case leaseOwnerUID = "lease_owner_uid"
      }
    }
    let data = try sortedJSON(State(state: state, revision: revision, leaseOwnerUID: leaseOwnerUID))
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  static func encodeAuthorityPeerDecision(
    _ payload: ReleaseObservationPeerDecision,
    candidate: ReleaseObservationCandidate,
    process: ReleaseObservationProcess,
    sequence: UInt64,
    recordedUnixMilliseconds: UInt64
  ) throws -> String {
    try encode(
      payload,
      event: "peer_authorization_decision",
      candidate: candidate,
      process: process,
      sequence: sequence,
      recordedUnixMilliseconds: recordedUnixMilliseconds)
  }

  static func encodeAuthorityOperationDecision(
    _ payload: ReleaseObservationAuthenticatedDecision,
    candidate: ReleaseObservationCandidate,
    process: ReleaseObservationProcess,
    sequence: UInt64,
    recordedUnixMilliseconds: UInt64
  ) throws -> String {
    try encode(
      payload,
      event: "operation_decision",
      candidate: candidate,
      process: process,
      sequence: sequence,
      recordedUnixMilliseconds: recordedUnixMilliseconds)
  }

  static func encodeAuthorityLeaseLivenessDecision(
    _ payload: ReleaseObservationAuthenticatedDecision,
    candidate: ReleaseObservationCandidate,
    process: ReleaseObservationProcess,
    sequence: UInt64,
    recordedUnixMilliseconds: UInt64
  ) throws -> String {
    try encode(
      payload,
      event: "lease_liveness_decision",
      candidate: candidate,
      process: process,
      sequence: sequence,
      recordedUnixMilliseconds: recordedUnixMilliseconds)
  }

  static func encodeAuthorityJournalDecision(
    _ payload: ReleaseObservationJournalDecision,
    candidate: ReleaseObservationCandidate,
    process: ReleaseObservationProcess,
    sequence: UInt64,
    recordedUnixMilliseconds: UInt64
  ) throws -> String {
    try encode(
      payload,
      event: "journal_integrity_decision",
      candidate: candidate,
      process: process,
      sequence: sequence,
      recordedUnixMilliseconds: recordedUnixMilliseconds)
  }

  private static func encode<Payload: Encodable & Sendable>(
    _ payload: Payload,
    event: String,
    candidate: ReleaseObservationCandidate,
    process: ReleaseObservationProcess,
    sequence: UInt64,
    recordedUnixMilliseconds: UInt64
  ) throws -> String {
    guard sequence > 0, recordedUnixMilliseconds > 0 else {
      throw ReleaseObservationError.invalidSequence
    }
    let envelope = ReleaseObservationEnvelope(
      schemaVersion: 1,
      document: document,
      component: "global_authority",
      event: event,
      sequence: sequence,
      recordedUnixMilliseconds: recordedUnixMilliseconds,
      process: process,
      candidate: candidate,
      payload: payload)
    let data = try sortedJSON(envelope)
    guard data.count + messagePrefix.utf8.count <= maximumMessageBytes else {
      throw ReleaseObservationError.messageTooLarge
    }
    guard let encoded = String(data: data, encoding: .utf8) else {
      throw ReleaseObservationError.encodingFailed
    }
    return messagePrefix + encoded
  }

  private static func sortedJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do {
      return try encoder.encode(value)
    } catch {
      throw ReleaseObservationError.encodingFailed
    }
  }

  private static func currentUnixMilliseconds() throws -> UInt64 {
    let interval = Date().timeIntervalSince1970
    guard interval.isFinite, interval > 0,
      interval <= Double(UInt64.max) / 1_000
    else { throw ReleaseObservationError.encodingFailed }
    return UInt64(interval * 1_000)
  }
}
