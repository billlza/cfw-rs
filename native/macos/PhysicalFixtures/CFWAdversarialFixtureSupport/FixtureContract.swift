import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation

public enum ExternalFixtureID: String, Sendable {
  case authorityOperationReplay = "authority-operation-replay-controller"
  case boundedAuthorityLoad = "bounded-authority-load-controller"
  case fastUserSwitch = "fast-user-switch-controller"
  case isolatedAuditSession = "isolated-audit-session-controller"
  case isolatedConsoleSession = "isolated-console-session-controller"
  case pidReuseWindow = "pid-reuse-window-controller"
  case rootOwnedAuthorityJournalSnapshot = "root-owned-authority-journal-snapshot"
  case rootOwnedSecretCanaryScanner = "root-owned-secret-canary-scanner"
  case rootOwnedUIDLauncher = "root-owned-uid-launcher"
  case signedOwnerLiveness = "signed-owner-liveness-controller"
}

public enum ExternalCaseID: String, CaseIterable, Sendable {
  case authorityJournalSymlink = "authority-journal-symlink"
  case authorityJournalTamper = "authority-journal-tamper"
  case authorityJournalTruncation = "authority-journal-truncation"
  case duplicateRedemption = "duplicate-redemption"
  case eventQueueSaturation = "event-queue-saturation"
  case fastUserSwitchingRace = "fast-user-switching-race"
  case heartbeatLoss = "heartbeat-loss"
  case inFlightSaturation = "in-flight-saturation"
  case inactiveConsoleUser = "inactive-console-user"
  case lateCallback = "late-callback"
  case replayCursorRollback = "replay-cursor-rollback"
  case replayedOperation = "replayed-operation"
  case replayedStartTicket = "replayed-start-ticket"
  case requestFlood = "request-flood"
  case secretExtractionCrashRecords = "secret-extraction-crash-records"
  case secretExtractionEvidence = "secret-extraction-evidence"
  case secretExtractionJournal = "secret-extraction-journal"
  case secretExtractionLogs = "secret-extraction-logs"
  case secretExtractionPreferences = "secret-extraction-preferences"
  case secretExtractionSnapshots = "secret-extraction-snapshots"
  case staleAuditEvidence = "stale-audit-evidence"
  case stalePIDEvidence = "stale-pid-evidence"
  case wrongAuditSession = "wrong-audit-session"
  case wrongUID = "wrong-uid"

  public var fixtureID: ExternalFixtureID {
    switch self {
    case .wrongUID:
      .rootOwnedUIDLauncher
    case .wrongAuditSession, .staleAuditEvidence:
      .isolatedAuditSession
    case .stalePIDEvidence:
      .pidReuseWindow
    case .inactiveConsoleUser:
      .isolatedConsoleSession
    case .replayedOperation, .replayedStartTicket, .duplicateRedemption:
      .authorityOperationReplay
    case .replayCursorRollback, .authorityJournalTruncation, .authorityJournalTamper,
      .authorityJournalSymlink:
      .rootOwnedAuthorityJournalSnapshot
    case .requestFlood, .inFlightSaturation, .eventQueueSaturation:
      .boundedAuthorityLoad
    case .heartbeatLoss, .lateCallback:
      .signedOwnerLiveness
    case .fastUserSwitchingRace:
      .fastUserSwitch
    case .secretExtractionLogs, .secretExtractionPreferences,
      .secretExtractionJournal, .secretExtractionCrashRecords,
      .secretExtractionSnapshots, .secretExtractionEvidence:
      .rootOwnedSecretCanaryScanner
    }
  }

  public var resetRequired: Bool {
    switch fixtureID {
    case .rootOwnedUIDLauncher, .isolatedAuditSession, .isolatedConsoleSession,
      .pidReuseWindow, .rootOwnedAuthorityJournalSnapshot, .rootOwnedSecretCanaryScanner,
      .fastUserSwitch:
      true
    case .authorityOperationReplay, .boundedAuthorityLoad, .signedOwnerLiveness:
      false
    }
  }

  var cleanupState: AuthorityState {
    switch self {
    case .replayCursorRollback, .authorityJournalTruncation, .authorityJournalTamper,
      .authorityJournalSymlink:
      .quarantined
    default:
      .off
    }
  }

  var secretSurface: String? {
    switch self {
    case .secretExtractionLogs: "unified-logs"
    case .secretExtractionPreferences: "preferences"
    case .secretExtractionJournal: "authority-journal"
    case .secretExtractionCrashRecords: "crash-records"
    case .secretExtractionSnapshots: "authority-snapshots"
    case .secretExtractionEvidence: "release-evidence"
    default: nil
    }
  }
}

struct ProcessObservation: Codable, Equatable, Sendable {
  let pid: UInt32
  let startUnixMilliseconds: UInt64

  enum CodingKeys: String, CodingKey {
    case pid
    case startUnixMilliseconds = "start_unix_ms"
  }
}

struct IdentityFreshnessEvidence: Codable, Equatable, Sendable {
  let capturedPID: UInt32
  let capturedStartUnixMilliseconds: UInt64
  let currentPID: UInt32
  let currentStartUnixMilliseconds: UInt64
  let capturedAuditSessionID: UInt32
  let currentAuditSessionID: UInt32

  enum CodingKeys: String, CodingKey {
    case capturedPID = "captured_pid"
    case capturedStartUnixMilliseconds = "captured_start_unix_ms"
    case currentPID = "current_pid"
    case currentStartUnixMilliseconds = "current_start_unix_ms"
    case capturedAuditSessionID = "captured_audit_session_id"
    case currentAuditSessionID = "current_audit_session_id"
  }
}

struct EmptyObject: Codable, Equatable, Sendable {}

enum BoundaryEvidence: Encodable, Sendable {
  case empty
  case freshness(IdentityFreshnessEvidence)

  func encode(to encoder: Encoder) throws {
    switch self {
    case .empty:
      try EmptyObject().encode(to: encoder)
    case .freshness(let value):
      try value.encode(to: encoder)
    }
  }
}

struct SecretCoverageEntry: Codable, Equatable, Sendable {
  let locationSHA256: String
  let contentSHA256: String
  let scannedBytes: UInt64
  let matchCount: UInt64

  enum CodingKeys: String, CodingKey {
    case locationSHA256 = "location_sha256"
    case contentSHA256 = "content_sha256"
    case scannedBytes = "scanned_bytes"
    case matchCount = "match_count"
  }
}

struct SecretCoverage: Codable, Equatable, Sendable {
  let schemaVersion: UInt16
  let document: String
  let caseID: String
  let surface: String
  let canarySHA256: String
  let startedAt: String
  let finishedAt: String
  let enumerationComplete: Bool
  let unreadableCount: UInt32
  let excludedCount: UInt32
  let entryCount: UInt32
  let totalScannedBytes: UInt64
  let totalMatchCount: UInt64
  let entries: [SecretCoverageEntry]

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case caseID = "case_id"
    case surface
    case canarySHA256 = "canary_sha256"
    case startedAt = "started_at"
    case finishedAt = "finished_at"
    case enumerationComplete = "enumeration_complete"
    case unreadableCount = "unreadable_count"
    case excludedCount = "excluded_count"
    case entryCount = "entry_count"
    case totalScannedBytes = "total_scanned_bytes"
    case totalMatchCount = "total_match_count"
    case entries
  }
}

enum SecretCoverageValue: Encodable, Sendable {
  case empty
  case coverage(SecretCoverage)

  func encode(to encoder: Encoder) throws {
    switch self {
    case .empty:
      try EmptyObject().encode(to: encoder)
    case .coverage(let value):
      try value.encode(to: encoder)
    }
  }
}

struct ProbeResult: Encodable, Sendable {
  let schemaVersion: UInt16 = 1
  let document = "cfw-adversarial-probe-result-v1"
  let caseID: String
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
  let preStateSHA256: String
  let postStateSHA256: String
  let cleanupState: String
  let boundaryEvidence: BoundaryEvidence
  let secretCoverage: SecretCoverageValue
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

struct ResetResult: Encodable, Sendable {
  let schemaVersion: UInt16 = 1
  let document = "cfw-adversarial-reset-result-v1"
  let caseID: String
  let postResetStateSHA256: String
  let cleanupState = "off"
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

struct PreconditionFailure: Encodable, Sendable {
  let schemaVersion: UInt16 = 1
  let document = "cfw-adversarial-precondition-unavailable-v1"
  let code = "physical_precondition_unavailable"
  let caseID: String
  let fixtureID: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document, code
    case caseID = "case_id"
    case fixtureID = "fixture_id"
  }
}

enum FixtureError: String, Error, Equatable, Sendable {
  case authorityResponseInvalid = "authority_response_invalid"
  case boundedCommandFailed = "bounded_command_failed"
  case cleanupContaminated = "cleanup_contaminated"
  case fixtureCaseMismatch = "fixture_case_mismatch"
  case fixtureFailed = "fixture_failed"
  case invalidArguments = "invalid_arguments"
  case outputEncodingFailed = "output_encoding_failed"
  case physicalPreconditionUnavailable = "physical_precondition_unavailable"
  case processIdentityUnavailable = "process_identity_unavailable"
  case secretCanaryObserved = "secret_canary_observed"
  case unsafeFilesystemEntry = "unsafe_filesystem_entry"
}

func sha256(_ data: Data) -> String {
  SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func canonicalJSON<T: Encodable>(_ value: T) throws -> Data {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  return try encoder.encode(value)
}

func writeCanonical<T: Encodable>(_ value: T) throws {
  let data = try canonicalJSON(value)
  guard data.count <= 1_048_576 else { throw FixtureError.outputEncodingFailed }
  FileHandle.standardOutput.write(data)
  FileHandle.standardOutput.write(Data([0x0A]))
}

func currentProcessObservation(pid: pid_t = getpid()) throws -> ProcessObservation {
  guard pid > 0 else { throw FixtureError.processIdentityUnavailable }
  var info = proc_bsdinfo()
  let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
  let observed = withUnsafeMutablePointer(to: &info) { pointer in
    proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, pointer, expected)
  }
  guard observed == expected else { throw FixtureError.processIdentityUnavailable }
  let (seconds, firstOverflow) = info.pbi_start_tvsec.multipliedReportingOverflow(by: 1_000)
  let (milliseconds, secondOverflow) = seconds.addingReportingOverflow(
    info.pbi_start_tvusec / 1_000)
  guard !firstOverflow, !secondOverflow, milliseconds > 0 else {
    throw FixtureError.processIdentityUnavailable
  }
  return ProcessObservation(
    pid: UInt32(bitPattern: pid), startUnixMilliseconds: milliseconds)
}

func stateSHA256(_ snapshot: AuthoritySnapshot) throws -> String {
  try ReleaseObservationLogger.authorityStateSHA256(
    state: snapshot.state,
    revision: snapshot.revision,
    leaseOwnerUID: snapshot.leaseView?.operation.ownerUID)
}

func iso8601Milliseconds(_ date: Date) -> String {
  let formatter = ISO8601DateFormatter()
  formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  return formatter.string(from: date)
}
