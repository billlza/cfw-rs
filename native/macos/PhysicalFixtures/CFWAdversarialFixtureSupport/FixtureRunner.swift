import CFWSharedProtocol
import Darwin
import Foundation

public enum AdversarialFixtureMain {
  public static func run(
    fixtureID: ExternalFixtureID,
    allowedCases: Set<ExternalCaseID>
  ) async {
    do {
      let arguments = CommandLine.arguments
      if try await runInternalWorker(arguments: arguments) { return }
      guard arguments.count == 3,
        let caseID = ExternalCaseID(rawValue: arguments[2]),
        caseID.fixtureID == fixtureID,
        allowedCases.contains(caseID)
      else { throw FixtureError.fixtureCaseMismatch }
      guard installedCaseID == caseID else {
        preconditionUnavailable(caseID, fixtureID: fixtureID)
      }
      switch arguments[1] {
      case "execute":
        try await writeCanonical(execute(caseID))
      case "reset":
        try await writeCanonical(reset(caseID))
      default:
        throw FixtureError.invalidArguments
      }
    } catch FixtureError.physicalPreconditionUnavailable {
      if CommandLine.arguments.count == 3,
        let caseID = ExternalCaseID(rawValue: CommandLine.arguments[2])
      {
        preconditionUnavailable(caseID, fixtureID: fixtureID)
      }
      fail(FixtureError.invalidArguments)
    } catch let error as FixtureError {
      fail(error)
    } catch {
      fail(FixtureError.fixtureFailed)
    }
  }
}

private func execute(_ caseID: ExternalCaseID) async throws -> ProbeResult {
  switch caseID {
  case .wrongUID:
    guard geteuid() == 0 else { throw FixtureError.physicalPreconditionUnavailable }
    let before = try consoleSnapshotWorker()
    guard before.snapshot.state == .off else { throw FixtureError.cleanupContaminated }
    let rejected = try await rejectedHostHandshake()
    let after = try consoleSnapshotWorker()
    let beforeDigest = try before.stateSHA256
    guard rejected.effectiveUserIdentifier == 0,
      after.snapshot.state == .off,
      try after.stateSHA256 == beforeDigest
    else { throw FixtureError.authorityResponseInvalid }
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: rejected.requestSHA256,
      process: rejected.process,
      effectiveUserIdentifier: rejected.effectiveUserIdentifier,
      auditSessionIdentifier: rejected.auditSessionIdentifier,
      preStateSHA256: beforeDigest,
      postStateSHA256: try after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .empty,
      secretCoverage: .empty,
      preResetStateSHA256: beforeDigest)

  case .wrongAuditSession:
    guard geteuid() == 0 else { throw FixtureError.physicalPreconditionUnavailable }
    let before = try consoleSnapshotWorker()
    let rejected = try isolatedRejectedWorker()
    let after = try consoleSnapshotWorker()
    let beforeDigest = try before.stateSHA256
    guard rejected.effectiveUserIdentifier == before.effectiveUserIdentifier,
      rejected.auditSessionIdentifier != before.auditSessionIdentifier,
      after.snapshot.state == .off,
      try after.stateSHA256 == beforeDigest
    else { throw FixtureError.physicalPreconditionUnavailable }
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: rejected.requestSHA256,
      process: rejected.process,
      effectiveUserIdentifier: rejected.effectiveUserIdentifier,
      auditSessionIdentifier: rejected.auditSessionIdentifier,
      preStateSHA256: beforeDigest,
      postStateSHA256: try after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .empty,
      secretCoverage: .empty,
      preResetStateSHA256: beforeDigest)

  case .staleAuditEvidence:
    guard geteuid() == 0 else { throw FixtureError.physicalPreconditionUnavailable }
    let current = try consoleSnapshotWorker()
    let captured = try isolatedIdentityWorker()
    guard captured.effectiveUserIdentifier == current.effectiveUserIdentifier,
      captured.auditSessionIdentifier != current.auditSessionIdentifier
    else { throw FixtureError.physicalPreconditionUnavailable }
    let evidence = IdentityFreshnessEvidence(
      capturedPID: captured.process.pid,
      capturedStartUnixMilliseconds: captured.process.startUnixMilliseconds,
      currentPID: current.process.pid,
      currentStartUnixMilliseconds: current.process.startUnixMilliseconds,
      capturedAuditSessionID: captured.auditSessionIdentifier,
      currentAuditSessionID: current.auditSessionIdentifier)
    let state = try current.stateSHA256
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: sha256(try canonicalJSON(evidence)),
      process: current.process,
      effectiveUserIdentifier: current.effectiveUserIdentifier,
      auditSessionIdentifier: current.auditSessionIdentifier,
      preStateSHA256: state,
      postStateSHA256: state,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .freshness(evidence),
      secretCoverage: .empty,
      preResetStateSHA256: state)

  case .stalePIDEvidence:
    let before = try await directSnapshot()
    guard before.snapshot.state == .off else { throw FixtureError.cleanupContaminated }
    let reused = try exerciseBoundedPIDReuse()
    let after = try await directSnapshot()
    let beforeDigest = try before.stateSHA256
    guard after.snapshot.state == .off,
      try after.stateSHA256 == beforeDigest
    else { throw FixtureError.cleanupContaminated }
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: reused.requestSHA256,
      process: reused.process,
      effectiveUserIdentifier: reused.effectiveUserIdentifier,
      auditSessionIdentifier: reused.auditSessionIdentifier,
      preStateSHA256: beforeDigest,
      postStateSHA256: try after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .freshness(reused.evidence),
      secretCoverage: .empty,
      preResetStateSHA256: beforeDigest)

  case .replayedOperation:
    let replay = try await exerciseReplayedOperation()
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: replay.requestSHA256,
      process: replay.before.process,
      effectiveUserIdentifier: replay.before.effectiveUserIdentifier,
      auditSessionIdentifier: replay.before.auditSessionIdentifier,
      preStateSHA256: try replay.before.stateSHA256,
      postStateSHA256: try replay.after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .empty,
      secretCoverage: .empty,
      preResetStateSHA256: "")

  case .requestFlood:
    let flood = try await exerciseBoundedRequestFlood()
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: flood.requestSHA256,
      process: flood.before.process,
      effectiveUserIdentifier: flood.before.effectiveUserIdentifier,
      auditSessionIdentifier: flood.before.auditSessionIdentifier,
      preStateSHA256: try flood.before.stateSHA256,
      postStateSHA256: try flood.after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .empty,
      secretCoverage: .empty,
      preResetStateSHA256: "")

  case .secretExtractionLogs, .secretExtractionPreferences,
    .secretExtractionJournal, .secretExtractionCrashRecords,
    .secretExtractionSnapshots, .secretExtractionEvidence:
    guard geteuid() == 0 else { throw FixtureError.physicalPreconditionUnavailable }
    let canary = try SecretCanary.generate()
    defer {
      var bytes = canary.bytes
      bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
    }
    let cycle = try consoleCanaryCycleWorker(canary.bytes)
    let coverage = try scanSecretSurface(
      caseID: caseID, canary: canary, authoritySnapshot: cycle.cleanSnapshot)
    let after = try consoleSnapshotWorker()
    let cleanDigest = try cycle.cleanSnapshot.stateSHA256
    guard after.snapshot.state == .off,
      try after.stateSHA256 == cleanDigest
    else { throw FixtureError.cleanupContaminated }
    return ProbeResult(
      caseID: caseID.rawValue,
      requestSHA256: cycle.requestSHA256,
      process: cycle.cleanSnapshot.process,
      effectiveUserIdentifier: cycle.cleanSnapshot.effectiveUserIdentifier,
      auditSessionIdentifier: cycle.cleanSnapshot.auditSessionIdentifier,
      preStateSHA256: cleanDigest,
      postStateSHA256: try after.stateSHA256,
      cleanupState: caseID.cleanupState.rawValue,
      boundaryEvidence: .empty,
      secretCoverage: .coverage(coverage),
      preResetStateSHA256: cleanDigest)

  case .inactiveConsoleUser, .replayedStartTicket, .duplicateRedemption,
    .replayCursorRollback, .authorityJournalTruncation, .authorityJournalTamper,
    .authorityJournalSymlink, .inFlightSaturation, .eventQueueSaturation,
    .heartbeatLoss, .fastUserSwitchingRace, .lateCallback:
    // These boundaries require an OS-owned second login session, an installed
    // role-specific Provider/ProxyAgent executable, or a launchd-mediated
    // Authority stop/restart transaction. The production protocol intentionally
    // exposes no test override for those authorities. Never translate their
    // absence into a passing observation.
    throw FixtureError.physicalPreconditionUnavailable
  }
}

private func reset(_ caseID: ExternalCaseID) async throws -> ResetResult {
  let observed: SnapshotObservation
  if caseID.fixtureID == .rootOwnedUIDLauncher
    || caseID.fixtureID == .isolatedAuditSession
    || caseID.fixtureID == .isolatedConsoleSession
    || caseID.fixtureID == .rootOwnedAuthorityJournalSnapshot
    || caseID.fixtureID == .rootOwnedSecretCanaryScanner
    || caseID.fixtureID == .fastUserSwitch
  {
    guard geteuid() == 0 else { throw FixtureError.physicalPreconditionUnavailable }
    observed = try consoleSnapshotWorker()
  } else {
    observed = try await directSnapshot()
  }
  return ResetResult(
    caseID: caseID.rawValue,
    postResetStateSHA256: try validatedResetDigest(observed),
    contaminationDetected: false)
}

func validatedResetDigest(_ observed: SnapshotObservation) throws -> String {
  guard observed.snapshot.state == .off, observed.snapshot.leaseView == nil else {
    throw FixtureError.cleanupContaminated
  }
  return try observed.stateSHA256
}

private func preconditionUnavailable(
  _ caseID: ExternalCaseID,
  fixtureID: ExternalFixtureID
) -> Never {
  do {
    try writeCanonical(
      PreconditionFailure(caseID: caseID.rawValue, fixtureID: fixtureID.rawValue))
    exit(EX_UNAVAILABLE)
  } catch {
    fail(FixtureError.outputEncodingFailed)
  }
}

private func fail(_ error: FixtureError) -> Never {
  FileHandle.standardError.write(Data((error.rawValue + "\n").utf8))
  exit(EX_SOFTWARE)
}

private let installedCaseID: ExternalCaseID? = {
  #if CFW_ADVERSARIAL_CASE_WRONG_UID
    .wrongUID
  #elseif CFW_ADVERSARIAL_CASE_WRONG_AUDIT_SESSION
    .wrongAuditSession
  #elseif CFW_ADVERSARIAL_CASE_STALE_PID_EVIDENCE
    .stalePIDEvidence
  #elseif CFW_ADVERSARIAL_CASE_STALE_AUDIT_EVIDENCE
    .staleAuditEvidence
  #elseif CFW_ADVERSARIAL_CASE_INACTIVE_CONSOLE_USER
    .inactiveConsoleUser
  #elseif CFW_ADVERSARIAL_CASE_REPLAYED_OPERATION
    .replayedOperation
  #elseif CFW_ADVERSARIAL_CASE_REPLAYED_START_TICKET
    .replayedStartTicket
  #elseif CFW_ADVERSARIAL_CASE_DUPLICATE_REDEMPTION
    .duplicateRedemption
  #elseif CFW_ADVERSARIAL_CASE_REPLAY_CURSOR_ROLLBACK
    .replayCursorRollback
  #elseif CFW_ADVERSARIAL_CASE_AUTHORITY_JOURNAL_TRUNCATION
    .authorityJournalTruncation
  #elseif CFW_ADVERSARIAL_CASE_AUTHORITY_JOURNAL_TAMPER
    .authorityJournalTamper
  #elseif CFW_ADVERSARIAL_CASE_AUTHORITY_JOURNAL_SYMLINK
    .authorityJournalSymlink
  #elseif CFW_ADVERSARIAL_CASE_REQUEST_FLOOD
    .requestFlood
  #elseif CFW_ADVERSARIAL_CASE_IN_FLIGHT_SATURATION
    .inFlightSaturation
  #elseif CFW_ADVERSARIAL_CASE_EVENT_QUEUE_SATURATION
    .eventQueueSaturation
  #elseif CFW_ADVERSARIAL_CASE_HEARTBEAT_LOSS
    .heartbeatLoss
  #elseif CFW_ADVERSARIAL_CASE_FAST_USER_SWITCHING_RACE
    .fastUserSwitchingRace
  #elseif CFW_ADVERSARIAL_CASE_LATE_CALLBACK
    .lateCallback
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_LOGS
    .secretExtractionLogs
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_PREFERENCES
    .secretExtractionPreferences
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_JOURNAL
    .secretExtractionJournal
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_CRASH_RECORDS
    .secretExtractionCrashRecords
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_SNAPSHOTS
    .secretExtractionSnapshots
  #elseif CFW_ADVERSARIAL_CASE_SECRET_EXTRACTION_EVIDENCE
    .secretExtractionEvidence
  #else
    nil
  #endif
}()
