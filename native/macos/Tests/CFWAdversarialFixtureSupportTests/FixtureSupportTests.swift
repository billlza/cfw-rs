import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAdversarialFixtureSupport

@Test func externalCaseMappingIsAnExactTenControllerClosure() {
  let cases = ExternalCaseID.allCases
  #expect(cases.count == 24)
  #expect(Set(cases.map(\.fixtureID)).count == 10)
  #expect(cases.filter(\.resetRequired).count == 16)
  #expect(ExternalCaseID.wrongUID.fixtureID == .rootOwnedUIDLauncher)
  #expect(ExternalCaseID.replayedOperation.fixtureID == .authorityOperationReplay)
  #expect(
    ExternalCaseID.secretExtractionEvidence.fixtureID == .rootOwnedSecretCanaryScanner)
}

@Test func probeResultEncodingIsCanonicalAndContainsNoPassFlag() throws {
  let process = ProcessObservation(pid: 42, startUnixMilliseconds: 1_800_000_000_000)
  let result = ProbeResult(
    caseID: "stale-pid-evidence",
    requestSHA256: String(repeating: "a", count: 64),
    process: process,
    effectiveUserIdentifier: 501,
    auditSessionIdentifier: 100_001,
    preStateSHA256: String(repeating: "b", count: 64),
    postStateSHA256: String(repeating: "b", count: 64),
    cleanupState: "off",
    boundaryEvidence: .freshness(
      IdentityFreshnessEvidence(
        capturedPID: 42,
        capturedStartUnixMilliseconds: 1_799_999_999_000,
        currentPID: 42,
        currentStartUnixMilliseconds: 1_800_000_000_000,
        capturedAuditSessionID: 100_001,
        currentAuditSessionID: 100_001)),
    secretCoverage: .empty,
    preResetStateSHA256: String(repeating: "b", count: 64))
  let encoded = try canonicalJSON(result)
  let object = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  #expect(object["document"] as? String == "cfw-adversarial-probe-result-v1")
  #expect(object["accepted"] == nil)
  #expect(object["passed"] == nil)
  #expect(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) == encoded)
}

@Test func secretCanaryMatchingIsObservedNotDeclared() {
  let canary = Data("bounded-canary".utf8)
  #expect(countOccurrences(of: canary, in: Data("clean surface".utf8)) == 0)
  #expect(
    countOccurrences(
      of: canary,
      in: Data("bounded-canary|bounded-canary".utf8)) == 2)
}

@Test func boundedCommandTimeoutFailsClosed() {
  #expect(throws: FixtureError.physicalPreconditionUnavailable) {
    _ = try runBoundedCommand(
      executable: "/bin/sleep",
      arguments: ["2"],
      timeoutSeconds: 1)
  }
}

@Test func currentProcessIdentityComesFromKernel() throws {
  let observed = try currentProcessObservation()
  #expect(observed.pid > 0)
  #expect(observed.startUnixMilliseconds > 0)
}

@Test func resetValidationRejectsContaminatedAuthorityState() throws {
  let process = ProcessObservation(pid: 42, startUnixMilliseconds: 1_800_000_000_000)
  let cursor = try ReplayCursor(
    installationID: AuthorityIdentifier(UUID()),
    acceptedEpoch: 1,
    acceptedGeneration: 1,
    revision: 2,
    previousRecordSHA256: SHA256Digest(hex: String(repeating: "a", count: 64)))
  let quarantined = try AuthoritySnapshot(
    protocolVersion: AuthorityProtocolVersion(),
    state: .quarantined,
    revision: 2,
    replayCursor: cursor,
    leaseView: nil,
    lastFailure: AuthorityFailureSummary(code: "journal-corrupt"),
    consoleUID: 501)
  let observation = SnapshotObservation(
    snapshot: quarantined,
    requestSHA256: String(repeating: "b", count: 64),
    process: process,
    effectiveUserIdentifier: 501,
    auditSessionIdentifier: 100_001)
  #expect(throws: FixtureError.cleanupContaminated) {
    _ = try validatedResetDigest(observation)
  }
}
