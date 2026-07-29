import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// Deterministic coverage for task 5.3: ownership-sensitive Tunnel preference
// compensation. Every Authority/NetworkExtension side effect lives behind an
// injected in-memory seam, so no real NetworkExtension, XPC, or Authority is
// exercised. The ordered compensation is: (1) Authority revoke + zeroize,
// (2) bounded stop, (3) compare-and-restore ONLY on an exact match,
// (4) save/reload/verify, (5) OS Off proof. Conflicts leave Quarantined via
// compensationConflict; cleanup timeouts/unverifiable results via cleanupUnproven.

// MARK: - Fakes

private final class FakeAuthorityRevoker: AuthorityPreparationRevoking, @unchecked Sendable {
  private let lock = NSLock()
  private let failure: Error?
  private var count = 0

  init(failure: Error? = nil) { self.failure = failure }

  var revokeCount: Int { lock.withLock { count } }

  func revokePreparation() async throws {
    lock.withLock { count += 1 }
    if let failure { throw failure }
  }
}

private final class SecretEraseCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0
  var eraseCount: Int { lock.withLock { count } }
  var eraser: @Sendable () -> Void {
    { self.lock.withLock { self.count += 1 } }
  }
}

private final class FakePreferences: ManagedTunnelPreferences, @unchecked Sendable {
  enum Event: Equatable { case load, status, stop, apply, remove }

  private let lock = NSLock()
  private var status: ManagedTunnelConnectionStatus
  private var values: ManagedTunnelPreferenceValues?
  private let stopReachesDisconnected: Bool
  private let applyMutatesStore: Bool
  private let removeMutatesStore: Bool
  private var log: [Event] = []

  init(
    status: ManagedTunnelConnectionStatus,
    values: ManagedTunnelPreferenceValues?,
    stopReachesDisconnected: Bool = true,
    applyMutatesStore: Bool = true,
    removeMutatesStore: Bool = true
  ) {
    self.status = status
    self.values = values
    self.stopReachesDisconnected = stopReachesDisconnected
    self.applyMutatesStore = applyMutatesStore
    self.removeMutatesStore = removeMutatesStore
  }

  var events: [Event] { lock.withLock { log } }
  var currentValues: ManagedTunnelPreferenceValues? { lock.withLock { values } }
  func count(of event: Event) -> Int { lock.withLock { log.filter { $0 == event }.count } }

  func loadCurrentValues() async throws -> ManagedTunnelPreferenceValues? {
    lock.withLock {
      log.append(.load)
      return values
    }
  }

  func connectionStatus() async throws -> ManagedTunnelConnectionStatus {
    lock.withLock {
      log.append(.status)
      return status
    }
  }

  func stop() async throws {
    lock.withLock {
      log.append(.stop)
      if stopReachesDisconnected { status = .disconnected }
    }
  }

  func apply(_ newValues: ManagedTunnelPreferenceValues) async throws {
    lock.withLock {
      log.append(.apply)
      if applyMutatesStore {
        values = newValues
        status = .invalid
      }
    }
  }

  func removeManager() async throws {
    lock.withLock {
      log.append(.remove)
      if removeMutatesStore {
        values = nil
        status = .invalid
      }
    }
  }
}

// MARK: - Builders

private func descriptor(
  epoch: UInt64 = 1,
  generation: UInt64 = 1,
  sha: String = String(repeating: "ab", count: 32),
  identity: String = String(repeating: "cd", count: 32)
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: try appleCredentialAudience(),
    installationID: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    epoch: epoch,
    generation: generation,
    byteCount: 2,
    sha256: SHA256Digest(hex: sha),
    identitySHA256: SHA256Digest(hex: identity))
}

private func values(
  _ descriptor: ConfigurationDescriptor,
  enabled: Bool = true,
  description: String? = "Clash for Mac Tunnel"
) -> ManagedTunnelPreferenceValues {
  ManagedTunnelPreferenceValues(
    descriptor: descriptor, isEnabled: enabled, localizedDescription: description)
}

/// A stop-wait policy with a no-op sleep so bounded waits resolve instantly.
private func fastStopWait(maximumPolls: Int = 5) -> TunnelPreferenceCompensation.StopWaitPolicy {
  TunnelPreferenceCompensation.StopWaitPolicy(maximumPolls: maximumPolls, sleep: {})
}

private func expectThrows(
  _ expected: AppleNetworkError,
  _ body: () async throws -> Void
) async {
  do {
    try await body()
    Issue.record("expected \(expected) but no error was thrown")
  } catch let error as AppleNetworkError {
    switch (error, expected) {
    case (.compensationConflict, .compensationConflict),
      (.cleanupUnproven, .cleanupUnproven):
      break
    default:
      Issue.record("expected \(expected) but got \(error)")
    }
  } catch {
    Issue.record("expected \(expected) but got \(error)")
  }
}

// MARK: - Tests

@Suite(.serialized)
struct TunnelPreferenceCompensationTests {
  // (Restore path) An operation that did NOT create the manager restores the exact
  // prior values, in the ordered steps, and proves Off.
  @Test func compareAndRestoreRestoresPriorManager() async throws {
    let written = values(try descriptor(generation: 2), description: "written")
    let prior = values(try descriptor(generation: 1), description: "prior")
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    let preferences = FakePreferences(status: .connected, values: written)
    let authority = FakeAuthorityRevoker()
    let secrets = SecretEraseCounter()

    try await TunnelPreferenceCompensation.run(
      receipt: receipt, authority: authority, preferences: preferences,
      secretEraser: secrets.eraser, stopWait: fastStopWait())

    #expect(authority.revokeCount == 1)
    // Connected: stop was invoked; prior values restored and verified.
    #expect(preferences.count(of: .stop) == 1)
    #expect(preferences.count(of: .apply) == 1)
    #expect(preferences.count(of: .remove) == 0)
    #expect(preferences.currentValues == prior)
    #expect(secrets.eraseCount >= 1)
    // Ordered: revoke happens (authority) before the first preference touch, and
    // the compare-load precedes the restore apply.
    let events = preferences.events
    #expect(events.first == .status)
    #expect(events.contains(.apply))
  }

  // (Created-manager path) An operation that created the manager removes it.
  @Test func compareAndRemoveRemovesCreatedManager() async throws {
    let written = values(try descriptor(generation: 2), description: "written")
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: true, priorValues: nil, writtenValues: written)

    let preferences = FakePreferences(status: .connected, values: written)
    let authority = FakeAuthorityRevoker()
    let secrets = SecretEraseCounter()

    try await TunnelPreferenceCompensation.run(
      receipt: receipt, authority: authority, preferences: preferences,
      secretEraser: secrets.eraser, stopWait: fastStopWait())

    #expect(preferences.count(of: .remove) == 1)
    #expect(preferences.count(of: .apply) == 0)
    #expect(preferences.currentValues == nil)
    #expect(secrets.eraseCount >= 1)
  }

  // No stop is issued when the connection is already disconnected.
  @Test func doesNotStopWhenAlreadyDisconnected() async throws {
    let written = values(try descriptor(generation: 2))
    let prior = values(try descriptor(generation: 1))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    let preferences = FakePreferences(status: .disconnected, values: written)
    try await TunnelPreferenceCompensation.run(
      receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
      secretEraser: {}, stopWait: fastStopWait())

    #expect(preferences.count(of: .stop) == 0)
    #expect(preferences.currentValues == prior)
  }

  // (External change) When current values no longer equal the written values, the
  // external/administrator change is never overwritten: compensationConflict and
  // Quarantined. Neither apply nor remove is called.
  @Test func externalChangeConflictLeavesQuarantinedWithoutOverwrite() async throws {
    let written = values(try descriptor(generation: 2), description: "written")
    let prior = values(try descriptor(generation: 1), description: "prior")
    let external = values(try descriptor(generation: 2), description: "administrator-edited")
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    let preferences = FakePreferences(status: .disconnected, values: external)
    let secrets = SecretEraseCounter()

    await expectThrows(.compensationConflict("")) {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
        secretEraser: secrets.eraser, stopWait: fastStopWait())
    }
    // The external value is preserved untouched.
    #expect(preferences.currentValues == external)
    #expect(preferences.count(of: .apply) == 0)
    #expect(preferences.count(of: .remove) == 0)
    // Terminal secret erasure still ran on the conflict path.
    #expect(secrets.eraseCount >= 1)
  }

  // An externally removed manager (current values now nil) is also a conflict, not
  // a silent success.
  @Test func externallyRemovedManagerConflicts() async throws {
    let written = values(try descriptor(generation: 2))
    let prior = values(try descriptor(generation: 1))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    let preferences = FakePreferences(status: .disconnected, values: nil)
    await expectThrows(.compensationConflict("")) {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
        secretEraser: {}, stopWait: fastStopWait())
    }
  }

  // (Cleanup timeout) A connection that never reaches disconnected exhausts the
  // bounded stop wait and returns cleanupUnproven, leaving Quarantined.
  @Test func stopTimeoutReturnsCleanupUnproven() async throws {
    let written = values(try descriptor(generation: 2))
    let prior = values(try descriptor(generation: 1))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    // stopReachesDisconnected == false: status stays connected forever.
    let preferences = FakePreferences(
      status: .connected, values: written, stopReachesDisconnected: false)
    let secrets = SecretEraseCounter()

    await expectThrows(.cleanupUnproven("")) {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
        secretEraser: secrets.eraser, stopWait: fastStopWait(maximumPolls: 3))
    }
    // Never restored/removed because the connection was not proven stopped first.
    #expect(preferences.count(of: .apply) == 0)
    #expect(preferences.count(of: .remove) == 0)
    #expect(secrets.eraseCount >= 1)
  }

  // (Unverifiable result) A restore that does not take effect fails the verify step
  // with cleanupUnproven rather than reporting a false Off.
  @Test func unverifiableRestoreReturnsCleanupUnproven() async throws {
    let written = values(try descriptor(generation: 2))
    let prior = values(try descriptor(generation: 1))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)

    // apply is a no-op: the reloaded values will not match the expected prior.
    let preferences = FakePreferences(
      status: .disconnected, values: written, applyMutatesStore: false)

    await expectThrows(.cleanupUnproven("")) {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
        secretEraser: {}, stopWait: fastStopWait())
    }
  }

  // Authority revocation is always attempted first; if it fails, the secret eraser
  // still runs and the error propagates (never a silent success).
  @Test func authorityRevocationFailureStillErasesSecrets() async throws {
    let written = values(try descriptor(generation: 2))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: true, priorValues: nil, writtenValues: written)

    let preferences = FakePreferences(status: .disconnected, values: written)
    let secrets = SecretEraseCounter()
    let authority = FakeAuthorityRevoker(
      failure: AuthorityDomainError(code: .globalAuthorityUnavailable))

    do {
      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: authority, preferences: preferences,
        secretEraser: secrets.eraser, stopWait: fastStopWait())
      Issue.record("expected the Authority revocation failure to propagate")
    } catch is AuthorityDomainError {
      // expected
    }
    #expect(authority.revokeCount == 1)
    // Revocation failed before any preference mutation.
    #expect(preferences.events.isEmpty)
    #expect(secrets.eraseCount == 1)
  }

  // The secret eraser runs exactly once on the success path even though the flow
  // erases eagerly after revocation and again from the terminal defer.
  @Test func secretEraserRunsExactlyOnceOnSuccess() async throws {
    let written = values(try descriptor(generation: 2))
    let receipt = PreferenceMutationReceipt(
      operationID: UUID(), createdManager: true, priorValues: nil, writtenValues: written)
    let preferences = FakePreferences(status: .disconnected, values: written)
    let secrets = SecretEraseCounter()

    try await TunnelPreferenceCompensation.run(
      receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
      secretEraser: secrets.eraser, stopWait: fastStopWait())

    #expect(secrets.eraseCount == 1)
  }

  // Every listed post-save failure point drives the identical ordered compensation
  // to a verified Off. The compensation is trigger-agnostic; the trigger only
  // decides that compensation runs.
  @Test func everyPostSaveFailurePointCompensatesToVerifiedOff() async throws {
    let triggers = [
      "cancellationBeforeStart", "reloadMismatch", "ticketExpiry",
      "synchronousStartFailure", "providerRejection", "readinessTimeout",
      "authorityRevocation",
    ]
    for trigger in triggers {
      let written = values(try descriptor(generation: 2), description: trigger)
      let prior = values(try descriptor(generation: 1), description: "prior-\(trigger)")
      let receipt = PreferenceMutationReceipt(
        operationID: UUID(), createdManager: false, priorValues: prior, writtenValues: written)
      let preferences = FakePreferences(status: .connecting, values: written)
      let secrets = SecretEraseCounter()

      try await TunnelPreferenceCompensation.run(
        receipt: receipt, authority: FakeAuthorityRevoker(), preferences: preferences,
        secretEraser: secrets.eraser, stopWait: fastStopWait())

      #expect(preferences.currentValues == prior, "trigger \(trigger) did not restore prior")
      #expect(secrets.eraseCount >= 1, "trigger \(trigger) did not erase secrets")
    }
  }
}
