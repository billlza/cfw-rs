import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Starts bound to the Authority: exact owner capabilities, lease mismatches,
// binding before libbox and preferences, attested readiness, and stops attested
// with the bound context.
@Suite(.serialized)
struct ProxySystemProxyOwnerCoordinatorTests {
  @Test(arguments: [ConfigurationSlot.localProxy, .systemProxy])
  func engineCrashKeepsAuthorityOwnershipUntilExplicitStop(slot: ConfigurationSlot) throws {
    let fixture = try makeFixture(slot: slot)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    let stopped = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stopped.record($0) }
    #expect(stopped.wait())
    #expect(stopped.values == [.success])
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    #expect(fixture.preferences.restoreCount == (slot == .systemProxy ? 1 : 0))
  }

  @Test func localProxyAttestsOnlyListenerReadinessAndStopsThroughTheAuthority() throws {
    let fixture = try makeFixture(slot: .localProxy, effectiveApplied: false)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    #expect(fixture.authority.readyAttestations.isEmpty)
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    #expect(fixture.orderLog.values == ["bind", "engine.start"])
    let ready = try #require(fixture.authority.readyAttestations.first)
    #expect(ready.operation.mode == .localProxy)
    #expect(ready.readyFlags == [.libboxStarted, .transportReady])
    #expect(!ready.readyFlags.contains(.operatingSystemStateReady))
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.lease.operation)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func localProxyCannotStartWithoutAnExactOwnerCapability() throws {
    let fixture = try makeFixture(
      slot: .localProxy, bindThrows: AuthorityDomainError(code: .ticketInvalid))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    #expect(fixture.orderLog.values == ["bind"])
    #expect(fixture.authority.readyAttestations.isEmpty)
    #expect(fixture.authority.stoppedAttestations.isEmpty)
  }

  @Test func localProxyRevocationStillClosesTheListenerAndAttestsStopped() throws {
    let fixture = try makeFixture(slot: .localProxy)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.revocation.revoke()
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.preferences.restoreCount == 0)
  }

  @Test func consumedAuthorizationFailsClosedBeforeAnyMutation() throws {
    let fixture = try makeFixture()
    let authorization = try fixture.authorization()
    let consumed = try authorization.consumeCapability()
    consumed.erase()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    try #require(start.wait())

    let outcome = try #require(start.values.first)
    guard case .failure(.authority(.ticketAlreadyRedeemed)) = outcome else {
      Issue.record("Expected fail-closed engine-lease (Authority) failure")
      return
    }
    #expect(fixture.authority.bindCount == 0)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values.isEmpty)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func rejectedCapabilityFailsClosedBeforeLibboxOrPreferences() throws {
    let fixture = try makeFixture(
      bindThrows: AuthorityDomainError(code: .globalAuthorityIdentityRejected))
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityIdentityRejected)) = start.values[0] else {
      Issue.record("Expected fail-closed Authority rejection")
      return
    }
    #expect(fixture.authority.bindCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.orderLog.values == ["bind"])
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func boundLeaseMismatchProvesStoppedAndAttestsExactAuthorityContext() throws {
    let fixture = try makeFixture(returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the mismatched bound lease to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(fixture.authority.stoppedAttestations.first?.leaseID == fixture.boundLease.leaseID)
  }

  @Test func boundMismatchAttestationFailureBlocksStartAndRetriesExactProof() throws {
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      returnMismatchedLease: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())
    guard case .failure(.cleanupFailed) = start.values[0] else {
      Issue.record("Expected the mismatch and stopped-attestation failures to be preserved")
      return
    }

    let blocked = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { blocked.record($0) }
    #expect(blocked.wait())
    #expect(blocked.values == [.failure(.lifecycleConflict)])
    #expect(fixture.authority.bindCount == 1)

    let retry = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { retry.record($0) }
    #expect(retry.wait())
    #expect(retry.values == [.success])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
  }

  @Test func revocationLatchedAfterBindPreventsLocalStartAndAttestsStopped() throws {
    let revocation = ProxyRevocationChannel()
    let fixture = try makeFixture(
      onBind: { revocation.revoke() },
      revocation: revocation)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(start.wait())

    guard case .failure(.engineLease) = start.values[0] else {
      Issue.record("Expected the claim-after-revoke start to fail closed")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func libboxDeadlineIsFixedWhenTheStartArrivesNotAfterTheBind() throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(bindGate: bindGate)
    let start = CoordinatorRecorder()
    let receivedBefore = ContinuousClock.now
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    let receivedAfter = ContinuousClock.now
    #expect(bindGate.waitUntilEntered())
    // A slow Authority bind must spend the libbox start's time, not extend it.
    Thread.sleep(forTimeInterval: 0.3)
    bindGate.release()
    #expect(fixture.engine.waitUntilStarted())
    let deadline = try #require(fixture.engine.deadlines.first)
    #expect(fixture.engine.deadlines.count == 1)
    #expect(deadline.instant >= receivedBefore.advanced(by: EngineStartBudget.ownerLibboxStart))
    #expect(deadline.instant <= receivedAfter.advanced(by: EngineStartBudget.ownerLibboxStart))
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
  }

  @Test func explicitStopDuringBindCancelsStartAndWaitsForExactStoppedProof() throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(bindGate: bindGate)
    let start = CoordinatorRecorder()
    let runtimeConfiguration = SensitiveDataBuffer(copying: Data("{}".utf8))
    fixture.coordinator.start(
      configuration: runtimeConfiguration,
      descriptor: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(bindGate.waitUntilEntered())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.values.isEmpty)
    bindGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(start.wait())
    #expect(start.values == [.failure(.startupCancelled)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.preferences.applyCount == 0)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.first?.operation == fixture.boundLease.operation)
    #expect(runtimeConfiguration.isErasedForTesting)
  }

  @Test func ownerBindingPrecedesLibboxAndPreferencesAndAttestsReadyExactly() throws {
    let fixture = try makeFixture(clockValue: 4_242)
    let authorization = try fixture.authorization()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: authorization
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    // Binding to the Authority precedes libbox start, which precedes SCPreferences.
    #expect(fixture.orderLog.values == ["bind", "engine.start", "apply"])
    #expect(fixture.authority.bindCount == 1)
    #expect(
      fixture.authority.bindContexts == [
        try ProxyOwnerContext(
          operation: fixture.lease.operation,
          leaseID: fixture.lease.leaseID)
      ])
    #expect(throws: (any Error).self) {
      _ = try authorization.consumeCapability()
    }

    let ready = fixture.authority.readyAttestations
    #expect(ready.count == 1)
    #expect(ready.first?.ownerRole == .proxyAgent)
    #expect(ready.first?.readyFlags == .all)
    #expect(ready.first?.packetPumpLimits == nil)
    #expect(ready.first?.monotonicTimestamp == 4_242)
    #expect(ready.first?.operation.mode == .systemProxy)
    #expect(ready.first?.operation.configSHA256 == fixture.descriptor.sha256)
    #expect(ready.first?.operation.identitySHA256 == fixture.descriptor.identitySHA256)
  }

  @Test func readinessRefusedWhenEffectiveProxyStateIsNotApplied() throws {
    let fixture = try makeFixture(effectiveApplied: false)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityUnavailable)) = start.values[0] else {
      Issue.record("Expected fail-closed readiness refusal")
      return
    }
    #expect(fixture.authority.readyAttestations.isEmpty)
    // The owned libbox runtime and System Proxy state are torn down on refusal.
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixture = try makeFixture(readyThrows: true)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    guard case .failure(.authority(.globalAuthorityUnavailable)) = start.values[0] else {
      Issue.record("Expected fail-closed attestation failure")
      return
    }
    #expect(fixture.authority.readyAttestations.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixture = try makeFixture(clockValue: 909)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.success])

    let stopped = fixture.authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 909)
    #expect(stopped.first?.operation.mode == .systemProxy)
    #expect(fixture.engine.stopCount == 1)
  }

  /// Starts System Proxy and waits until it is active.
  func activeFixture(
    stoppedAttestationFailures: Int = 0,
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = []
  ) throws -> CoordinatorFixture {
    let fixture = try makeFixture(
      stoppedAttestationFailures: stoppedAttestationFailures, leaseStatuses: leaseStatuses)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])
    return fixture
  }

  func stop(_ fixture: CoordinatorFixture) -> [CoordinatorOutcome] {
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      stop.record(result)
    }
    #expect(stop.wait())
    return stop.values
  }

  func snapshotState(_ fixture: CoordinatorFixture) -> EngineStateKind? {
    let snapshot = SnapshotRecorder()
    fixture.coordinator.snapshot { snapshot.record($0) }
    #expect(snapshot.wait())
    return snapshot.values.first?.state.kind
  }
}
