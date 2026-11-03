import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// A retiring agent ends only once its stop, its pending start and its settings
// are settled.
extension ProxySystemProxyOwnerCoordinatorTests {
  /// A retiring agent keeps a running System Proxy, its engine and settings,
  /// until its stop restores them, and ends after the stop's reply.
  @Test func aRetiringAgentKeepsItsSystemProxyUntilTheStopThenEnds() throws {
    let fixture = try activeFixture()
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(snapshotState(fixture) == .proxyActive)
    #expect(fixture.engine.stopCount == 0)
    #expect(fixture.preferences.restoreCount == 0)

    #expect(stop(fixture) == [.success])
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.preferences.restoreCount == 1)
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
  }

  /// The end waits for the stop's attestation and reply.
  @Test func aRetiringAgentEndsOnlyAfterItsStopIsAttestedAndAnswered() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))

    let stopped = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { result in
      fixture.orderLog.record("stopReply")
      stopped.record(result)
    }
    #expect(stoppedGate.waitUntilEntered())
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    stoppedGate.release()
    #expect(stopped.wait())
    #expect(fixture.processEnds.wait())
    #expect(Array(fixture.orderLog.values.suffix(2)) == ["stopReply", "endProcess"])
  }

  /// A retiring agent whose stop the Authority did not attest still owns its
  /// lease, so it keeps running; a retried stop that attests ends it.
  @Test func aRetiringAgentWhoseStopWasNotAttestedEndsOnceARetryIs() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.held)])
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("the unattested stop did not keep its failure")
      return
    }
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(stop(fixture) == [.success])
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
  }

  /// A start still binding its lease when the agent retires may own that
  /// lease once bound, so the agent ends only after the start finished: a
  /// bound start fails and its stop proves the owner Off, and a start the
  /// Authority refused to bind just fails.
  @Test(arguments: [false, true])
  func aRetiringAgentEndsOnlyOnceItsPendingStartFinished(bindFails: Bool) throws {
    let bindGate = BlockingCallGate()
    let fixture = try makeFixture(
      bindThrows: bindFails ? AuthorityDomainError(code: .ticketInvalid) : nil,
      bindGate: bindGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor, authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(bindGate.waitUntilEntered())
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)

    bindGate.release()
    #expect(start.wait())
    #expect(
      start.values == [.failure(bindFails ? .authority(.ticketInvalid) : .agentEnding)])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.processEnds.wait())
    #expect(fixture.authority.stoppedAttemptCount == (bindFails ? 0 : 1))
  }

  /// A retiring agent that holds only settings an earlier agent left ends
  /// once the rights the user grants restored them.
  @Test func aRetiringAgentWithLeftoverSettingsEndsOnceTheRightsRestoredThem() throws {
    let fixture = try makeFixture(preferencesRestoreFailures: 1, leftoverSettings: true)
    #expect(snapshotState(fixture) == .failed)
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.authority.stoppedAttemptCount == 0)
  }

  /// A retiring agent whose stop could not restore its settings keeps running
  /// until the rights the user grants restore them; it then completes the
  /// stop and ends.
  @Test func aRetiringAgentWhoseRestoreFailedEndsOnceTheRightsRestoredIt() throws {
    let fixture = try restoreFailingFixture()
    fixture.coordinator.retire(after: LibboxInstanceUnclosable(.callDidNotReturn))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.processEnds.values.isEmpty)
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.retired(LibboxInstanceUnclosable(.callDidNotReturn))])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }
}
