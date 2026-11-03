import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Revocation: forced stops, their attestation and retained context, unclosable
// owners, and a revocation racing an explicit stop.
extension ProxySystemProxyOwnerCoordinatorTests {
  /// A revocation's stop settles the same way, and once settled a later
  /// revocation finds nothing to stop or attest.
  @Test func aRevokedOwnerWhoseLeaseIsGoneSettlesOnce() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.absent)])
    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    let settled = ContinuousClock.now.advanced(by: .seconds(2))
    while fixture.authority.leaseStatusQueries.isEmpty || snapshotState(fixture) != .off {
      guard ContinuousClock.now < settled else {
        Issue.record("the revoked owner did not settle Off")
        return
      }
      Thread.sleep(forTimeInterval: 0.01)
    }
    fixture.revocation.revoke()
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
  }

  @Test func revocationOfAnUnclosableOwnerEndsTheProcessOnceWithoutAttesting() throws {
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    let fixture = try makeFixture(engineCloseFailure: closeFailure)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    fixture.revocation.revoke()
    fixture.revocation.revoke()
    #expect(fixture.processEnds.wait())
    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stop.wait())
    #expect(stop.values == [.failure(.engineUnclosable(closeFailure))])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.processEnds.values == [.engineUnclosable(closeFailure)])
  }

  @Test func revocationForcesStopAndAttestsStopped() throws {
    let fixture = try makeFixture()
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func revocationRetainsContextUntilStoppedAttestationSucceeds() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(
      stoppedAttestationFailures: 1,
      stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    #expect(start.values == [.success])

    fixture.revocation.revoke()
    #expect(stoppedGate.waitUntilEntered())
    #expect(fixture.authority.waitForStoppedAttempt())
    let joinedStop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) {
      joinedStop.record($0)
    }
    stoppedGate.release()
    #expect(joinedStop.wait())
    guard case .failure(.engineLease) = joinedStop.values[0] else {
      Issue.record("Expected the joined stop to observe the failed attestation")
      return
    }
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.isEmpty)

    // Revocation is idempotently retryable after local Off because the exact owner
    // context was retained when the first Authority attestation failed.
    fixture.revocation.revoke()
    #expect(fixture.authority.waitForStoppedAttempt())
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentExplicitStopAndRevocationShareOneStopTransaction() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())

    let stop = CoordinatorRecorder()
    fixture.coordinator.stop(expectedConfiguration: fixture.descriptor) { stop.record($0) }
    #expect(stoppedGate.waitUntilEntered())
    fixture.revocation.revoke()
    stoppedGate.release()

    #expect(stop.wait())
    #expect(stop.values == [.success])
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.preferences.restoreCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.authority.stoppedAttestations.count == 1)
  }
}
