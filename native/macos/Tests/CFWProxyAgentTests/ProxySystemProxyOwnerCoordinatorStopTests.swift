import CFWSharedProtocol
import Foundation
import Synchronization
import Testing

@testable import CFWCredentialTransport
@testable import CFWLibboxRuntime
@testable import CFWProxyAgentCore

// Stops whose lease the Authority no longer holds, holds or quarantined, and
// restores that finish once the user grants the rights.
extension ProxySystemProxyOwnerCoordinatorTests {
  /// After an Authority restart, or once it recovered, the Authority no longer
  /// holds the lease, so the stopped attestation has nothing to complete. An
  /// owner whose stop finished locally learns that and settles Off; the Host
  /// then proves Off itself.
  @Test func aStopWhoseLeaseTheAuthorityNoLongerHoldsSettlesOff() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.absent)])
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.leaseStatusQueries == [fixture.lease.leaseID])
    #expect(snapshotState(fixture) == .off)
    // Nothing is left to attest or stop again.
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// A lease the Authority still holds, an Authority that cannot tell yet, and
  /// no answer at all prove nothing: the stop keeps its failure and its owner
  /// context, so the next stop attests again.
  @Test(arguments: [
    Result<OwnerLeaseStatus, AuthorityDomainError>.success(.held), .success(.notReady),
    .failure(AuthorityDomainError(code: .globalAuthorityInterrupted)),
  ])
  func aStopWhoseLeaseIsHeldOrUnknownKeepsItsFailure(
    status: Result<OwnerLeaseStatus, AuthorityDomainError>
  ) throws {
    let fixture = try activeFixture(stoppedAttestationFailures: 1, leaseStatuses: [status])
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("an unproven stop did not keep its attestation failure")
      return
    }
    #expect(snapshotState(fixture) == .failed)
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 2)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// The Authority refuses the attestation of a stop it quarantined, and
  /// releases the lease once the owner's process ended. The agent, its stop
  /// finished locally, replies and then ends.
  @Test func aStopTheAuthorityQuarantinedEndsTheAgentAfterItsReply() throws {
    let fixture = try activeFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.quarantined)])
    guard case .failure(.engineLease)? = stop(fixture).first else {
      Issue.record("a quarantined stop did not report its attestation failure")
      return
    }
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.quarantinedStop])
    #expect(Array(fixture.orderLog.values.suffix(3)) == ["leaseStatus", "stopReply", "endProcess"])
  }

  /// Only a stop that finished locally and whose attestation failed asks after
  /// its lease.
  @Test func anAttestedOrLocallyFailedStopAsksNothing() throws {
    let attested = try activeFixture()
    #expect(stop(attested) == [.success])
    #expect(attested.authority.leaseStatusQueries.isEmpty)

    let restoreFailing = try makeFixture(preferencesRestoreFailures: 1)
    let start = CoordinatorRecorder()
    restoreFailing.coordinator.start(
      configuration: restoreFailing.descriptor,
      authorization: try restoreFailing.authorization()
    ) { start.record($0) }
    #expect(restoreFailing.engine.waitUntilStarted())
    restoreFailing.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.preferences)? = stop(restoreFailing).first else {
      Issue.record("the restore failure was not reported")
      return
    }
    #expect(restoreFailing.authority.leaseStatusQueries.isEmpty)
  }

  /// A stop that failed because its settings could not be restored ends once
  /// the rights the user granted restored them, as a retried stop would: after
  /// the reply, the agent attests Stopped and its owner context ends, so the
  /// Host's retry asks nothing more of the Authority.
  @Test func aStopWhoseRestoreFailedEndsOnceGrantedRightsRestoredIt() throws {
    let fixture = try restoreFailingFixture()
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.authority.waitForStoppedAttempt())
    let settled = ContinuousClock.now.advanced(by: .seconds(2))
    while snapshotState(fixture) != .off {
      guard ContinuousClock.now < settled else {
        Issue.record("the restored stop did not settle Off")
        return
      }
      Thread.sleep(forTimeInterval: 0.01)
    }
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values.isEmpty)
  }

  /// The Authority quarantined the failed stop meanwhile, so it refuses the
  /// attestation, and the agent, its settings restored, ends, which lifts the
  /// quarantine.
  @Test func aFailedStopTheAuthorityQuarantinedEndsTheAgentOnceItsSettingsAreRestored()
    throws
  {
    let fixture = try restoreFailingFixture(
      stoppedAttestationFailures: 1, leaseStatuses: [.success(.quarantined)])
    #expect(restoreAfterAuthorization(fixture))
    #expect(fixture.processEnds.wait())
    #expect(fixture.processEnds.values == [.quarantinedStop])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }

  /// Settings still not restored after the rights were granted leave the
  /// failed stop as it was: nothing is attested, and the agent reports the
  /// same failure.
  @Test func aStopWhoseSettingsStayUnrestoredKeepsItsFailure() throws {
    let fixture = try restoreFailingFixture(preferencesRestoreFailures: 2)
    #expect(restoreAfterAuthorization(fixture))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(snapshotState(fixture) == .failed)
  }

  /// A session whose engine failed while its settings could not be restored
  /// still holds its lease, and the Host, finding the owner Off once granted
  /// rights restored the settings, would never stop it. The agent attests the
  /// session's stop before it answers the rights request, so the Off that
  /// follows finds the lease stopping; the Host's own stop then finds nothing
  /// left to attest.
  @Test func aCrashedSessionsRestoreAttestsItsStopBeforeTheAnswer() throws {
    let stoppedGate = BlockingCallGate()
    let fixture = try makeFixture(preferencesRestoreFailures: 1, stoppedGate: stoppedGate)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    fixture.engine.emit(.failed(ProxyEngineFailure(code: "crash", message: "Runtime exited.")))
    #expect(snapshotState(fixture) == .failed)

    let replied = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { replied.signal() }
    #expect(stoppedGate.waitUntilEntered())
    #expect(
      replied.wait(timeout: .now() + .milliseconds(100)) == .timedOut,
      "the rights request was answered before the stop was attested")
    stoppedGate.release()
    #expect(replied.wait(timeout: .now() + 2) == .success)
    #expect(fixture.preferences.restoreCount == 2)
    #expect(fixture.authority.stoppedAttestations.map(\.operation) == [fixture.lease.operation])
    #expect(snapshotState(fixture) == .off)
    #expect(stop(fixture) == [.success])
    #expect(fixture.authority.stoppedAttemptCount == 1)
  }

  /// Granted rights stop no running session: its settings stay applied until
  /// its own stop.
  @Test func grantedRightsLeaveARunningSessionAndItsOwnerAlone() throws {
    let fixture = try activeFixture()
    #expect(restoreAfterAuthorization(fixture))
    Thread.sleep(forTimeInterval: 0.1)
    #expect(snapshotState(fixture) == .proxyActive)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 0)
  }

  /// A System Proxy session whose stop failed because its settings could not
  /// be restored, its engine already stopped.
  func restoreFailingFixture(
    preferencesRestoreFailures: Int = 1,
    stoppedAttestationFailures: Int = 0,
    leaseStatuses: [Result<OwnerLeaseStatus, AuthorityDomainError>] = []
  ) throws -> CoordinatorFixture {
    let fixture = try makeFixture(
      preferencesRestoreFailures: preferencesRestoreFailures,
      stoppedAttestationFailures: stoppedAttestationFailures, leaseStatuses: leaseStatuses)
    let start = CoordinatorRecorder()
    fixture.coordinator.start(
      configuration: fixture.descriptor,
      authorization: try fixture.authorization()
    ) { start.record($0) }
    #expect(fixture.engine.waitUntilStarted())
    fixture.engine.emit(.mixedListenerReady(try readyEndpoint()))
    #expect(start.wait())
    guard case .failure(.preferences)? = stop(fixture).first else {
      Issue.record("the restore failure was not reported")
      return fixture
    }
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.authority.stoppedAttemptCount == 0)
    return fixture
  }

  func restoreAfterAuthorization(_ fixture: CoordinatorFixture) -> Bool {
    let replied = DispatchSemaphore(value: 0)
    fixture.coordinator.restoreSettingsAfterAuthorization { replied.signal() }
    return replied.wait(timeout: .now() + 2) == .success
  }
}
