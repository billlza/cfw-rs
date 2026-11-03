import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Unclosable engines and runtimes, retried stopped attestations, revocation,
// and concurrent stops and starts.
extension TicketOnlyStartupTests {
  @Test func unclosableEngineNeverAttestsStoppedAndEndsTheProcessOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [nil])

    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)
    let failedStop = StopResultRecorder()
    fixture.coordinator.stop { result in
      fixture.events.record("stop")
      failedStop.record(result)
    }
    #expect(failedStop.wait())
    #expect(fixture.processEnds.wait())
    #expect(unclosableStopFailure(failedStop.values.first) == closeFailure)
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "stop"])
    #expect(authority.stoppedAttemptCount == 0)
    #expect(authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    // A retry reaches neither libbox nor the Authority, and ends nothing again.
    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(unclosableStopFailure(retry.values.first) == closeFailure)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values == [closeFailure])
  }

  @Test func unclosableRuntimeArmsTheProcessEndAndFailsTheStartWithoutAttesting() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close failed service")
    let runtime = UnclosablePacketRuntime(closeFailure: closeFailure)
    let fixture = try makeCoordinator(
      authority: authority, runtimeFactory: UnclosablePacketRuntimeFactory(runtime: runtime))
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { error in
      fixture.events.record("start")
      start.record(error)
    }
    #expect(start.wait())
    #expect(fixture.processEnds.wait())

    #expect(start.values == [.engineUnclosable(closeFailure)])
    // The process end is armed before the failure completes anything; it
    // ends the process only once Network Extension received the completions.
    #expect(fixture.events.values == ["end", "start"])
    #expect(fixture.processEnds.values == [closeFailure])
    #expect(authority.readyAttestations.isEmpty)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(runtime.stopCount == 1)
  }

  @Test func stoppedAttestationFailureKeepsContextForAnExactRetry() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(stoppedFailures: 1) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())

    let failedStop = StopResultRecorder()
    fixture.coordinator.stop { failedStop.record($0) }
    #expect(failedStop.wait())
    #expect(isAttestationStopFailure(failedStop.values.first))
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.isEmpty)
    #expect(fixture.engine.stopCount == 1)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(stopSucceeded(retry.values.first))
    #expect(authority.stoppedAttemptCount == 2)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
  }

  @Test func unclosableEngineDuringRevocationIsReportedAndEndsTheProcessOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    let closeFailure = LibboxInstanceUnclosable(closeFailure: "close network: monitor")
    fixture.engine.failStops(with: closeFailure)

    fixture.revocation.revoke()
    #expect(fixture.revocationFailures.wait())
    #expect(fixture.processEnds.wait())
    #expect(fixture.revocationFailures.errors == [.localRuntime(.engineUnclosable(closeFailure))])
    #expect(authority.stoppedAttemptCount == 0)
    #expect(authority.stoppedAttestations.isEmpty)

    let blockedStart = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blockedStart.record($0) }
    #expect(blockedStart.wait())
    #expect(blockedStart.values == [.lifecycleConflict])

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(unclosableStopFailure(retry.values.first) == closeFailure)
    #expect(authority.stoppedAttemptCount == 0)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.processEnds.values == [closeFailure])
  }

  @Test func successfulRevocationStopsAuthorityAndCompletesTheOSSession() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    fixture.revocation.revoke()

    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
    #expect(fixture.revocationFailures.errors.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentExplicitStopAndRevocationShareOneStopTransaction() throws {
    let stoppedGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      stoppedGate: stoppedGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stoppedGate.waitUntilEntered())
    fixture.revocation.revoke()
    stoppedGate.release()

    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func concurrentSecondStartIsRejectedSoTicketIsRedeemedOnce() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let first = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { first.record($0) }
    #expect(first.wait())
    #expect(first.values == [nil])

    // A second start while active must not redeem another ticket.
    let second = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { second.record($0) }
    #expect(second.wait())
    #expect(second.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)
  }
}
