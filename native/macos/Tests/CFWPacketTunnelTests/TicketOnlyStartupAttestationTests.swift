import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Ready attestation: a stop during it, its failure, and stops attested with the
// bound context.
extension TicketOnlyStartupTests {
  @Test func explicitStopDuringReadyAttestationCannotReportAStoppedTunnelReady() throws {
    let readyGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      readyGate: readyGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(readyGate.waitUntilEntered())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(start.values.isEmpty)
    #expect(fixture.engine.stopCount == 1)
    #expect(fixture.pump.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)

    readyGate.release()
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(authority.readyAttestations.count == 1)
    #expect(authority.stoppedAttestations.count == 1)
  }

  @Test func readyAttestationFailureTearsDownAndFailsClosed() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: true)
    let authority = FakeOwnerAuthorityClient(readyThrows: true) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    // libbox was started for injection, then torn down when readiness could not be attested.
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.engine.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixtureData.configuration.isErased)
    let readySecretsErased = fixtureData.secrets.slots.allSatisfy { $0.isErased }
    #expect(readySecretsErased)
  }

  @Test func readyFailureWithStoppedAttestationFailureRetainsExactContext() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      readyThrows: true,
      stoppedFailures: 1
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.isEmpty)

    let blocked = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { blocked.record($0) }
    #expect(blocked.wait())
    #expect(blocked.values == [.lifecycleConflict])
    #expect(authority.redeemCount == 1)

    let retry = StopResultRecorder()
    fixture.coordinator.stop { retry.record($0) }
    #expect(retry.wait())
    #expect(stopSucceeded(retry.values.first))
    #expect(fixture.engine.stopCount == 1)
    #expect(authority.stoppedAttemptCount == 2)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
  }

  @Test func stopAttestsStoppedExactlyWithBoundContext() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority, clockValue: 999)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(start.wait())
    #expect(start.values == [nil])

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))

    let stopped = authority.stoppedAttestations
    #expect(stopped.count == 1)
    #expect(stopped.first?.libboxStopped == true)
    #expect(stopped.first?.transportClosed == true)
    #expect(stopped.first?.osRestored == true)
    #expect(stopped.first?.monotonicTimestamp == 999)
    #expect(stopped.first?.operation == fixtureData.redeemed.operation)
    #expect(fixture.engine.stopCount == 1)
  }
}
