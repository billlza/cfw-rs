import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// Ticket-only starts: the redeemed material injected and attested, a stop or a
// revocation during redemption, the libbox deadline, and failures after it.
@Suite(.serialized)
struct TicketOnlyStartupTests {
  @Test func revocationLatchedAfterRedeemPreventsTunnelDataPlaneStart() throws {
    let descriptor = try tunnelDescriptor()
    let redeemedFixture = try makeRedeemedFixture(
      descriptor: descriptor, withSecretSlot: false)
    let revocation = TunnelRevocationChannel()
    let authority = FakeOwnerAuthorityClient(
      onRedeem: { revocation.revoke() },
      makeRedeemed: { redeemedFixture.redeemed })
    let fixture = try makeCoordinator(
      authority: authority, revocation: revocation)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values.count == 1)
    #expect(start.values[0] == .globalAuthorityUnavailable)
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.readyAttestations.isEmpty)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(fixture.revocationCompletions.wait())
    #expect(fixture.revocationCompletions.count == 1)
  }

  @Test func explicitStopDuringRedeemCancelsStartAndWaitsForStoppedAttestation() throws {
    let redeemGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(
      redeemGate: redeemGate
    ) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    #expect(redeemGate.waitUntilEntered())

    let stop = StopResultRecorder()
    fixture.coordinator.stop { stop.record($0) }
    #expect(stop.values.isEmpty)
    redeemGate.release()

    #expect(stop.wait())
    #expect(stopSucceeded(stop.values.first))
    #expect(start.wait())
    #expect(start.values == [.startupCancelled])
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
    #expect(fixture.revocationCompletions.count == 0)

    // The cancelled attempt converged back to idle. A new ticket reaches Authority
    // (and is rejected as already redeemed by this one-shot fake) rather than being
    // masked by a leaked coordinator lifecycle conflict.
    let next = CompletionRecorder()
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { next.record($0) }
    #expect(next.wait())
    #expect(next.values == [.invalidStartTicket])
    #expect(authority.redeemCount == 2)
  }

  @Test func ticketOnlyStartupInjectsRedeemedMaterialAndAttestsReady() throws {
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
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 1)
    #expect(fixture.pump.startCount == 1)

    let ready = authority.readyAttestations
    #expect(ready.count == 1)
    #expect(ready.first?.ownerRole == .provider)
    #expect(ready.first?.readyFlags == .all)
    #expect(ready.first?.packetPumpLimits?.maximumPacketBytes == 1_500)
    #expect(ready.first?.monotonicTimestamp == 12_345)
    // The redeemed transport configuration buffer is wiped after injection.
    #expect(fixtureData.configuration.isErased)
  }

  @Test func libboxDeadlineIsFixedWhenMacOSDeliversTheStartNotAfterRedemption() throws {
    let redeemGate = BlockingCallGate()
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient(redeemGate: redeemGate) { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    let receivedBefore = ContinuousClock.now
    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }
    let receivedAfter = ContinuousClock.now
    #expect(redeemGate.waitUntilEntered())
    // A slow redemption must spend the libbox start's time, not extend it.
    Thread.sleep(forTimeInterval: 0.3)
    redeemGate.release()
    #expect(start.wait())
    #expect(start.values == [nil])
    let deadline = try #require(fixture.engine.deadlines.first)
    #expect(fixture.engine.deadlines.count == 1)
    #expect(deadline.instant >= receivedBefore.advanced(by: EngineStartBudget.ownerLibboxStart))
    #expect(deadline.instant <= receivedAfter.advanced(by: EngineStartBudget.ownerLibboxStart))
  }

  @Test func redeemedMismatchWithDescriptorFailsClosed() throws {
    // Build a redeemed operation whose digests do not match the provider descriptor.
    let otherDescriptor = try ConfigurationDescriptor(
      slot: .tunnel,
      tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
      credentialAudience: CredentialAudience(
        profileID: UUID(),
        profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
      installationID: UUID(),
      epoch: 1,
      generation: 1,
      byteCount: 2,
      sha256: SHA256Digest(hex: String(repeating: "11", count: 32)),
      identitySHA256: SHA256Digest(hex: String(repeating: "22", count: 32)))
    let mismatched = try makeRedeemedFixture(descriptor: otherDescriptor, withSecretSlot: true)
    let authority = FakeOwnerAuthorityClient { mismatched.redeemed }
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.invalidConfigurationSlot])
    #expect(fixture.engine.startCount == 0)
    // Transport buffers are wiped even on the rejection path.
    #expect(mismatched.configuration.isErased)
    let mismatchSecretsErased = mismatched.secrets.slots.allSatisfy { $0.isErased }
    #expect(mismatchSecretsErased)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(authority.stoppedAttestations.first?.operation == mismatched.redeemed.operation)
    #expect(authority.stoppedAttestations.first?.leaseID == mismatched.redeemed.lease.leaseID)
  }

  @Test func postRedeemSessionStartFailureStopsAndAttestsBeforeCompleting() throws {
    let fixtureData = try makeRedeemedFixture(
      descriptor: try tunnelDescriptor(), withSecretSlot: false)
    let authority = FakeOwnerAuthorityClient { fixtureData.redeemed }
    let fixture = try makeCoordinator(authority: authority, failPreparation: true)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    guard case .configuration = start.values[0] else {
      Issue.record("Expected the injected configuration preparation failure")
      return
    }
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(authority.stoppedAttemptCount == 1)
    #expect(authority.stoppedAttestations.count == 1)
    #expect(authority.stoppedAttestations.first?.operation == fixtureData.redeemed.operation)
  }
}
