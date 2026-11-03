import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWLibboxRuntime
@testable import CFWPacketTunnel

// The start ticket: its option, its size and its redemption failures, and what
// the provider reports to the host for expired tickets, timeouts and unclosable
// engines.
extension TicketOnlyStartupTests {
  @Test func missingTicketOptionIsRejectedBeforeReachingAuthority() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .globalAuthorityUnavailable))
    // No options at all fails closed with invalidStartTicket.
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: nil)
    }
    // Platform metadata or inline configuration cannot replace the ticket.
    let metadataOnly: [String: NSObject] = [
      "ServerAddress": "Clash for Mac" as NSString,
      "VendorData": ["configuration": "untrusted-inline-configuration"] as NSDictionary,
      "configuration": Data("{}".utf8) as NSData,
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: metadataOnly)
    }
    #expect(authority.redeemCount == 0)
  }

  @Test func wrongSizedTicketValueIsRejected() throws {
    let tooShort: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey: Data([0x1, 0x2, 0x3]) as NSData
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: tooShort)
    }
    let wrongType: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey: NSNumber(value: 7)
    ]
    #expect(throws: PacketTunnelProviderError.invalidStartTicket) {
      _ = try PacketTunnelProvider.startTicket(from: wrongType)
    }
  }

  @Test func exactSizedTicketValueIsAccepted() throws {
    let options: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey:
        Data(repeating: 0x5, count: AuthorityV1Limits.ticketBytes) as NSData
    ]
    let ticket = try PacketTunnelProvider.startTicket(from: options)
    ticket.erase()
  }

  @Test func platformMetadataDoesNotReplaceTheAuthorityTicket() throws {
    let options: [String: NSObject] = [
      NativeProtocolConstants.tunnelStartTicketOptionKey:
        Data(repeating: 0x5, count: AuthorityV1Limits.ticketBytes) as NSData,
      "ServerAddress": "Clash for Mac" as NSString,
      "VendorData": ["configuration": "untrusted-inline-configuration"] as NSDictionary,
    ]
    let ticket = try PacketTunnelProvider.startTicket(from: options)
    defer { ticket.erase() }
    #expect(try ticket.withUnsafeBytes { Data($0) } == Data(repeating: 0x5, count: 32))

    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketInvalid))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    fixture.coordinator.start(ticket: ticket, descriptor: fixture.descriptor) { start.record($0) }
    #expect(start.wait())
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
  }

  @Test func authorityUnavailableFailsClosedWithNoEngineStart() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .globalAuthorityUnavailable))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.globalAuthorityUnavailable])
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
  }

  @Test func invalidTicketRedemptionFailsClosed() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketInvalid))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()

    fixture.coordinator.start(
      ticket: try makeTicket(), descriptor: fixture.descriptor
    ) { start.record($0) }

    #expect(start.wait())
    #expect(start.values == [.invalidStartTicket])
    #expect(fixture.engine.startCount == 0)
  }

  @Test func expiredTicketKeepsItsTypedCauseAndNeverStartsTheEngine() throws {
    let authority = FailingRedeemAuthorityClient(
      error: AuthorityDomainError(code: .ticketExpired))
    let fixture = try makeCoordinator(authority: authority)
    let start = CompletionRecorder()
    let ticket = try makeTicket()

    fixture.coordinator.start(ticket: ticket, descriptor: fixture.descriptor) { start.record($0) }

    #expect(start.wait())
    let failure = try #require(start.values.first ?? nil).engineFailure
    #expect(failure.code == PacketTunnelFailureCode.startTicketExpired.rawValue)
    #expect(authority.redeemCount == 1)
    #expect(fixture.engine.startCount == 0)
    #expect(fixture.pump.startCount == 0)
    #expect(throws: (any Error).self) { try ticket.withUnsafeBytes { _ in () } }
  }

  @Test func providerOnlyEncodesExpiredTicketsAsFreshRetryEvidence() throws {
    let descriptor = try tunnelDescriptor()
    let expired =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.expiredStartTicket, configuration: descriptor)) as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(expired, configuration: descriptor)
        == TunnelStartupFailure.ticketExpired)
    let replay = TunnelTicketStartCoordinator.mapRedeemError(
      AuthorityDomainError(code: .ticketAlreadyRedeemed))
    #expect(replay == .invalidStartTicket)
    let invalid =
      try #require(
        PacketTunnelProvider.platformStartError(
          replay, configuration: descriptor)) as NSError
    #expect(TunnelStartupFailure.matchingFailure(invalid, configuration: descriptor) == nil)
    #expect(PacketTunnelProvider.platformStartError(nil, configuration: descriptor) == nil)
  }

  @Test func providerReportsAStartTimeoutToTheHostWithItsLineage() throws {
    let descriptor = try tunnelDescriptor()
    #expect(
      PacketTunnelProviderError.engineStartTimedOut.engineFailure
        == TunnelStartupFailure.engineStartTimedOut)
    let timedOut =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.engineStartTimedOut, configuration: descriptor)) as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(timedOut, configuration: descriptor)
        == TunnelStartupFailure.engineStartTimedOut)
    // Other engine failures keep reaching the Host through its readiness wait.
    let failed =
      try #require(
        PacketTunnelProvider.platformStartError(
          PacketTunnelProviderError.engineStart("libbox failed"), configuration: descriptor))
      as NSError
    #expect(TunnelStartupFailure.matchingFailure(failed, configuration: descriptor) == nil)
  }

  @Test func providerReportsAnUnclosableEngineToTheHostWithItsLineage() throws {
    let descriptor = try tunnelDescriptor()
    let unclosable = PacketTunnelProviderError.engineUnclosable(
      LibboxInstanceUnclosable(closeFailure: "secret close detail"))
    #expect(unclosable.engineFailure == TunnelStartupFailure.engineUnclosable)
    let reported =
      try #require(PacketTunnelProvider.platformStartError(unclosable, configuration: descriptor))
      as NSError
    #expect(
      TunnelStartupFailure.matchingFailure(reported, configuration: descriptor)
        == TunnelStartupFailure.engineUnclosable)
    #expect(!reported.localizedDescription.contains("secret"))
  }
}
