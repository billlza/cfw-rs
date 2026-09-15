import CFWAppleNetwork
import CFWSharedProtocol
import Testing

@testable import CFWNativeBridge

struct TunnelStartupFailureMappingTests {
  @Test func expiredTicketReachesTheRustBoundaryWithoutBecomingUnavailable() {
    let mapped = NativeBridgeCoordinator.map(
      AppleNetworkError.providerFailure(TunnelStartupFailure.ticketExpired))
    #expect(mapped.responseFailure.code == .ticketExpired)
  }
}
