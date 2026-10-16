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

  @Test func providerStartTimeoutReachesTheRustBoundaryAsItsOwnCause() {
    let mapped = NativeBridgeCoordinator.map(
      AppleNetworkError.providerFailure(TunnelStartupFailure.engineStartTimedOut))
    #expect(mapped.responseFailure.code == .engineStartTimedOut)
    #expect(
      mapped.responseFailure.message == NativeBridgeErrorCode.engineStartTimedOut.stableMessage)
    // The same wire code and text as the Rust BackendErrorKind::EngineStartTimedOut.
    #expect(NativeBridgeErrorCode.engineStartTimedOut.rawValue == "engine_start_timed_out")
    #expect(
      NativeBridgeErrorCode.engineStartTimedOut.stableMessage
        == "The engine did not finish starting in time and was stopped, usually because rule "
        + "datasets were still downloading. Datasets that finished are kept for the next start.")
  }

  @Test func proxyAgentStartTimeoutReachesTheRustBoundaryAsItsOwnCause() {
    let timedOut = NativeBridgeCoordinator.map(
      ProxyAgentHostError.agentFailure(
        EngineFailure(
          code: NativeBridgeErrorCode.engineStartTimedOut.rawValue,
          message: "System Proxy runtime startup did not finish in time and was interrupted.",
          isRetryable: false)))
    #expect(timedOut.responseFailure.code == .engineStartTimedOut)
    #expect(
      timedOut.responseFailure.message == NativeBridgeErrorCode.engineStartTimedOut.stableMessage)
    let failed = NativeBridgeCoordinator.map(
      ProxyAgentHostError.agentFailure(
        EngineFailure(
          code: "proxy-engine-start-failed", message: "System Proxy runtime startup failed.",
          isRetryable: false)))
    #expect(failed.responseFailure.code == .systemProxyRuntimeFailed)
  }
}
