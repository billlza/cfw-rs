import Testing

@testable import CFWAppleNetwork

private struct FixedProxyAgentServiceController: ProxyAgentServiceControlling {
  let status: ProxyAgentRegistrationStatus

  func registrationStatus() -> ProxyAgentRegistrationStatus { status }

  func ensureRegistered() throws {}
}

private func transport(
  status: ProxyAgentRegistrationStatus
) throws -> AuthenticatedProxyAgentTransport {
  try AuthenticatedProxyAgentTransport(
    machServiceName: "com.bill.clashformac.proxy-agent",
    teamIdentifier: "YKUPL7Z869",
    proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent",
    serviceController: FixedProxyAgentServiceController(status: status))
}

@Suite(.serialized)
struct ProxyAgentHostClientTests {
  @Test func snapshotRequiresApprovedRegistrationInsteadOfProjectingFalseOff() async throws {
    let awaitingApproval = try transport(status: .requiresApproval)
    await #expect(throws: ProxyAgentHostError.registrationRequiresApproval) {
      _ = try await awaitingApproval.snapshot()
    }

    for status in [ProxyAgentRegistrationStatus.notRegistered, .notFound] {
      let unavailable = try transport(status: status)
      await #expect(throws: ProxyAgentHostError.registrationUnavailable) {
        _ = try await unavailable.snapshot()
      }
    }
  }
}
