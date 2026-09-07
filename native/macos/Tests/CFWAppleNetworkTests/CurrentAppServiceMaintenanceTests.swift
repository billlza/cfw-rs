import Darwin
import Testing

@testable import CFWAppleNetwork

private enum MaintenanceFixtureError: Error { case injected }

private final class MaintenanceProxyService: ProxyAgentServicing, @unchecked Sendable {
  var statuses: [ProxyAgentRegistrationStatus]
  var registerError: (any Error)?
  var unregisterError: (any Error)?
  private(set) var registerCalls = 0
  private(set) var unregisterCalls = 0

  init(
    _ statuses: [ProxyAgentRegistrationStatus],
    registerError: (any Error)? = nil,
    unregisterError: (any Error)? = nil
  ) {
    self.statuses = statuses
    self.registerError = registerError
    self.unregisterError = unregisterError
  }

  var registrationStatus: ProxyAgentRegistrationStatus {
    statuses.count > 1 ? statuses.removeFirst() : statuses[0]
  }

  func register() throws {
    registerCalls += 1
    if let registerError { throw registerError }
  }

  func unregister() throws {
    unregisterCalls += 1
    if let unregisterError { throw unregisterError }
  }
}

private final class MaintenanceAuthorityService: GlobalAuthorityDaemonServicing,
  @unchecked Sendable
{
  var statuses: [GlobalAuthorityRegistrationStatus]
  var registerError: (any Error)?
  var unregisterError: (any Error)?
  private(set) var registerCalls = 0
  private(set) var unregisterCalls = 0

  init(
    _ statuses: [GlobalAuthorityRegistrationStatus],
    registerError: (any Error)? = nil,
    unregisterError: (any Error)? = nil
  ) {
    self.statuses = statuses
    self.registerError = registerError
    self.unregisterError = unregisterError
  }

  var registrationStatus: GlobalAuthorityRegistrationStatus {
    statuses.count > 1 ? statuses.removeFirst() : statuses[0]
  }

  func register() throws {
    registerCalls += 1
    if let registerError { throw registerError }
  }

  func unregister() throws {
    unregisterCalls += 1
    if let unregisterError { throw unregisterError }
  }
}

@Suite(.serialized)
struct CurrentAppServiceMaintenanceTests {
  @Test func processInventoryRejectsEmptyFailedTruncatedAndMisalignedResults() {
    let stride = MemoryLayout<pid_t>.stride
    #expect(
      !CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: -1, capacityBytes: stride * 2))
    #expect(
      !CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: 0, capacityBytes: stride * 2))
    #expect(
      !CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: Int32(stride * 2), capacityBytes: stride * 2))
    #expect(
      !CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: Int32(stride + 1), capacityBytes: stride * 3))
    #expect(
      CurrentAppServiceRuntimeObserver.isCompleteProcessInventory(
        returnedBytes: Int32(stride), capacityBytes: stride * 2))
  }

  @Test func processObserverBindsInstalledAndExecutingCandidateServices() {
    let candidate =
      "/Users/release/target/candidates/0.4.0/validation/40022/signed/Clash for Mac.app"
    #expect(
      CurrentAppServiceRuntimeObserver.serviceExecutablePaths(
        .globalAuthority,
        currentBundlePath: candidate
      ) == [
        "/Applications/Clash for Mac.app/Contents/Library/HelperTools/CFWGlobalAuthority",
        candidate + "/Contents/Library/HelperTools/CFWGlobalAuthority",
      ])
    #expect(
      CurrentAppServiceRuntimeObserver.serviceExecutablePaths(
        .proxyAgent,
        currentBundlePath: candidate
      ).contains(
        candidate
          + "/Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
      ))
    #expect(
      CurrentAppServiceRuntimeObserver.isUnexpectedServiceExecutable(
        path: "/tmp/Clash for Mac.app/Contents/Library/HelperTools/CFWGlobalAuthority",
        name: "CFWGlobalAuthority",
        allowedPaths: CurrentAppServiceRuntimeObserver.serviceExecutablePaths(
          .globalAuthority,
          currentBundlePath: candidate
        )
      ))
  }

  @Test func exactServicesRegisterAndUnregisterWithPostconditions() throws {
    let proxy = MaintenanceProxyService([.enabled, .notRegistered])
    let authority = MaintenanceAuthorityService([.notRegistered, .enabled])
    let maintainer = CurrentAppServiceMaintainer(
      proxyAgent: proxy,
      globalAuthority: authority
    )

    #expect(
      try maintainer.perform(.unregister, on: .proxyAgent) == .notRegistered)
    #expect(try maintainer.perform(.register, on: .globalAuthority) == .enabled)
    #expect(proxy.unregisterCalls == 1)
    #expect(proxy.registerCalls == 0)
    #expect(authority.registerCalls == 1)
    #expect(authority.unregisterCalls == 0)
  }

  @Test func idempotentTerminalStatesDoNotRepeatMutation() throws {
    let proxy = MaintenanceProxyService([.notRegistered])
    let authority = MaintenanceAuthorityService([.enabled])
    let maintainer = CurrentAppServiceMaintainer(
      proxyAgent: proxy,
      globalAuthority: authority
    )

    #expect(
      try maintainer.perform(.unregister, on: .proxyAgent) == .notRegistered)
    #expect(try maintainer.perform(.register, on: .globalAuthority) == .enabled)
    #expect(proxy.unregisterCalls == 0)
    #expect(authority.registerCalls == 0)
  }

  @Test func approvalUnknownMutationAndPostconditionFailuresStayDistinct() {
    let cases:
      [(
        MaintenanceProxyService,
        CurrentAppServiceMutation,
        CurrentAppServiceMaintenanceError
      )] = [
        (
          MaintenanceProxyService([.requiresApproval]),
          .unregister,
          .approvalRequired(.proxyAgent)
        ),
        (
          MaintenanceProxyService([.unknown]),
          .register,
          .statusUnknown(.proxyAgent)
        ),
        (
          MaintenanceProxyService([.notFound]),
          .register,
          .serviceNotFound(.proxyAgent)
        ),
        (
          MaintenanceProxyService(
            [.enabled], unregisterError: MaintenanceFixtureError.injected),
          .unregister,
          .mutationFailed(.proxyAgent)
        ),
        (
          MaintenanceProxyService([.enabled]),
          .unregister,
          .postconditionFailed(.proxyAgent)
        ),
      ]
    for (proxy, mutation, expected) in cases {
      let maintainer = CurrentAppServiceMaintainer(
        proxyAgent: proxy,
        globalAuthority: MaintenanceAuthorityService([.enabled])
      )
      #expect(throws: expected) {
        try maintainer.perform(mutation, on: .proxyAgent)
      }
      switch expected {
      case .approvalRequired, .serviceNotFound, .statusUnknown:
        #expect(proxy.registerCalls == 0)
        #expect(proxy.unregisterCalls == 0)
      case .mutationFailed, .postconditionFailed:
        #expect(proxy.unregisterCalls == 1)
      }
    }
  }

  @Test func maintenanceSurfaceNeverAddressesLegacyTombstone() {
    #expect(CurrentAppService.allCases == [.proxyAgent, .globalAuthority])
  }
}
