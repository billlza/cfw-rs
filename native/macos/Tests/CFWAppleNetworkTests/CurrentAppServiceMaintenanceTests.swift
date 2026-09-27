import Darwin
import Foundation
import Testing

@testable import CFWAppleNetwork

private enum MaintenanceFixtureError: Error { case injected }

@Test func orphanedServiceProxyObservationIncludesScopedAndSupplementalSwitches() {
  #expect(CurrentSystemProxySwitchObserver.classify([:]) == .disabled)
  #expect(CurrentSystemProxySwitchObserver.classify(["HTTPEnable": false]) == .disabled)
  #expect(CurrentSystemProxySwitchObserver.classify(["HTTPEnable": true]) == .enabled)
  #expect(CurrentSystemProxySwitchObserver.classify(["HTTPEnable": "0"]) == .unobservable)
  #expect(CurrentSystemProxySwitchObserver.classify(["SOCKSEnable": -1]) == .unobservable)
  #expect(
    CurrentSystemProxySwitchObserver.classify([
      "__SCOPED__": ["en0": ["HTTPSEnable": 1]]
    ]) == .enabled)
  #expect(
    CurrentSystemProxySwitchObserver.classify([
      "__SUPPLEMENTAL__": [["ProxyAutoConfigEnable": 1]]
    ]) == .enabled)
  #expect(
    CurrentSystemProxySwitchObserver.classify([
      "__SCOPED__": ["en0": ["HTTPSEnable": 0]],
      "__SUPPLEMENTAL__": [["SOCKSEnable": 0]],
    ]) == .disabled)
  #expect(CurrentSystemProxySwitchObserver.classify(["__SCOPED__": "unavailable"]) == .unobservable)
  #expect(
    CurrentSystemProxySwitchObserver.classify([
      "__SCOPED__": ["en0": ["__SCOPED__": ["en1": ["HTTPEnable": 0]]]]
    ]) == .unobservable)
  #expect(
    CurrentSystemProxySwitchObserver.classify([
      "__SUPPLEMENTAL__": Array(repeating: ["HTTPEnable": 0], count: 129)
    ]) == .unobservable)
}

private final class ControlledAuthorityUnregistration: GlobalAuthorityDaemonServicing,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let barrier = ServiceUnregistrationBarrier()
  private var state: GlobalAuthorityRegistrationStatus = .enabled
  private var callbacks: [@Sendable (Result<Void, Error>) -> Void] = []
  private var requested: (count: Int, finish: @Sendable (Result<Void, Error>) -> Void)?
  private var deadlineAction: (@Sendable () -> Void)?
  private var osCompletionDelivered = true
  private var registrations = 0
  let legacyReturnsBeforeCompletion: Bool
  let registerResult: GlobalAuthorityRegistrationStatus
  let pendingProjection: GlobalAuthorityRegistrationStatus
  let registerThrows: Bool

  init(
    legacyReturnsBeforeCompletion: Bool = false,
    initial: GlobalAuthorityRegistrationStatus = .enabled,
    registerResult: GlobalAuthorityRegistrationStatus = .enabled,
    pendingProjection: GlobalAuthorityRegistrationStatus = .notRegistered,
    registerThrows: Bool = false
  ) {
    self.legacyReturnsBeforeCompletion = legacyReturnsBeforeCompletion
    self.state = initial
    self.registerResult = registerResult
    self.pendingProjection = pendingProjection
    self.registerThrows = registerThrows
  }

  var registrationStatus: GlobalAuthorityRegistrationStatus { lock.withLock { state } }
  var registerCalls: Int { lock.withLock { registrations } }
  var unregisterCalls: Int { lock.withLock { callbacks.count } }

  func requireRegistrationReady() throws { try barrier.requireRegistrationReady() }

  func register() throws {
    try barrier.register {
      try lock.withLock {
        registrations += 1
        guard osCompletionDelivered else {
          throw NSError(domain: NSPOSIXErrorDomain, code: 1)
        }
        state = registerResult
        if registerThrows { throw NSError(domain: NSPOSIXErrorDomain, code: 1) }
      }
    }
  }

  func unregister() async throws {
    if legacyReturnsBeforeCompletion {
      submit { _ in }
      return
    }
    try await barrier.unregister(
      deadline: CallbackDeadlineScheduler { action in
        self.lock.withLock { self.deadlineAction = action }
      }, operation: { finish in self.submit(finish) })
  }

  private func submit(_ finish: @escaping @Sendable (Result<Void, Error>) -> Void) {
    let waiting: (@Sendable (Result<Void, Error>) -> Void)? = lock.withLock {
      state = pendingProjection
      osCompletionDelivered = false
      callbacks.append(finish)
      guard let waiting = requested, callbacks.count >= waiting.count else { return nil }
      requested = nil
      return waiting.finish
    }
    waiting?(.success(()))
  }

  func waitUntilSubmitted(count: Int = 1) async throws {
    let _: Void = try await awaitBoundedCallback(
      deadline: CallbackDeadlineScheduler(timeout: .seconds(5)),
      timeoutError: MaintenanceFixtureError.injected
    ) { finish in
      let ready = self.lock.withLock {
        if self.callbacks.count >= count { return true }
        self.requested = (count, finish)
        return false
      }
      if ready { finish(.success(())) }
    }
  }

  func complete(_ result: Result<Void, Error>, at index: Int = 0) {
    let callback = lock.withLock {
      if index == callbacks.count - 1 {
        osCompletionDelivered = true
        if case .success = result { state = .notRegistered }
      }
      return callbacks[index]
    }
    callback(result)
  }

  func expire() throws {
    let action = try #require(lock.withLock { deadlineAction })
    action()
  }
}

private struct ControlledProxyUnregistration: ProxyAgentServicing {
  let shared: ControlledAuthorityUnregistration
  var registrationStatus: ProxyAgentRegistrationStatus {
    switch shared.registrationStatus {
    case .enabled: .enabled
    case .requiresApproval: .requiresApproval
    case .notRegistered: .notRegistered
    case .notFound: .notFound
    case .unknown: .unknown
    }
  }
  func requireRegistrationReady() throws { try shared.requireRegistrationReady() }
  func register() throws { try shared.register() }
  func unregister() async throws { try await shared.unregister() }
}

@Suite(.timeLimit(.minutes(1))) struct ServiceUnregistrationCompletionTests {
  private func maintainer(_ authority: ControlledAuthorityUnregistration)
    -> CurrentAppServiceMaintainer
  {
    CurrentAppServiceMaintainer(
      proxyAgent: MaintenanceProxyService([.notRegistered]), globalAuthority: authority)
  }

  @Test func oldImmediateReturnAllowsTheKnownUnsafeReregistrationSequence() async throws {
    let service = ControlledAuthorityUnregistration(legacyReturnsBeforeCompletion: true)
    let subject = maintainer(service)
    #expect(try await subject.perform(.unregister, on: .globalAuthority) == .notRegistered)
    await #expect(throws: CurrentAppServiceMaintenanceError.mutationFailed(.globalAuthority)) {
      try await subject.perform(.register, on: .globalAuthority)
    }
    #expect(service.registerCalls == 1)
    service.complete(.success(()))
  }

  @Test func currentMaintainerWaitsForCompletionBeforeReregistering() async throws {
    let service = ControlledAuthorityUnregistration()
    let subject = maintainer(service)
    let pending = Task { try await subject.perform(.unregister, on: .globalAuthority) }
    try await service.waitUntilSubmitted()
    #expect(service.registrationStatus == .notRegistered)
    await #expect(throws: CurrentAppServiceMaintenanceError.unregistrationPending(.globalAuthority))
    {
      try await subject.perform(.register, on: .globalAuthority)
    }
    await #expect(throws: CurrentAppServiceMaintenanceError.unregistrationPending(.globalAuthority))
    {
      try await subject.perform(.unregister, on: .globalAuthority)
    }
    #expect(throws: GlobalAuthorityRegistrationError.registrationFailed) {
      try SMGlobalAuthorityServiceController(service: service).ensureRegistered()
    }
    #expect(service.registerCalls == 0)
    #expect(service.unregisterCalls == 1)
    service.complete(.success(()))
    #expect(try await pending.value == .notRegistered)
    #expect(try await subject.perform(.register, on: .globalAuthority) == .enabled)
    #expect(service.registerCalls == 1)
  }

  @Test func callbackFailureDoesNotAdvanceRegistration() async throws {
    let service = ControlledAuthorityUnregistration()
    let subject = maintainer(service)
    let pending = Task { try await subject.perform(.unregister, on: .globalAuthority) }
    try await service.waitUntilSubmitted()
    service.complete(.failure(MaintenanceFixtureError.injected))
    await #expect(throws: CurrentAppServiceMaintenanceError.mutationFailed(.globalAuthority)) {
      try await pending.value
    }
    #expect(service.registerCalls == 0)
    #expect(service.registrationStatus == .notRegistered)
  }

  @Test(arguments: [false, true])
  func expiredOrCancelledWaitKeepsOrdinaryRegistrationBlocked(cancel: Bool) async throws {
    let service = ControlledAuthorityUnregistration(
      pendingProjection: cancel ? .enabled : .notRegistered)
    let subject = maintainer(service)
    let pending = Task { try await subject.perform(.unregister, on: .globalAuthority) }
    try await service.waitUntilSubmitted()
    if cancel {
      pending.cancel()
      await #expect(throws: CancellationError.self) { try await pending.value }
    } else {
      try service.expire()
      await #expect(
        throws: CurrentAppServiceMaintenanceError.unregistrationTimedOut(.globalAuthority)
      ) {
        try await pending.value
      }
    }
    #expect(throws: GlobalAuthorityRegistrationError.registrationFailed) {
      try SMGlobalAuthorityServiceController(service: service).ensureRegistered()
    }
    #expect(throws: (any Error).self) {
      try SMProxyAgentServiceController(
        service: ControlledProxyUnregistration(shared: service)
      ).ensureRegistered()
    }
    await #expect(throws: CurrentAppServiceMaintenanceError.unregistrationPending(.globalAuthority))
    {
      try await subject.perform(.register, on: .globalAuthority)
    }
    service.complete(.success(()))
    #expect(service.registerCalls == 0)
    try SMGlobalAuthorityServiceController(service: service).ensureRegistered()
    #expect(service.registerCalls == 1)
    // A duplicate old callback cannot release a later unregister epoch.
    let next = Task { try await subject.perform(.unregister, on: .globalAuthority) }
    try await service.waitUntilSubmitted(count: 2)
    service.complete(.success(()), at: 0)
    #expect(throws: ServiceUnregistrationError.self) { try service.requireRegistrationReady() }
    service.complete(.success(()), at: 1)
    #expect(try await next.value == .notRegistered)
    #expect(service.registerCalls == 1)
  }

  @Test(arguments: [false, true])
  func registrationThatRequiresApprovalRetainsItsType(registerThrows: Bool) async {
    let service = ControlledAuthorityUnregistration(
      initial: .notRegistered, registerResult: .requiresApproval, registerThrows: registerThrows)
    await #expect(throws: CurrentAppServiceMaintenanceError.approvalRequired(.globalAuthority)) {
      try await maintainer(service).perform(.register, on: .globalAuthority)
    }
    #expect(service.registrationStatus == .requiresApproval)
    #expect(service.registerCalls == 1)
  }

  @Test func alreadyCancelledCallerDoesNotSubmitUnregistration() async {
    let service = ControlledAuthorityUnregistration()
    let subject = maintainer(service)
    let pending = Task {
      withUnsafeCurrentTask { $0?.cancel() }
      return try await subject.perform(.unregister, on: .globalAuthority)
    }
    await #expect(throws: CancellationError.self) { try await pending.value }
    #expect(service.unregisterCalls == 0)
    #expect(service.registrationStatus == .enabled)
  }
}

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

  func requireRegistrationReady() throws {}

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

  func requireRegistrationReady() throws {}

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

  @Test func exactServicesRegisterAndUnregisterWithPostconditions() async throws {
    let proxy = MaintenanceProxyService([.enabled, .notRegistered])
    let authority = MaintenanceAuthorityService([.notRegistered, .enabled])
    let maintainer = CurrentAppServiceMaintainer(
      proxyAgent: proxy,
      globalAuthority: authority
    )

    #expect(
      try await maintainer.perform(.unregister, on: .proxyAgent) == .notRegistered)
    #expect(try await maintainer.perform(.register, on: .globalAuthority) == .enabled)
    #expect(proxy.unregisterCalls == 1)
    #expect(proxy.registerCalls == 0)
    #expect(authority.registerCalls == 1)
    #expect(authority.unregisterCalls == 0)
  }

  @Test func idempotentTerminalStatesDoNotRepeatMutation() async throws {
    let proxy = MaintenanceProxyService([.notRegistered])
    let authority = MaintenanceAuthorityService([.enabled])
    let maintainer = CurrentAppServiceMaintainer(
      proxyAgent: proxy,
      globalAuthority: authority
    )

    #expect(
      try await maintainer.perform(.unregister, on: .proxyAgent) == .notRegistered)
    #expect(try await maintainer.perform(.register, on: .globalAuthority) == .enabled)
    #expect(proxy.unregisterCalls == 0)
    #expect(authority.registerCalls == 0)
  }

  @Test func approvalUnknownMutationAndPostconditionFailuresStayDistinct() async {
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
      await #expect(throws: expected) {
        try await maintainer.perform(mutation, on: .proxyAgent)
      }
      switch expected {
      case .approvalRequired, .serviceNotFound, .statusUnknown:
        #expect(proxy.registerCalls == 0)
        #expect(proxy.unregisterCalls == 0)
      case .mutationFailed, .postconditionFailed, .unregistrationPending, .unregistrationTimedOut:
        #expect(proxy.unregisterCalls == 1)
      }
    }
  }

  @Test func maintenanceSurfaceNeverAddressesLegacyTombstone() {
    #expect(CurrentAppService.allCases == [.proxyAgent, .globalAuthority])
  }
}
