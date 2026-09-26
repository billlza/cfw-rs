import CFWAppleNetwork
import Foundation

/// Existing coordinator tests explicitly use an in-memory, current-build pair.
/// Production has no default observer that could bypass signed-code inspection.
struct FixedCurrentServiceBuildObserver: CurrentAppServiceBuildObserving {
  func inspect() throws -> CurrentAppServiceBuildInspection {
    let code = try CurrentAppServiceCodeIdentity(
      build: 50010, cdHash: Data(repeating: 0x42, count: 20))
    let observation = CurrentAppServiceBuildObservation(
      registration: .enabled, runningCode: code, expectedCode: code)
    return .init(proxy: observation, authority: observation)
  }
}

final class ServiceUpgradeFixture: CurrentAppServiceMaintaining,
  CurrentAppServiceBuildObserving, @unchecked Sendable
{
  private let lock = NSLock()
  private var proxyStatus: CurrentAppServiceStatus = .enabled
  private var authorityStatus: CurrentAppServiceStatus = .enabled
  private var currentProxy = false
  private var currentAuthority = false
  private var remainingInspectionFailures: Int
  private let failAfterProxyUnregister: Bool
  private let cancelAfterProxyUnregister: Bool
  private let conflictingInspection: Int?
  private let failedMutation: String?
  private var inspections = 0
  private var events: [String] = []

  init(
    inspectionFailures: Int = 0, failAfterProxyUnregister: Bool = false,
    cancelAfterProxyUnregister: Bool = false,
    proxyStatus: CurrentAppServiceStatus = .enabled,
    authorityStatus: CurrentAppServiceStatus = .enabled,
    conflictingInspection: Int? = nil,
    failedMutation: String? = nil
  ) {
    remainingInspectionFailures = inspectionFailures
    self.failAfterProxyUnregister = failAfterProxyUnregister
    self.cancelAfterProxyUnregister = cancelAfterProxyUnregister
    self.proxyStatus = proxyStatus
    self.authorityStatus = authorityStatus
    self.conflictingInspection = conflictingInspection
    self.failedMutation = failedMutation
  }

  var inspectionCount: Int { lock.withLock { inspections } }
  var mutations: [String] { lock.withLock { events } }

  func markCurrent() {
    lock.withLock {
      currentProxy = true
      currentAuthority = true
    }
  }
  func markOld() {
    lock.withLock {
      currentProxy = false
      currentAuthority = false
    }
  }

  func status(of service: CurrentAppService) -> CurrentAppServiceStatus {
    lock.withLock { service == .proxyAgent ? proxyStatus : authorityStatus }
  }

  func setStatus(_ status: CurrentAppServiceStatus, of service: CurrentAppService) {
    lock.withLock {
      if service == .proxyAgent { proxyStatus = status } else { authorityStatus = status }
    }
  }

  func inspect() throws -> CurrentAppServiceBuildInspection {
    try lock.withLock {
      inspections += 1
      if remainingInspectionFailures > 0 {
        remainingInspectionFailures -= 1
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      let expected = try CurrentAppServiceCodeIdentity(
        build: 50010, cdHash: Data(repeating: 0x42, count: 20))
      let previous = try CurrentAppServiceCodeIdentity(
        build: 50009, cdHash: Data(repeating: 0x41, count: 20))
      let proxyCode =
        inspections == conflictingInspection
        ? try CurrentAppServiceCodeIdentity(build: 50010, cdHash: Data(repeating: 0x43, count: 20))
        : (currentProxy ? expected : previous)
      return .init(
        proxy: .init(
          registration: proxyStatus,
          runningCode: proxyStatus == .notRegistered ? nil : proxyCode,
          expectedCode: expected),
        authority: .init(
          registration: authorityStatus,
          runningCode: authorityStatus == .notRegistered
            ? nil : (currentAuthority ? expected : previous),
          expectedCode: expected))
    }
  }

  func perform(_ mutation: CurrentAppServiceMutation, on service: CurrentAppService) throws
    -> CurrentAppServiceStatus
  {
    try lock.withLock {
      if mutation == .observe { return service == .proxyAgent ? proxyStatus : authorityStatus }
      events.append("\(mutation):\(service)")
      if failedMutation == "\(mutation):\(service)" {
        throw CurrentAppServiceMaintenanceError.mutationFailed(service)
      }
      let status: CurrentAppServiceStatus = mutation == .register ? .enabled : .notRegistered
      if service == .proxyAgent {
        proxyStatus = status
        if mutation == .register { currentProxy = true }
      } else {
        authorityStatus = status
        if mutation == .register { currentAuthority = true }
      }
      if cancelAfterProxyUnregister, mutation == .unregister, service == .proxyAgent {
        withUnsafeCurrentTask { $0?.cancel() }
      }
      if failAfterProxyUnregister, mutation == .unregister, service == .proxyAgent {
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      return status
    }
  }
}

struct ServiceUpgradeAbsentRuntimeObserver: CurrentAppServiceRuntimeObserving {
  func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus { .absent }
}

struct ServiceUpgradeDisabledProxyObserver: CurrentSystemProxySwitchObserving {
  func status() -> CurrentSystemProxySwitchStatus { .disabled }
}

struct ServiceUpgradeRuntimeState: CurrentAppServiceRuntimeObserving {
  let authority: CurrentAppServiceRuntimeStatus
  func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus {
    service == .globalAuthority ? authority : .absent
  }
}

struct ServiceUpgradeSystemProxyState: CurrentSystemProxySwitchObserving {
  let observed: CurrentSystemProxySwitchStatus
  func status() -> CurrentSystemProxySwitchStatus { observed }
}
