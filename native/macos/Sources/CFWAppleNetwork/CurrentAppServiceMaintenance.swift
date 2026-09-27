import Darwin
import Foundation
import OSLog
import SystemConfiguration

public enum CurrentSystemProxySwitchStatus: Equatable, Sendable {
  case disabled
  case enabled
  case unobservable
}

public protocol CurrentSystemProxySwitchObserving: Sendable {
  func status() -> CurrentSystemProxySwitchStatus
}

/// Read-only precondition for repairing orphaned services. This deliberately
/// cannot authorize normal engine use or attest a restored ownership journal.
public struct CurrentSystemProxySwitchObserver: CurrentSystemProxySwitchObserving {
  public init() {}

  public func status() -> CurrentSystemProxySwitchStatus {
    guard let effective = SCDynamicStoreCopyProxies(nil) as? [String: Any],
      let preferences = SCPreferencesCreate(nil, "Clash for Mac service repair" as CFString, nil),
      let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService],
      !services.isEmpty
    else { return .unobservable }
    let effectiveStatus = Self.classify(effective)
    guard effectiveStatus == .disabled else { return effectiveStatus }
    for service in services {
      guard let proxies = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies)
      else {
        continue
      }
      guard let configuration = SCNetworkProtocolGetConfiguration(proxies) as? [String: Any] else {
        continue
      }
      let status = Self.classify(configuration)
      guard status == .disabled else { return status }
    }
    return .disabled
  }

  static func classify(_ configuration: [String: Any]) -> CurrentSystemProxySwitchStatus {
    for field in [
      "HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable",
      "ProxyAutoDiscoveryEnable",
    ] {
      guard let value = configuration[field] else { continue }
      guard let number = value as? NSNumber else { return .unobservable }
      if number == 1 { return .enabled }
      guard number == 0 else { return .unobservable }
    }
    if let scoped = configuration["__SCOPED__"] {
      guard let configurations = scoped as? [String: [String: Any]], configurations.count <= 128
      else {
        return .unobservable
      }
      for configuration in configurations.values {
        guard configuration["__SCOPED__"] == nil, configuration["__SUPPLEMENTAL__"] == nil else {
          return .unobservable
        }
        let status = classify(configuration)
        guard status == .disabled else { return status }
      }
    }
    if let supplemental = configuration["__SUPPLEMENTAL__"] {
      guard let configurations = supplemental as? [[String: Any]], configurations.count <= 128
      else {
        return .unobservable
      }
      for configuration in configurations {
        guard configuration["__SCOPED__"] == nil, configuration["__SUPPLEMENTAL__"] == nil else {
          return .unobservable
        }
        let status = classify(configuration)
        guard status == .disabled else { return status }
      }
    }
    return .disabled
  }
}

public enum CurrentAppService: UInt32, CaseIterable, Sendable {
  case proxyAgent = 1
  case globalAuthority = 2
}

public enum CurrentAppServiceMutation: UInt32, Sendable {
  case observe = 0
  case register = 1
  case unregister = 2
}

public enum CurrentAppServiceStatus: Int32, Codable, Equatable, Hashable, Sendable {
  case enabled = 0
  case requiresApproval = 1
  case notRegistered = 2
  case notFound = 3
  case unknown = 4
}

public enum CurrentAppServiceRuntimeStatus: Equatable, Sendable {
  case absent
  case present
  case unobservable
}

public protocol CurrentAppServiceRuntimeObserving: Sendable {
  func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus
}

/// A bounded, read-only process observer for the two fixed current services.
///
/// Registration state alone is not a process-absence proof: an unregister may
/// have completed while its old process is still exiting. Two identical
/// libproc snapshots are therefore required before absence or presence is
/// projected. Enumeration failure, truncation, a racing matching process, or
/// an inaccessible matching process remains explicitly unobservable.
public struct CurrentAppServiceRuntimeObserver: CurrentAppServiceRuntimeObserving {
  private static let maximumProcessInventoryBytes = 1 << 20
  private static let inventorySlackBytes = 4096
  private static let installedBundlePath = "/Applications/Clash for Mac.app"
  private let currentBundlePath: String?

  public init() {
    self.init(currentBundleURL: Bundle.main.bundleURL)
  }

  init(currentBundleURL: URL) {
    let standardized = currentBundleURL.standardizedFileURL
    let resolved = standardized.resolvingSymlinksInPath()
    currentBundlePath =
      standardized.isFileURL
        && standardized.path.hasPrefix("/")
        && standardized.path == resolved.path
      ? standardized.path : nil
  }

  public func status(of service: CurrentAppService) -> CurrentAppServiceRuntimeStatus {
    guard let currentBundlePath else { return .unobservable }
    let identity = Self.identity(for: service, currentBundlePath: currentBundlePath)
    guard
      let first = Self.matchingProcessIdentifiers(identity),
      let second = Self.matchingProcessIdentifiers(identity),
      first == second
    else {
      return .unobservable
    }
    return first.isEmpty ? .absent : .present
  }

  private static func identity(
    for service: CurrentAppService,
    currentBundlePath: String
  ) -> (name: String, paths: Set<String>) {
    let relativePath: String
    let name: String
    switch service {
    case .proxyAgent:
      name = "CFWProxyAgent"
      relativePath =
        "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent"
    case .globalAuthority:
      name = "CFWGlobalAuthority"
      relativePath = "Contents/Library/HelperTools/CFWGlobalAuthority"
    }
    return (
      name,
      [installedBundlePath, currentBundlePath].reduce(into: Set<String>()) {
        paths, bundlePath in
        paths.insert(
          URL(fileURLWithPath: bundlePath, isDirectory: true)
            .appendingPathComponent(relativePath, isDirectory: false)
            .path)
      }
    )
  }

  private static func matchingProcessIdentifiers(
    _ identity: (name: String, paths: Set<String>)
  ) -> Set<pid_t>? {
    let requestedBytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
    guard requestedBytes > 0 else { return nil }
    let capacityBytes = Int(requestedBytes) + inventorySlackBytes
    guard capacityBytes <= maximumProcessInventoryBytes else { return nil }

    let processCapacity = capacityBytes / MemoryLayout<pid_t>.stride
    var processIdentifiers = [pid_t](repeating: 0, count: processCapacity)
    let allocatedBytes = processIdentifiers.count * MemoryLayout<pid_t>.stride
    let returnedBytes = processIdentifiers.withUnsafeMutableBytes { buffer in
      proc_listpids(
        UInt32(PROC_ALL_PIDS),
        0,
        buffer.baseAddress,
        Int32(allocatedBytes)
      )
    }
    guard
      isCompleteProcessInventory(
        returnedBytes: returnedBytes,
        capacityBytes: allocatedBytes
      )
    else { return nil }

    var matches = Set<pid_t>()
    let returnedCount = Int(returnedBytes) / MemoryLayout<pid_t>.stride
    for processIdentifier in processIdentifiers.prefix(returnedCount)
    where processIdentifier > 0 {
      var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
      let pathLength = pathBuffer.withUnsafeMutableBytes { buffer in
        proc_pidpath(
          processIdentifier,
          buffer.baseAddress,
          UInt32(buffer.count)
        )
      }
      if pathLength <= 0 || Int(pathLength) >= pathBuffer.count {
        var nameBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let nameLength = nameBuffer.withUnsafeMutableBytes { buffer in
          proc_name(
            processIdentifier,
            buffer.baseAddress,
            UInt32(buffer.count)
          )
        }
        errno = 0
        if nameLength > 0,
          Int(nameLength) < nameBuffer.count,
          decode(nameBuffer, length: nameLength) == identity.name,
          kill(processIdentifier, 0) == 0 || errno == EPERM
        {
          return nil
        }
        continue
      }
      if let path = decode(pathBuffer, length: pathLength) {
        if identity.paths.contains(path) {
          matches.insert(processIdentifier)
        } else if isUnexpectedServiceExecutable(
          path: path,
          name: identity.name,
          allowedPaths: identity.paths
        ) {
          return nil
        }
      }
    }
    return matches
  }

  static func isCompleteProcessInventory(
    returnedBytes: Int32,
    capacityBytes: Int
  ) -> Bool {
    returnedBytes > 0
      && Int(returnedBytes) < capacityBytes
      && Int(returnedBytes) % MemoryLayout<pid_t>.stride == 0
  }

  static func serviceExecutablePaths(
    _ service: CurrentAppService,
    currentBundlePath: String
  ) -> Set<String> {
    identity(for: service, currentBundlePath: currentBundlePath).paths
  }

  static func isUnexpectedServiceExecutable(
    path: String,
    name: String,
    allowedPaths: Set<String>
  ) -> Bool {
    URL(fileURLWithPath: path, isDirectory: false).lastPathComponent == name
      && !allowedPaths.contains(path)
  }

  private static func decode(_ buffer: [CChar], length: Int32) -> String? {
    guard length > 0, Int(length) < buffer.count else { return nil }
    let bytes = buffer.prefix(Int(length)).map(UInt8.init(bitPattern:))
    return String(bytes: bytes, encoding: .utf8)
  }
}

public enum CurrentAppServiceMaintenanceError: Error, Equatable, Sendable {
  case approvalRequired(CurrentAppService)
  case serviceNotFound(CurrentAppService)
  case statusUnknown(CurrentAppService)
  case mutationFailed(CurrentAppService)
  case postconditionFailed(CurrentAppService)
  case unregistrationPending(CurrentAppService)
  case unregistrationTimedOut(CurrentAppService)
}

enum ServiceUnregistrationError: Error { case pending, timedOut }

/// SMAppService's asynchronous completion is the re-registration barrier.
/// Caller cancellation/deadline ends only that wait; the uncancellable OS
/// operation keeps this instance blocked until its own completion arrives.
final class ServiceUnregistrationBarrier: @unchecked Sendable {
  private let lock = NSLock()
  private var pending: UUID?

  func requireRegistrationReady() throws {
    try lock.withLock {
      guard pending == nil else { throw ServiceUnregistrationError.pending }
    }
  }

  func register(_ operation: () throws -> Void) throws {
    try lock.withLock {
      guard pending == nil else { throw ServiceUnregistrationError.pending }
      try operation()
    }
  }

  func unregister(
    deadline: CallbackDeadlineScheduler = CallbackDeadlineScheduler(timeout: .seconds(5)),
    operation: @escaping (@escaping @Sendable (Result<Void, Error>) -> Void) -> Void
  ) async throws {
    let epoch = UUID()
    let _: Void = try await awaitBoundedCallback(
      deadline: deadline, timeoutError: ServiceUnregistrationError.timedOut
    ) { finish in
      let began = self.lock.withLock {
        guard self.pending == nil else { return false }
        self.pending = epoch
        return true
      }
      guard began else {
        finish(.failure(ServiceUnregistrationError.pending))
        return
      }
      operation { result in
        let current = self.lock.withLock {
          guard self.pending == epoch else { return false }
          self.pending = nil
          return true
        }
        if current { finish(result) }
      }
    }
    try Task.checkCancellation()
  }
}

public protocol CurrentAppServiceMaintaining: Sendable {
  func status(of service: CurrentAppService) -> CurrentAppServiceStatus
  func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService
  ) async throws -> CurrentAppServiceStatus
}

/// The narrow maintenance boundary for the two current SMAppService jobs.
///
/// Ordinary runtime registration remains owned by the existing controllers.
/// This type exists only so the signed Host can place an Off installation into
/// a dormant bundle-swap state and later restore the exact current services.
/// It deliberately has no surface for the legacy one-way tombstone.
public struct CurrentAppServiceMaintainer: CurrentAppServiceMaintaining, Sendable {
  private static let log = Logger(
    subsystem: "com.bill.clashformac", category: "service-maintenance")
  private let proxyAgent: any ProxyAgentServicing
  private let globalAuthority: any GlobalAuthorityDaemonServicing

  public init(
    proxyAgent: any ProxyAgentServicing = SMProxyAgentService(),
    globalAuthority: any GlobalAuthorityDaemonServicing = SMGlobalAuthorityDaemonService()
  ) {
    self.proxyAgent = proxyAgent
    self.globalAuthority = globalAuthority
  }

  public func status(of service: CurrentAppService) -> CurrentAppServiceStatus {
    switch service {
    case .proxyAgent:
      switch proxyAgent.registrationStatus {
      case .enabled: .enabled
      case .requiresApproval: .requiresApproval
      case .notRegistered: .notRegistered
      case .notFound: .notFound
      case .unknown: .unknown
      }
    case .globalAuthority:
      switch globalAuthority.registrationStatus {
      case .enabled: .enabled
      case .requiresApproval: .requiresApproval
      case .notRegistered: .notRegistered
      case .notFound: .notFound
      case .unknown: .unknown
      }
    }
  }

  public func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService
  ) async throws -> CurrentAppServiceStatus {
    try Task.checkCancellation()
    if mutation == .observe {
      return status(of: service)
    }
    // NotRegistered does not itself prove that an earlier asynchronous
    // unregister has completed. Reject even an otherwise idempotent retry.
    if mutation != .observe {
      do {
        switch service {
        case .proxyAgent: try proxyAgent.requireRegistrationReady()
        case .globalAuthority: try globalAuthority.requireRegistrationReady()
        }
      } catch ServiceUnregistrationError.pending {
        throw CurrentAppServiceMaintenanceError.unregistrationPending(service)
      } catch {
        throw CurrentAppServiceMaintenanceError.mutationFailed(service)
      }
    }
    let initial = status(of: service)
    switch (mutation, initial) {
    case (_, .requiresApproval):
      throw CurrentAppServiceMaintenanceError.approvalRequired(service)
    case (_, .notFound):
      throw CurrentAppServiceMaintenanceError.serviceNotFound(service)
    case (_, .unknown):
      throw CurrentAppServiceMaintenanceError.statusUnknown(service)
    case (.register, .enabled), (.unregister, .notRegistered):
      return initial
    case (.register, .notRegistered):
      do {
        try register(service)
      } catch ServiceUnregistrationError.pending {
        throw CurrentAppServiceMaintenanceError.unregistrationPending(service)
      } catch {
        Self.recordMutationFailure(error, mutation: .register, service: service)
        if status(of: service) == .requiresApproval {
          throw CurrentAppServiceMaintenanceError.approvalRequired(service)
        }
        throw CurrentAppServiceMaintenanceError.mutationFailed(service)
      }
      let final = status(of: service)
      if final == .requiresApproval {
        throw CurrentAppServiceMaintenanceError.approvalRequired(service)
      }
      guard final == .enabled else {
        throw CurrentAppServiceMaintenanceError.postconditionFailed(service)
      }
      return .enabled
    case (.unregister, .enabled):
      do {
        try await unregister(service)
        try Task.checkCancellation()
      } catch is CancellationError {
        throw CancellationError()
      } catch ServiceUnregistrationError.pending {
        throw CurrentAppServiceMaintenanceError.unregistrationPending(service)
      } catch ServiceUnregistrationError.timedOut {
        throw CurrentAppServiceMaintenanceError.unregistrationTimedOut(service)
      } catch {
        Self.recordMutationFailure(error, mutation: .unregister, service: service)
        throw CurrentAppServiceMaintenanceError.mutationFailed(service)
      }
      let final = status(of: service)
      guard final == .notRegistered else {
        throw CurrentAppServiceMaintenanceError.postconditionFailed(service)
      }
      return final
    case (.observe, _):
      return initial
    }
  }

  private static func recordMutationFailure(
    _ error: Error, mutation: CurrentAppServiceMutation, service: CurrentAppService
  ) {
    let failure = error as NSError
    let knownDomains = [
      NSPOSIXErrorDomain, NSCocoaErrorDomain, NSOSStatusErrorDomain, NSMachErrorDomain,
      "SMAppServiceErrorDomain", "kSMErrorDomain",
    ]
    let domain = knownDomains.contains(failure.domain) ? failure.domain : "unclassified"
    log.error(
      "Service mutation failed: service=\(service.rawValue) mutation=\(mutation.rawValue) domain=\(domain, privacy: .public) code=\(failure.code)"
    )
  }

  private func register(_ service: CurrentAppService) throws {
    switch service {
    case .proxyAgent: try proxyAgent.register()
    case .globalAuthority: try globalAuthority.register()
    }
  }

  private func unregister(_ service: CurrentAppService) async throws {
    switch service {
    case .proxyAgent: try await proxyAgent.unregister()
    case .globalAuthority: try await globalAuthority.unregister()
    }
  }
}
