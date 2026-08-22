import Darwin
import Foundation

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
}

public protocol CurrentAppServiceMaintaining: Sendable {
  func status(of service: CurrentAppService) -> CurrentAppServiceStatus
  func perform(
    _ mutation: CurrentAppServiceMutation,
    on service: CurrentAppService
  ) throws -> CurrentAppServiceStatus
}

/// The narrow maintenance boundary for the two current SMAppService jobs.
///
/// Ordinary runtime registration remains owned by the existing controllers.
/// This type exists only so the signed Host can place an Off installation into
/// a dormant bundle-swap state and later restore the exact current services.
/// It deliberately has no surface for the legacy one-way tombstone.
public struct CurrentAppServiceMaintainer: CurrentAppServiceMaintaining, Sendable {
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
  ) throws -> CurrentAppServiceStatus {
    if mutation == .observe {
      return status(of: service)
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
      } catch {
        throw CurrentAppServiceMaintenanceError.mutationFailed(service)
      }
      guard status(of: service) == .enabled else {
        throw CurrentAppServiceMaintenanceError.postconditionFailed(service)
      }
      return .enabled
    case (.unregister, .enabled):
      do {
        try unregister(service)
      } catch {
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

  private func register(_ service: CurrentAppService) throws {
    switch service {
    case .proxyAgent: try proxyAgent.register()
    case .globalAuthority: try globalAuthority.register()
    }
  }

  private func unregister(_ service: CurrentAppService) throws {
    switch service {
    case .proxyAgent: try proxyAgent.unregister()
    case .globalAuthority: try globalAuthority.unregister()
    }
  }
}
