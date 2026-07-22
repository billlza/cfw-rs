import CFWSharedProtocol
import Darwin
import Foundation

public enum LibboxRuntimeRole: String, Codable, Equatable, Sendable {
  case systemProxy
  case packetTunnel

  fileprivate var directoryName: String {
    switch self {
    case .systemProxy:
      "LibboxProxy"
    case .packetTunnel:
      "LibboxTunnel"
    }
  }
}

public enum LibboxRuntimeError: Error, Equatable, Sendable {
  case libboxUnavailable
  case missingBundleSetting(String)
  case appGroupUnavailable(String)
  case unsafeRuntimeDirectory(String)
  case invalidConfigurationSize(Int)
  case invalidConfigurationEncoding
  case invalidConfigurationJSON
  case configurationCheckFailed(String)
  case unexpectedPacketDescriptor
  case missingPacketDescriptor
  case packetDescriptorAlreadyTransferred
  case unsupportedPlatformOperation(String)
  case networkMonitorAlreadyStarted
  case networkMonitorUnavailable
  case networkMonitorTimedOut
  case alreadyStarted
  case setupConflict
  case setupFailed(String)
  case serverCreationFailed(String)
  case serviceStartFailed(String)
  case serviceStartCleanupFailed(start: String, cleanup: String)
  case serviceNotRunning(state: Int32, message: String)
  case serviceStopFailed(String)
}

extension LibboxRuntimeError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .libboxUnavailable:
      return "The pinned source-built libbox framework is unavailable."
    case .missingBundleSetting(let key):
      return "Required libbox runtime setting \(key) is missing."
    case .appGroupUnavailable(let identifier):
      return "The libbox App Group \(identifier) is unavailable."
    case .unsafeRuntimeDirectory(let message):
      return "The libbox runtime directory is unsafe: \(message)"
    case .invalidConfigurationSize(let size):
      return "The libbox configuration has an invalid size: \(size) bytes."
    case .invalidConfigurationEncoding:
      return "The libbox configuration is not UTF-8."
    case .invalidConfigurationJSON:
      return "The libbox configuration is not a JSON object."
    case .configurationCheckFailed(let message):
      return "libbox rejected the configuration: \(message)"
    case .unexpectedPacketDescriptor:
      return "System Proxy must not receive a packet-flow descriptor."
    case .missingPacketDescriptor:
      return "Packet Tunnel requires one packet-flow descriptor."
    case .packetDescriptorAlreadyTransferred:
      return "The packet-flow descriptor was already transferred."
    case .unsupportedPlatformOperation(let operation):
      return "The libbox platform operation \(operation) is not supported."
    case .networkMonitorAlreadyStarted:
      return "The libbox default-interface monitor is already running."
    case .networkMonitorUnavailable:
      return "The libbox default-interface monitor is unavailable."
    case .networkMonitorTimedOut:
      return "The libbox default-interface monitor did not produce an initial path."
    case .alreadyStarted:
      return "The libbox runtime is already starting or active."
    case .setupConflict:
      return "The process attempted to initialize libbox with different directories."
    case .setupFailed(let message):
      return "libbox setup failed: \(message)"
    case .serverCreationFailed(let message):
      return "libbox service creation failed: \(message)"
    case .serviceStartFailed(let message):
      return "libbox service startup failed: \(message)"
    case .serviceStartCleanupFailed(let start, let cleanup):
      return "libbox startup failed (\(start)); cleanup also failed (\(cleanup))."
    case .serviceNotRunning(let state, let message):
      return "libbox runtime state is \(state): \(message)"
    case .serviceStopFailed(let message):
      return "libbox service stop failed: \(message)"
    }
  }
}

public struct LibboxRuntimeDirectories: Equatable, Sendable {
  public let base: URL
  public let working: URL
  public let temporary: URL

  public static func fromMainBundle(role: LibboxRuntimeRole) throws
    -> LibboxRuntimeDirectories
  {
    if role == .packetTunnel {
      guard
        let applicationSupport = FileManager.default.urls(
          for: .applicationSupportDirectory,
          in: .userDomainMask
        ).first
      else {
        throw LibboxRuntimeError.unsafeRuntimeDirectory(
          "The system extension Application Support container is unavailable."
        )
      }
      // A sandboxed system extension owns this container. It intentionally
      // does not share an App Group path with the user-context host or Agent.
      return try prepare(container: applicationSupport, role: role)
    }
    guard
      let identifier = Bundle.main.object(forInfoDictionaryKey: "CFWAppGroupIdentifier")
        as? String,
      !identifier.isEmpty
    else {
      throw LibboxRuntimeError.missingBundleSetting("CFWAppGroupIdentifier")
    }
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: identifier
      )
    else {
      throw LibboxRuntimeError.appGroupUnavailable(identifier)
    }
    return try prepare(container: container, role: role)
  }

  public static func prepare(container: URL, role: LibboxRuntimeRole) throws
    -> LibboxRuntimeDirectories
  {
    let base = container.appendingPathComponent(role.directoryName, isDirectory: true)
    let working = base.appendingPathComponent("Working", isDirectory: true)
    let temporary = base.appendingPathComponent("Temporary", isDirectory: true)
    let baseFD: Int32
    do {
      baseFD = try SecureAppGroupFileSystem.createAndOpenPrivateDirectory(at: base)
    } catch {
      throw LibboxRuntimeError.unsafeRuntimeDirectory(error.localizedDescription)
    }
    defer { Darwin.close(baseFD) }
    do {
      let workingFD = try SecureAppGroupFileSystem.createAndOpenPrivateSubdirectory(
        in: baseFD,
        named: "Working"
      )
      Darwin.close(workingFD)
      let temporaryFD = try SecureAppGroupFileSystem.createAndOpenPrivateSubdirectory(
        in: baseFD,
        named: "Temporary"
      )
      Darwin.close(temporaryFD)
    } catch {
      throw LibboxRuntimeError.unsafeRuntimeDirectory(error.localizedDescription)
    }
    return LibboxRuntimeDirectories(base: base, working: working, temporary: temporary)
  }

  public func validate() throws {
    let baseFD: Int32
    do {
      baseFD = try SecureAppGroupFileSystem.openPrivateDirectory(at: base)
    } catch {
      throw LibboxRuntimeError.unsafeRuntimeDirectory(error.localizedDescription)
    }
    defer { Darwin.close(baseFD) }
    for name in ["Working", "Temporary"] {
      do {
        let childFD = try SecureAppGroupFileSystem.createAndOpenPrivateSubdirectory(
          in: baseFD,
          named: name
        )
        Darwin.close(childFD)
      } catch {
        throw LibboxRuntimeError.unsafeRuntimeDirectory(error.localizedDescription)
      }
    }
  }
}

public protocol LibboxServiceRuntime: AnyObject {
  /// Takes ownership of packetFileDescriptor on every path when one is supplied.
  func start(configuration: Data, packetFileDescriptor: Int32?) throws
  func stop() throws
  func healthCheck() throws
  func resetNetwork()
}

public protocol LibboxServiceRuntimeFactory: Sendable {
  func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime
}

public struct SourceBuiltLibboxRuntimeFactory: LibboxServiceRuntimeFactory {
  public init() {}

  public func makeRuntime(role: LibboxRuntimeRole) throws -> any LibboxServiceRuntime {
    #if canImport(Libbox) && canImport(CFWLibboxObjC)
      return try SourceBuiltLibboxServiceRuntime(
        role: role,
        directories: LibboxRuntimeDirectories.fromMainBundle(role: role)
      )
    #else
      throw LibboxRuntimeError.libboxUnavailable
    #endif
  }
}
