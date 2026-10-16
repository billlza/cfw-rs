import CFWSharedProtocol
import Darwin
import Foundation

#if CFW_LINKED_LIBBOX && !canImport(Libbox)
  #error("The native runtime target requires the Libbox module.")
#endif
#if CFW_LINKED_LIBBOX && !canImport(CFWLibboxObjC)
  #error("The native runtime target requires the CFWLibboxObjC module.")
#endif

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

public enum LibboxRuntimeEndpointRole: String, Equatable, Sendable {
  case mixed
  case controller
}

public struct LibboxRuntimeEndpointConflict: Equatable, Sendable {
  public let role: LibboxRuntimeEndpointRole
  public let port: UInt16

  public static func validated(
    kind: Int32,
    port: Int32,
    mixedKind: Int32,
    controllerKind: Int32,
    receipt: LibboxRuntimeStartReceipt,
    runtimeRole: LibboxRuntimeRole
  ) throws -> LibboxRuntimeEndpointConflict {
    guard mixedKind != controllerKind,
      port > 0,
      port <= Int32(UInt16.max),
      let exactPort = UInt16(exactly: port)
    else {
      throw LibboxRuntimeError.invalidEndpointConflict(kind: kind, port: port)
    }

    let endpointRole: LibboxRuntimeEndpointRole
    switch kind {
    case mixedKind:
      guard runtimeRole == .systemProxy,
        receipt.mixedListener?.port == exactPort
      else {
        throw LibboxRuntimeError.invalidEndpointConflict(kind: kind, port: port)
      }
      endpointRole = .mixed
    case controllerKind:
      guard receipt.controllerListener.port == exactPort else {
        throw LibboxRuntimeError.invalidEndpointConflict(kind: kind, port: port)
      }
      endpointRole = .controller
    default:
      throw LibboxRuntimeError.invalidEndpointConflict(kind: kind, port: port)
    }
    return LibboxRuntimeEndpointConflict(role: endpointRole, port: exactPort)
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
  case configurationCheckFailed(LibboxDiagnostic)
  /// libbox accepted the configuration but could not close the instance it
  /// built to check it.
  case configurationCheckCleanupFailed(LibboxDiagnostic)
  /// libbox returned neither a check nor an error, which its API never does.
  case configurationCheckReturnedNothing
  case unexpectedPacketDescriptor
  case missingPacketDescriptor
  case packetDescriptorAlreadyTransferred
  case unsupportedPlatformOperation(String)
  case networkMonitorAlreadyStarted
  case networkMonitorUnavailable
  case networkMonitorTimedOut
  case alreadyStarted
  case setupConflict
  case setupFailed(LibboxDiagnostic)
  case serverCreationFailed(LibboxDiagnostic)
  case serviceStartFailed(LibboxDiagnostic)
  /// The start did not finish by its owner's deadline (`EngineStartBudget`):
  /// it was interrupted then, or too little time was left to begin it.
  case serviceStartTimedOut
  case invalidRuntimeEndpoints
  case invalidEndpointConflict(kind: Int32, port: Int32)
  case endpointConflict(role: LibboxRuntimeEndpointRole, port: UInt16)
  case serviceNotRunning(state: Int32, message: LibboxDiagnostic)
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
    case .configurationCheckFailed:
      return "libbox rejected the configuration."
    case .configurationCheckCleanupFailed:
      return "libbox could not close the instance it built to check the configuration."
    case .configurationCheckReturnedNothing:
      return "libbox returned neither a configuration check nor an error."
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
    case .setupFailed:
      return "libbox setup failed."
    case .serverCreationFailed:
      return "libbox service creation failed."
    case .serviceStartFailed:
      return "libbox service startup failed."
    case .serviceStartTimedOut:
      let seconds = EngineStartBudget.ownerLibboxStart.components.seconds
      return
        "libbox service startup did not finish within the \(seconds) seconds an engine start may take."
    case .invalidRuntimeEndpoints:
      return
        "The libbox configuration does not contain the exact application-owned loopback endpoints."
    case .invalidEndpointConflict(let kind, let port):
      return
        "libbox returned an endpoint conflict that does not match the start receipt (kind \(kind), port \(port))."
    case .endpointConflict(let role, let port):
      return "The libbox \(role.rawValue) endpoint could not bind to port \(port)."
    case .serviceNotRunning(let state, _):
      return "libbox runtime state is \(state)."
    }
  }
}

/// Text libbox reported. libbox's errors can name outbounds, servers and paths,
/// so the text never leaves this process: it prints as a placeholder, reflects
/// nothing, and only this module and its tests can read it.
public struct LibboxDiagnostic: Equatable, Sendable, CustomStringConvertible,
  CustomDebugStringConvertible, CustomReflectable
{
  let text: String

  init(_ text: String) {
    self.text = text
  }

  public var description: String { "<libbox diagnostic>" }
  public var debugDescription: String { description }
  public var customMirror: Mirror { Mirror(self, children: []) }
}

/// libbox could not close a service instance. libbox closes an instance once
/// (`Box.Close` reports `os.ErrClosed` from then on), so whatever that close left
/// open stays in this process until the process ends. A close, or an
/// interrupted start, that does not return within its bound counts alike: a
/// thread stays inside libbox, so nothing it may still use can be released.
/// The runtime that throws it is spent: it never starts, closes or reports idle
/// again. Its initializers are internal, so only the runtime makes one.
public struct LibboxInstanceUnclosable: Error, Equatable, Sendable {
  enum Cause: Equatable, Sendable {
    /// libbox's close reported this failure, which never leaves this process.
    case closeFailed(LibboxDiagnostic)
    /// The close had not returned within `EngineStopBudget.libboxClose`.
    case closeDidNotReturn
    /// The start its deadline interrupted, or that interrupt, had not returned
    /// within `EngineStartBudget.interruptLimit`.
    case interruptDidNotReturn
  }

  let cause: Cause

  init(closeFailure: String) {
    cause = .closeFailed(LibboxDiagnostic(closeFailure))
  }

  init(_ cause: Cause) {
    self.cause = cause
  }
}

extension LibboxInstanceUnclosable: LocalizedError {
  public var errorDescription: String? {
    "libbox could not close its service instance."
  }
}

extension LibboxInstanceUnclosable.Cause {
  /// What kept the instance open, for logs: never libbox's own text.
  var kind: String {
    switch self {
    case .closeFailed: "close failed"
    case .closeDidNotReturn: "close did not return"
    case .interruptDidNotReturn: "interrupt did not return"
    }
  }
}

public struct LibboxLoopbackTCPEndpoint: Equatable, Sendable {
  public let host: String
  public let port: UInt16

  public init(host: String, port: UInt16) throws {
    guard host == "127.0.0.1", port > 0 else {
      throw LibboxRuntimeError.invalidRuntimeEndpoints
    }
    self.host = host
    self.port = port
  }
}

/// Exact local listeners admitted by one source-built libbox start.
///
/// The receipt is derived from the same configuration bytes passed to libbox
/// and is returned only after the runtime reports Started. A separate TCP
/// connect could hit a foreign process and cannot establish ownership.
public struct LibboxRuntimeStartReceipt: Equatable, Sendable {
  public let mixedListener: LibboxLoopbackTCPEndpoint?
  public let controllerListener: LibboxLoopbackTCPEndpoint
  let processPolicy: LibboxProcessLookupPolicy

  public static func parse(
    configuration: Data,
    role: LibboxRuntimeRole
  ) throws -> LibboxRuntimeStartReceipt {
    guard configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      let root = try? JSONSerialization.jsonObject(with: configuration) as? [String: Any],
      let experimental = root["experimental"] as? [String: Any],
      let clashAPI = experimental["clash_api"] as? [String: Any],
      let controllerText = clashAPI["external_controller"] as? String,
      let secret = clashAPI["secret"] as? String,
      !secret.isEmpty
    else {
      throw LibboxRuntimeError.invalidRuntimeEndpoints
    }
    let controller = try parseController(controllerText)
    let processPolicy = try LibboxProcessLookupPolicy.parse(root)
    let inbounds = root["inbounds"] as? [[String: Any]] ?? []
    let mixed = inbounds.filter { inbound in
      inbound["type"] as? String == "mixed"
        && inbound["tag"] as? String == "cfw-system-proxy"
    }
    if !mixed.isEmpty {
      guard mixed.count == 1,
        let host = mixed[0]["listen"] as? String,
        let port = exactPort(mixed[0]["listen_port"]),
        let mixedListener = try? LibboxLoopbackTCPEndpoint(host: host, port: port),
        mixedListener.port != controller.port
      else {
        throw LibboxRuntimeError.invalidRuntimeEndpoints
      }
      return LibboxRuntimeStartReceipt(
        mixedListener: mixedListener,
        controllerListener: controller,
        processPolicy: processPolicy
      )
    }
    guard role == .packetTunnel else {
      throw LibboxRuntimeError.invalidRuntimeEndpoints
    }
    return LibboxRuntimeStartReceipt(
      mixedListener: nil, controllerListener: controller, processPolicy: processPolicy)
  }

  private static func parseController(
    _ value: String
  ) throws -> LibboxLoopbackTCPEndpoint {
    let components = value.split(separator: ":", omittingEmptySubsequences: false)
    guard components.count == 2,
      components[0] == "127.0.0.1",
      let port = UInt16(components[1]),
      port > 0
    else {
      throw LibboxRuntimeError.invalidRuntimeEndpoints
    }
    return try LibboxLoopbackTCPEndpoint(host: "127.0.0.1", port: port)
  }

  private static func exactPort(_ value: Any?) -> UInt16? {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID(),
      number.int64Value > 0,
      number.int64Value <= Int64(UInt16.max),
      Double(number.int64Value) == number.doubleValue
    else {
      return nil
    }
    return UInt16(number.int64Value)
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
  /// A start still running at `deadline` is interrupted, and one with too little
  /// time left is not begun. Either fails with
  /// `LibboxRuntimeError.serviceStartTimedOut` unless the start already failed
  /// for its own reason, which it keeps. A failed start whose service cannot be
  /// closed fails with `LibboxInstanceUnclosable` instead, and the runtime is
  /// spent.
  func start(configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline)
    throws
  func startReceipt(
    configuration: Data,
    packetFileDescriptor: Int32?,
    role: LibboxRuntimeRole,
    deadline: EngineStartDeadline
  ) throws -> LibboxRuntimeStartReceipt
  /// Closes the running service. Closing can fail only when libbox cannot close
  /// the instance, which leaves the runtime spent: every later stop throws the
  /// same failure without touching libbox again, because libbox closes an
  /// instance once. Callers never call it while a start is running.
  func stop() throws(LibboxInstanceUnclosable)
  func healthCheck() throws
  func resetNetwork()
}

extension LibboxServiceRuntime {
  public func startReceipt(
    configuration: Data,
    packetFileDescriptor: Int32?,
    role: LibboxRuntimeRole,
    deadline: EngineStartDeadline
  ) throws -> LibboxRuntimeStartReceipt {
    try start(
      configuration: configuration, packetFileDescriptor: packetFileDescriptor, deadline: deadline)
    return try LibboxRuntimeStartReceipt.parse(
      configuration: configuration,
      role: role
    )
  }
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
