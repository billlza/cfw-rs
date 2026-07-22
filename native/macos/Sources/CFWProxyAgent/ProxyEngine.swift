import CFWLibboxRuntime
import CFWSharedProtocol
import Darwin
import Foundation

enum ProxyEngineError: Error, Equatable, Sendable {
  case runtime(String)
  case invalidConfiguration
  case missingMixedListener
  case duplicateMixedListener
  case invalidListenerHost(String)
  case invalidListenerPort(UInt16)
}

struct MixedListenerEndpoint: Equatable, Sendable {
  let host: String
  let port: UInt16

  init(host: String, port: UInt16) throws {
    guard host == "127.0.0.1" else {
      throw ProxyEngineError.invalidListenerHost(host)
    }
    guard port > 0 else {
      throw ProxyEngineError.invalidListenerPort(port)
    }
    self.host = host
    self.port = port
  }
}

struct ProxyEngineFailure: Error, Equatable, Sendable {
  let code: String
  let message: String
}

enum ProxyEngineEvent: Equatable, Sendable {
  case mixedListenerReady(MixedListenerEndpoint)
  /// The engine has terminated and no longer owns runtime resources.
  case failed(ProxyEngineFailure)
}

protocol ProxyEngine: AnyObject {
  /// Starts the engine without publishing system proxy settings. A successful
  /// return only means startup was accepted; readiness is established solely
  /// by a later mixedListenerReady event. Implementations must clean up any
  /// partial runtime state before throwing.
  func start(
    configuration: Data,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws

  /// Stops the engine. If this throws, the caller must retain the cross-process
  /// engine lease and retry instead of assuming the listener has terminated.
  func stop() throws
  func healthCheck() throws
}

protocol ProxyEngineFactory: Sendable {
  func makeEngine(configuration: Data) throws -> any ProxyEngine
}

struct LibboxProxyEngineFactory: ProxyEngineFactory {
  private let runtimeFactory: any LibboxServiceRuntimeFactory

  init(
    runtimeFactory: any LibboxServiceRuntimeFactory = SourceBuiltLibboxRuntimeFactory()
  ) {
    self.runtimeFactory = runtimeFactory
  }

  func makeEngine(configuration: Data) throws -> any ProxyEngine {
    _ = try Self.mixedListener(in: configuration)
    do {
      return LibboxProxyEngine(
        runtime: try runtimeFactory.makeRuntime(role: .systemProxy)
      )
    } catch {
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
  }

  static func mixedListener(in configuration: Data) throws -> MixedListenerEndpoint {
    guard configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      let root = try? JSONSerialization.jsonObject(with: configuration) as? [String: Any],
      let inbounds = root["inbounds"] as? [[String: Any]]
    else {
      throw ProxyEngineError.invalidConfiguration
    }
    let matches = inbounds.filter { inbound in
      inbound["type"] as? String == "mixed"
        && inbound["tag"] as? String == "cfw-system-proxy"
    }
    guard !matches.isEmpty else {
      throw ProxyEngineError.missingMixedListener
    }
    guard matches.count == 1 else {
      throw ProxyEngineError.duplicateMixedListener
    }
    let listener = matches[0]
    guard let host = listener["listen"] as? String,
      let portNumber = listener["listen_port"] as? NSNumber,
      CFGetTypeID(portNumber) != CFBooleanGetTypeID(),
      portNumber.int64Value > 0,
      portNumber.int64Value <= Int64(UInt16.max),
      Double(portNumber.int64Value) == portNumber.doubleValue
    else {
      throw ProxyEngineError.invalidConfiguration
    }
    return try MixedListenerEndpoint(
      host: host,
      port: UInt16(portNumber.int64Value)
    )
  }
}

private final class LibboxProxyEngine: ProxyEngine, @unchecked Sendable {
  private enum State {
    case idle
    case owned(UUID, @Sendable (ProxyEngineEvent) -> Void)
    case failedOwned
  }

  private let runtime: any LibboxServiceRuntime
  private let lock = NSLock()
  private var state = State.idle

  init(runtime: any LibboxServiceRuntime) {
    self.runtime = runtime
  }

  func start(
    configuration: Data,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    let endpoint = try LibboxProxyEngineFactory.mixedListener(in: configuration)
    let sessionID = UUID()
    try lock.withLock {
      guard case .idle = state else {
        throw ProxyEngineError.runtime("Proxy engine already owns a runtime.")
      }
      state = .owned(sessionID, eventHandler)
    }
    do {
      try runtime.start(configuration: configuration, packetFileDescriptor: nil)
    } catch {
      // ProxySessionLifecycle always invokes stop() after a start error. Keep
      // ownership until that explicit barrier succeeds, even if the runtime
      // already performed an idempotent local cleanup.
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
    DispatchQueue.global(qos: .userInitiated).async { [weak self] in
      self?.probeListener(endpoint, sessionID: sessionID)
    }
  }

  func stop() throws {
    let previousState = lock.withLock { () -> State in
      let previous = state
      state = .failedOwned
      return previous
    }
    guard !Self.isIdle(previousState) else {
      lock.withLock { state = .idle }
      return
    }
    do {
      try runtime.stop()
      lock.withLock { state = .idle }
    } catch {
      lock.withLock { state = .failedOwned }
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
  }

  func healthCheck() throws {
    let ownsRuntime = lock.withLock { () -> Bool in
      switch state {
      case .owned, .failedOwned:
        true
      case .idle:
        false
      }
    }
    guard ownsRuntime else {
      throw ProxyEngineError.runtime("Proxy engine does not own a runtime.")
    }
    do {
      try runtime.healthCheck()
    } catch {
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
  }

  private func probeListener(_ endpoint: MixedListenerEndpoint, sessionID: UUID) {
    let deadline = ContinuousClock.now.advanced(by: .seconds(5))
    while ContinuousClock.now < deadline {
      guard isCurrent(sessionID) else {
        return
      }
      if Self.canConnect(to: endpoint) {
        emitReady(endpoint, sessionID: sessionID)
        return
      }
      Thread.sleep(forTimeInterval: 0.05)
    }
    // ProxySessionLifecycle owns the 10-second readiness timeout and will call
    // stop(), preserving the lease if cleanup fails. A probe timeout must not
    // emit `.failed`, whose protocol contract means resources already ended.
  }

  private func isCurrent(_ sessionID: UUID) -> Bool {
    lock.withLock {
      guard case .owned(let activeID, _) = state else {
        return false
      }
      return activeID == sessionID
    }
  }

  private func emitReady(_ endpoint: MixedListenerEndpoint, sessionID: UUID) {
    let handler: (@Sendable (ProxyEngineEvent) -> Void)? = lock.withLock {
      guard case .owned(let activeID, let handler) = state,
        activeID == sessionID
      else {
        return nil
      }
      return handler
    }
    handler?(.mixedListenerReady(endpoint))
  }

  private static func canConnect(to endpoint: MixedListenerEndpoint) -> Bool {
    let socketFD = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    guard socketFD >= 0 else {
      return false
    }
    defer { Darwin.close(socketFD) }
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = endpoint.port.bigEndian
    let converted = endpoint.host.withCString { host in
      inet_pton(AF_INET, host, &address.sin_addr)
    }
    guard converted == 1 else {
      return false
    }
    return withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
        Darwin.connect(
          socketFD,
          socketAddress,
          socklen_t(MemoryLayout<sockaddr_in>.size)
        ) == 0
      }
    }
  }

  private static func isIdle(_ state: State) -> Bool {
    if case .idle = state {
      return true
    }
    return false
  }
}
