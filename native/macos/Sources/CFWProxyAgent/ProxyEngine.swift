import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation

enum ProxyEngineError: Error, Equatable, Sendable {
  case runtime(String)
  case endpointConflict(role: LibboxRuntimeEndpointRole, port: UInt16)
  case runtimeReceiptMismatch
  case invalidConfiguration
  case missingMixedListener
}

typealias MixedListenerEndpoint = LibboxLoopbackTCPEndpoint

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
    do {
      let expectedReceipt = try LibboxRuntimeStartReceipt.parse(
        configuration: configuration,
        role: .systemProxy
      )
      return LibboxProxyEngine(
        runtime: try runtimeFactory.makeRuntime(role: .systemProxy),
        expectedReceipt: expectedReceipt
      )
    } catch {
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
  }

  static func mixedListener(in configuration: Data) throws -> MixedListenerEndpoint {
    do {
      guard
        let endpoint = try LibboxRuntimeStartReceipt.parse(
          configuration: configuration,
          role: .systemProxy
        ).mixedListener
      else {
        throw ProxyEngineError.missingMixedListener
      }
      return endpoint
    } catch let error as ProxyEngineError {
      throw error
    } catch {
      throw ProxyEngineError.invalidConfiguration
    }
  }
}

private final class LibboxProxyEngine: ProxyEngine, @unchecked Sendable {
  private enum State {
    case idle
    case owned(UUID, @Sendable (ProxyEngineEvent) -> Void)
    case failedOwned
  }

  private let runtime: any LibboxServiceRuntime
  private let expectedReceipt: LibboxRuntimeStartReceipt
  private let lock = NSLock()
  private var state = State.idle

  init(
    runtime: any LibboxServiceRuntime,
    expectedReceipt: LibboxRuntimeStartReceipt
  ) {
    self.runtime = runtime
    self.expectedReceipt = expectedReceipt
  }

  func start(
    configuration: Data,
    eventHandler: @escaping @Sendable (ProxyEngineEvent) -> Void
  ) throws {
    let configurationReceipt = try LibboxRuntimeStartReceipt.parse(
      configuration: configuration,
      role: .systemProxy
    )
    guard configurationReceipt == expectedReceipt,
      let endpoint = expectedReceipt.mixedListener
    else {
      throw ProxyEngineError.runtimeReceiptMismatch
    }
    let sessionID = UUID()
    try lock.withLock {
      guard case .idle = state else {
        throw ProxyEngineError.runtime("Proxy engine already owns a runtime.")
      }
      state = .owned(sessionID, eventHandler)
    }
    do {
      let runtimeReceipt = try runtime.startReceipt(
        configuration: configuration,
        packetFileDescriptor: nil,
        role: .systemProxy
      )
      guard runtimeReceipt == expectedReceipt else {
        throw ProxyEngineError.runtimeReceiptMismatch
      }
    } catch let error as LibboxRuntimeError {
      if case .endpointConflict(let role, let port) = error {
        throw ProxyEngineError.endpointConflict(role: role, port: port)
      }
      // ProxySessionLifecycle always invokes stop() after a start error. Keep
      // ownership until that explicit barrier succeeds, even if the runtime
      // already performed an idempotent local cleanup.
      throw ProxyEngineError.runtime(error.localizedDescription)
    } catch {
      throw ProxyEngineError.runtime(error.localizedDescription)
    }
    emitReady(endpoint, sessionID: sessionID)
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

  private static func isIdle(_ state: State) -> Bool {
    if case .idle = state {
      return true
    }
    return false
  }
}
