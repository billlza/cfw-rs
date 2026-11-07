import CFWSharedProtocol
import Darwin
import Foundation

/// Controllable connection-generation seam. Every request registered on one XPC
/// connection receives a terminal transport failure when that exact generation is
/// retired. Late replies race through their per-request first-result gate and can
/// never complete a request on the replacement connection.
final class ProxyAgentConnectionLifecycle: @unchecked Sendable {
  let identifier = UUID()

  private let lock = NSLock()
  private let invalidate: @Sendable () -> Void
  private var retired = false
  private var pending: [UUID: @Sendable () -> Void] = [:]

  init(invalidate: @escaping @Sendable () -> Void) {
    self.invalidate = invalidate
  }

  func register(
    token: UUID,
    onRetire: @escaping @Sendable () -> Void
  ) -> Bool {
    let accepted = lock.withLock {
      guard !retired else { return false }
      pending[token] = onRetire
      return true
    }
    if !accepted { onRetire() }
    return accepted
  }

  func release(token: UUID) {
    _ = lock.withLock { pending.removeValue(forKey: token) }
  }

  func retire() {
    let outcome = lock.withLock { () -> (Bool, [@Sendable () -> Void]) in
      guard !retired else { return (false, []) }
      retired = true
      let callbacks = Array(pending.values)
      pending.removeAll(keepingCapacity: false)
      return (true, callbacks)
    }
    guard outcome.0 else { return }
    invalidate()
    for callback in outcome.1 { callback() }
  }

  var pendingCount: Int { lock.withLock { pending.count } }
  var isRetired: Bool { lock.withLock { retired } }
}

struct BoundedProxyAgentRequestRegistry: Sendable {
  static let productionMaximum = 16

  let maximum: Int
  private(set) var tokens: Set<UUID> = []

  init(maximum: Int = productionMaximum) {
    precondition(maximum > 0, "ProxyAgent request capacity must be positive")
    self.maximum = maximum
  }

  mutating func reserve() throws -> UUID {
    guard tokens.count < maximum else {
      throw ProxyAgentHostError.transportCapacityExceeded
    }
    let token = UUID()
    tokens.insert(token)
    return token
  }

  mutating func release(_ token: UUID) {
    tokens.remove(token)
  }
}

/// The byte arguments of one authorized ProxyAgent start, in XPC argument order.
struct ProxyAgentStartRequest: Sendable {
  let capability: Data
  let context: Data
  let configuration: Data
  let request: Data
}

struct ProxyAgentConnectionDependencies: @unchecked Sendable {
  typealias ConnectionFactory = @Sendable (String) -> NSXPCConnection
  typealias Execute =
    @Sendable (
      NSXPCConnection,
      Data,
      @escaping @Sendable (Result<Data, Error>) -> Void
    ) -> Void
  typealias StartSystemProxy =
    @Sendable (
      NSXPCConnection,
      ProxyAgentStartRequest,
      @escaping @Sendable (Result<Data, Error>) -> Void
    ) -> Void

  let makeConnection: ConnectionFactory
  let prepareConnection: @Sendable (NSXPCConnection, String) -> Void
  let activateConnection: @Sendable (NSXPCConnection) -> Void
  let execute: Execute
  let startSystemProxy: StartSystemProxy

  static let production = ProxyAgentConnectionDependencies(
    makeConnection: { NSXPCConnection(machServiceName: $0) },
    prepareConnection: { connection, requirement in
      connection.setCodeSigningRequirement(requirement)
      connection.remoteObjectInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    },
    activateConnection: { $0.activate() },
    execute: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(.failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
        return
      }
      proxy.execute(request) { data, error in
        if error != nil {
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          reply(.success(data))
        } else {
          reply(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
    },
    startSystemProxy: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(.failure(ProxyAgentHostError.transportUnavailable("remote interface is unavailable")))
        return
      }
      proxy.startSystemProxy(
        request.capability,
        context: request.context,
        configuration: request.configuration,
        request: request.request
      ) { data, error in
        if error != nil {
          reply(.failure(ProxyAgentHostError.transportUnavailable("remote-error")))
        } else if let data {
          reply(.success(data))
        } else {
          reply(.failure(ProxyAgentHostError.malformedResponse))
        }
      }
    }
  )
}

struct Installed40019ProxyTransportDependencies: @unchecked Sendable {
  let observeProcess: @Sendable () throws -> Installed40019ServiceProcessIdentity
  let makeConnection: ProxyAgentConnectionDependencies.ConnectionFactory
  let prepareConnection: @Sendable (NSXPCConnection, String) -> Void
  let activateConnection: @Sendable (NSXPCConnection) -> Void
  let execute:
    @Sendable (NSXPCConnection, Data, @escaping @Sendable (Data?, NSError?) -> Void) -> Void
  let peerProcessIdentifier: @Sendable (NSXPCConnection) -> pid_t
  let peerUserIdentifier: @Sendable (NSXPCConnection) -> uid_t

  static let production = Installed40019ProxyTransportDependencies(
    observeProcess: { try Installed40019ServiceProcessObserver().observe(.proxyAgent) },
    makeConnection: ProxyAgentConnectionDependencies.production.makeConnection,
    prepareConnection: ProxyAgentConnectionDependencies.production.prepareConnection,
    activateConnection: ProxyAgentConnectionDependencies.production.activateConnection,
    execute: { connection, request, reply in
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
          reply(nil, NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionInterrupted))
        }) as? CFWProxyAgentXPCProtocol
      else {
        reply(nil, NSError(domain: NSCocoaErrorDomain, code: NSXPCConnectionInvalid))
        return
      }
      proxy.execute(request, withReply: reply)
    },
    peerProcessIdentifier: { $0.processIdentifier },
    peerUserIdentifier: { $0.effectiveUserIdentifier }
  )
}
