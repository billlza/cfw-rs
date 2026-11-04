import CFWSharedProtocol
import Foundation
import OSLog

/// A connection whose sends XPC can order a block after: the block runs once
/// every message handed to the connection before it has been sent.
protocol ProxyAgentSendBarrier: AnyObject {
  func scheduleSendBarrierBlock(_ block: @escaping @Sendable () -> Void)
}

extension NSXPCConnection: ProxyAgentSendBarrier {}

/// The ProxyAgent's accepted connections, from acceptance until invalidation.
final class ProxyAgentConnections: @unchecked Sendable {
  private let lock = NSLock()
  private var connections: [ObjectIdentifier: NSXPCConnection] = [:]

  /// Tracks `connection` until it is invalidated. Call it before resuming the
  /// connection.
  func track(_ connection: NSXPCConnection) {
    let key = ObjectIdentifier(connection)
    lock.withLock { connections[key] = connection }
    connection.invalidationHandler = { [weak self] in
      self?.forget(key)
    }
  }

  var open: [any ProxyAgentSendBarrier] {
    lock.withLock { Array(connections.values) }
  }

  private func forget(_ key: ObjectIdentifier) {
    lock.withLock { _ = connections.removeValue(forKey: key) }
  }
}

final class ProxyAgentListenerDelegate: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "proxy-agent-xpc"
  )
  private let identityPolicy: CodeIdentityPolicy
  private let service: ProxyAgentService
  private let connections: ProxyAgentConnections

  init(
    identityPolicy: CodeIdentityPolicy, service: ProxyAgentService,
    connections: ProxyAgentConnections
  ) {
    self.identityPolicy = identityPolicy
    self.service = service
    self.connections = connections
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    do {
      try identityPolicy.configure(connection, requiredUserIdentifier: geteuid())
    } catch {
      Self.logger.error(
        "Rejected XPC connection: \(String(describing: error), privacy: .public)"
      )
      connection.invalidate()
      return false
    }

    connection.exportedInterface = NSXPCInterface(with: CFWProxyAgentXPCProtocol.self)
    connection.exportedObject = service
    connections.track(connection)
    connection.resume()
    return true
  }
}
