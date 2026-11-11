import Foundation

private final class AuthorityReplyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<AuthorityXPCReply, Error>?

  init(_ continuation: CheckedContinuation<AuthorityXPCReply, Error>) {
    self.continuation = continuation
  }

  func finish(_ result: Result<AuthorityXPCReply, Error>) {
    let value = lock.withLock {
      let value = continuation
      continuation = nil
      return value
    }
    value?.resume(with: result)
  }
}

private final class AuthorityVoidReplyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Void, Error>?

  init(_ continuation: CheckedContinuation<Void, Error>) {
    self.continuation = continuation
  }

  func finish(_ result: Result<Void, Error>) {
    let value = lock.withLock {
      let value = continuation
      continuation = nil
      return value
    }
    value?.resume(with: result)
  }
}

public final class AuthorityEventReceiver: NSObject,
  CFWGlobalAuthorityEventSinkProtocol, @unchecked Sendable
{
  public let queue = BoundedAuthorityEventQueue()
  private let disconnect: @Sendable () -> Void
  private let onEvent: @Sendable (AuthorityEvent) -> Void

  public init(
    disconnect: @escaping @Sendable () -> Void,
    onEvent: @escaping @Sendable (AuthorityEvent) -> Void = { _ in }
  ) {
    self.disconnect = disconnect
    self.onEvent = onEvent
  }

  public func deliverEvent(
    _ event: Data, reply: @escaping (NSError?) -> Void
  ) {
    do {
      let decoded = try AuthorityV1Codec.decodeEvent(event)
      if queue.enqueue(decoded) == .peerMustDisconnect {
        disconnect()
        reply(AuthorityXPCErrorContract.error(.resourceExhausted))
      } else {
        onEvent(decoded)
        _ = queue.dequeue()
        reply(nil)
      }
    } catch {
      disconnect()
      reply(AuthorityXPCErrorContract.error(.invalidMessage))
    }
  }
}

private final class WeakXPCConnectionBox: @unchecked Sendable {
  weak var connection: NSXPCConnection?
  init(_ connection: NSXPCConnection) { self.connection = connection }
}

public final class NSXPCGlobalAuthorityRemote: AuthorityRemoteCalling,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let role: AuthorityRole
  private let machServiceName: String
  private let timeout: Duration
  private let onEvent: @Sendable (AuthorityEvent) -> Void
  private let onDisconnect: @Sendable () -> Void
  private var connection: NSXPCConnection?
  private var heartbeatTask: Task<Void, Never>?
  private enum BuildPolicy {
    case protocolPeer
    case currentHost(ServiceCodeHash)
  }
  private var buildPolicy: BuildPolicy = .protocolPeer
  private var connectionRequiresCurrentBuild = false
  private var buildConstraint = ServiceConnectionBuildConstraint()

  /// The production Host supplies the verified embedded Authority requirement.
  /// Owner and physical protocol-fixture clients retain their existing role
  /// identity contract; this initializer makes no build claim for those peers.
  public convenience init(currentHostCodeHash: ServiceCodeHash) {
    self.init(role: .host)
    buildPolicy = .currentHost(currentHostCodeHash)
  }

  public init(
    role: AuthorityRole,
    machServiceName: String? = nil,
    timeout: Duration = .seconds(5),
    onEvent: @escaping @Sendable (AuthorityEvent) -> Void = { _ in },
    onDisconnect: @escaping @Sendable () -> Void = {}
  ) {
    self.role = role
    self.machServiceName =
      machServiceName
      ?? GlobalAuthorityConnectionContract.machServiceName(for: role)
    self.timeout = timeout
    self.onEvent = onEvent
    self.onDisconnect = onDisconnect
  }
  public func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let requiresCurrentBuild: Bool
    switch buildPolicy {
    case .currentHost:
      requiresCurrentBuild = method == .prepareStart || method == .installationRecoveryIdentity
    case .protocolPeer: requiresCurrentBuild = false
    }
    let connection = connected(requiresCurrentBuild: requiresCurrentBuild)
    let result: AuthorityXPCReply = try await withCheckedThrowingContinuation { continuation in
      let gate = AuthorityReplyGate(continuation)
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
          gate.finish(.failure(AuthorityXPCErrorContract.domainError(error)))
        }) as? CFWGlobalAuthorityXPCProtocol
      else {
        gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
        return
      }
      dispatch(
        method: method, proxy: proxy, request: request,
        configuration: configuration, secretPayload: secretPayload, gate: gate)
      let timeout = method.replyTimeout(within: self.timeout)
      Task {
        do {
          try await Task.sleep(for: timeout)
          gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityTimeout)))
        } catch is CancellationError {
          return
        } catch {
          gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
        }
      }
    }
    return result
  }

  public func confirmOwnerClaim() async throws {
    guard role != .host else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    guard let connection = lock.withLock({ self.connection }),
      startHeartbeat(on: connection)
    else { throw AuthorityDomainError(code: .globalAuthorityInterrupted) }
  }

  public func noteOwnerStopped() async {
    stopHeartbeat()
  }

  public func invalidate() async {
    let (value, heartbeat) = lock.withLock {
      let value = connection
      connection = nil
      let heartbeat = heartbeatTask
      heartbeatTask = nil
      return (value, heartbeat)
    }
    heartbeat?.cancel()
    value?.invalidate()
  }

  private func connected(requiresCurrentBuild: Bool) -> NSXPCConnection {
    var retired: NSXPCConnection?
    let selected = lock.withLock {
      let requirement: String
      switch buildPolicy {
      case .currentHost(let hash):
        requirement = buildConstraint.requirement(
          base: GlobalAuthorityConnectionContract.authorityDesignatedRequirement,
          currentCodeHash: hash, requestingCurrentBuild: requiresCurrentBuild)
      case .protocolPeer:
        requirement = GlobalAuthorityConnectionContract.authorityDesignatedRequirement
      }
      let requiresCurrentBuild = buildConstraint.requiresCurrentBuild
      if let connection, !requiresCurrentBuild || connectionRequiresCurrentBuild {
        return connection
      }
      retired = connection
      let value = NSXPCConnection(
        machServiceName: machServiceName, options: .privileged)
      value.setCodeSigningRequirement(requirement)
      value.remoteObjectInterface = NSXPCInterface(
        with: CFWGlobalAuthorityXPCProtocol.self)
      let box = WeakXPCConnectionBox(value)
      let receiver = AuthorityEventReceiver(
        disconnect: { [weak self, box] in
          let connection = box.connection
          self?.clear(connection)
          connection?.invalidate()
        },
        onEvent: onEvent)
      value.exportedInterface = NSXPCInterface(
        with: CFWGlobalAuthorityEventSinkProtocol.self)
      value.exportedObject = receiver
      value.interruptionHandler = { [weak self, box] in
        let connection = box.connection
        self?.clear(connection)
        connection?.invalidate()
      }
      value.invalidationHandler = { [weak self] in
        self?.clear(box.connection)
      }
      value.activate()
      connection = value
      connectionRequiresCurrentBuild = requiresCurrentBuild
      return value
    }
    retired?.invalidate()
    return selected
  }

  private func clear(_ expected: NSXPCConnection?) {
    let result = lock.withLock { () -> (Bool, Task<Void, Never>?) in
      guard connection === expected else { return (false, nil) }
      connection = nil
      let heartbeat = heartbeatTask
      heartbeatTask = nil
      return (true, heartbeat)
    }
    guard result.0 else { return }
    result.1?.cancel()
    onDisconnect()
  }

  private func startHeartbeat(on connection: NSXPCConnection) -> Bool {
    guard role != .host else { return true }
    let box = WeakXPCConnectionBox(connection)
    return lock.withLock {
      guard self.connection === connection else { return false }
      guard heartbeatTask == nil else { return true }
      heartbeatTask = Task { [weak self, box] in
        guard let self else { return }
        while !Task.isCancelled {
          do {
            try await Task.sleep(for: .seconds(2))
          } catch is CancellationError {
            return
          } catch {
            box.connection?.invalidate()
            return
          }
          guard let connection = box.connection else { return }
          do {
            try await self.sendHeartbeat(on: connection)
          } catch {
            connection.invalidate()
            return
          }
        }
      }
      return true
    }
  }

  private func stopHeartbeat() {
    let heartbeat = lock.withLock {
      let heartbeat = heartbeatTask
      heartbeatTask = nil
      return heartbeat
    }
    heartbeat?.cancel()
  }

  private func sendHeartbeat(on connection: NSXPCConnection) async throws {
    try await withCheckedThrowingContinuation { continuation in
      let gate = AuthorityVoidReplyGate(continuation)
      guard
        let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
          gate.finish(.failure(AuthorityXPCErrorContract.domainError(error)))
        }) as? CFWGlobalAuthorityXPCProtocol
      else {
        gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
        return
      }
      proxy.ownerHeartbeat { error in
        if let error {
          gate.finish(.failure(AuthorityXPCErrorContract.domainError(error)))
        } else {
          gate.finish(.success(()))
        }
      }
      let timeout = self.timeout
      Task {
        do {
          try await Task.sleep(for: timeout)
          gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityTimeout)))
        } catch is CancellationError {
          return
        } catch {
          gate.finish(.failure(AuthorityDomainError(code: .globalAuthorityUnavailable)))
        }
      }
    }
  }
  private func dispatch(
    method: AuthorityXPCMethod, proxy: CFWGlobalAuthorityXPCProtocol,
    request: Data, configuration: Data?, secretPayload: Data?,
    gate: AuthorityReplyGate
  ) {
    let simpleReply: (Data?, NSError?) -> Void = { data, error in
      if let error {
        gate.finish(.failure(error))
      } else if let data {
        gate.finish(.success(AuthorityXPCReply(response: data)))
      } else {
        gate.finish(.failure(AuthorityDomainError(code: .invalidMessage)))
      }
    }
    switch method {
    case .handshake:
      proxy.handshake(request, reply: simpleReply)
    case .prepareStart:
      guard let configuration else {
        gate.finish(.failure(AuthorityDomainError(code: .invalidMessage)))
        return
      }
      proxy.prepareStart(
        request, configuration: configuration,
        secretPayload: secretPayload, reply: simpleReply)
    case .bindProxyOwner:
      proxy.bindProxyOwner(request, reply: simpleReply)
    case .redeemTunnelTicket:
      proxy.redeemTunnelTicket(request) { response, configuration, secrets, error in
        if let error {
          gate.finish(.failure(error))
        } else if let response, let configuration {
          gate.finish(
            .success(
              AuthorityXPCReply(
                response: response, configuration: configuration,
                secretPayload: secrets)))
        } else {
          gate.finish(.failure(AuthorityDomainError(code: .invalidMessage)))
        }
      }
    case .attestReady:
      proxy.attestReady(request, reply: simpleReply)
    case .beginStop:
      proxy.beginStop(request, reply: simpleReply)
    case .completeStop:
      proxy.completeStop(request, reply: simpleReply)
    case .reconcileOff:
      proxy.reconcileOff(request, reply: simpleReply)
    case .attestStopped:
      proxy.attestStopped(request, reply: simpleReply)
    case .cancelPrepared:
      proxy.cancelPrepared(request, reply: simpleReply)
    case .snapshot:
      proxy.snapshot(request, reply: simpleReply)
    case .installationRecoveryIdentity:
      proxy.installationRecoveryIdentity(request, reply: simpleReply)
    case .ownerLeaseStatus:
      proxy.ownerLeaseStatus(request, reply: simpleReply)
    }
  }
}
