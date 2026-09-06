import Foundation

public actor BoundedAuthorityXPCClient: AuthorityClient, EngineOwnerAuthorityClient {
  private let remote: any AuthorityRemoteCalling
  private var negotiated = false

  public init(remote: any AuthorityRemoteCalling) {
    self.remote = remote
  }

  deinit {
    let remote = remote
    Task { await remote.invalidate() }
  }

  public func prepare(
    _ request: PrepareStartRequest,
    configuration: SensitiveBytes, secrets: SensitiveBytes?
  ) async throws -> PreparedStart {
    defer {
      configuration.erase()
      secrets?.erase()
    }
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .prepareStart(request))
    var configurationData = try configuration.withUnsafeBytes { Data($0) }
    var secretData = try secrets?.withUnsafeBytes { Data($0) }
    defer {
      configurationData.resetBytes(
        in: configurationData.startIndex..<configurationData.endIndex)
      if secretData != nil {
        let range = secretData!.startIndex..<secretData!.endIndex
        secretData!.resetBytes(in: range)
      }
    }
    let reply = try await perform(
      method: .prepareStart, request: AuthorityV1Codec.encode(envelope),
      configuration: configurationData, secretPayload: secretData)
    let prepared = try AuthorityPreparedStartCodec.decode(
      reply.response, requestID: requestID,
      operationID: request.operation.operationID)
    guard prepared.operation == request.operation,
      prepared.preferenceDescriptorSHA256 == request.operation.identitySHA256
    else {
      prepared.erase()
      throw AuthorityDomainError(code: .staleOperation)
    }
    return prepared
  }

  public func cancelPrepared(
    _ context: OperationContext, revision: UInt64
  ) async throws {
    let request = try CancelPreparedRequest(
      operation: context, expectedRevision: revision)
    let acknowledgement = try await acknowledgement(
      .cancelPrepared(request), operation: context.operationID)
    try requireRevision(
      acknowledgement.revision,
      after: revision,
      increments: 2)
  }
  public func beginStop(_ request: BeginStopRequest) async throws -> StopDirective {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .beginStop(request))
    let reply = try await perform(
      method: .beginStop, request: AuthorityV1Codec.encode(envelope))
    let directive = try correlated(
      StopDirective.self, data: reply.response,
      requestID: requestID, operationID: request.operation.operationID)
    let (incrementedRevision, overflow) = request.expectedRevision.addingReportingOverflow(1)
    guard directive.operation == request.operation,
      directive.leaseID == request.leaseID,
      directive.revision == request.expectedRevision
        || (!overflow && directive.revision == incrementedRevision)
    else { throw AuthorityDomainError(code: .staleOperation) }
    return directive
  }

  public func completeStop(_ request: CompleteStopRequest) async throws {
    let acknowledgement = try await acknowledgement(
      .completeStop(request), operation: request.operation.operationID)
    try requireRevision(
      acknowledgement.revision,
      after: request.expectedRevision,
      increments: 1)
  }

  public func reconcileOff(
    _ request: ReconcileOffRequest
  ) async throws -> ReconcileOffReceipt {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .reconcileOff(request))
    let reply = try await perform(
      method: .reconcileOff, request: AuthorityV1Codec.encode(envelope))
    let receipt = try correlated(
      ReconcileOffReceipt.self, data: reply.response,
      requestID: requestID, operationID: nil)
    guard receipt.replayCursor == request.replayCursor else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    return receipt
  }

  public func snapshot() async throws -> AuthoritySnapshot {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .snapshot(SnapshotRequest()))
    let reply = try await perform(
      method: .snapshot, request: AuthorityV1Codec.encode(envelope))
    return try correlated(
      AuthoritySnapshot.self, data: reply.response,
      requestID: requestID, operationID: nil)
  }

  public func bind(
    _ capability: OwnerCapability, context: ProxyOwnerContext
  ) async throws -> LeaseView {
    defer { capability.erase() }
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let request = BindProxyOwnerRequest(
      operation: context.operation, leaseID: context.leaseID,
      capability: capability)
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .bindProxyOwner(request))
    let reply = try await perform(
      method: .bindProxyOwner, request: AuthorityV1Codec.encode(envelope))
    let lease = try correlated(
      LeaseView.self, data: reply.response, requestID: requestID,
      operationID: context.operation.operationID)
    guard lease.operation == context.operation,
      lease.leaseID == context.leaseID,
      lease.state == .starting
    else { throw AuthorityDomainError(code: .staleOperation) }
    try await remote.confirmOwnerClaim()
    return lease
  }

  public func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    defer { ticket.erase() }
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let request = RedeemTunnelTicketRequest(ticket: ticket)
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .redeemTunnelTicket(request))
    var reply = try await perform(
      method: .redeemTunnelTicket, request: AuthorityV1Codec.encode(envelope))
    guard let configurationData = reply.configuration else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    let metadataEnvelope = try AuthorityV1Codec.decodeResponse(
      RedeemedTunnelMetadata.self, from: reply.response)
    let metadata = metadataEnvelope.result
    guard metadataEnvelope.requestID == requestID,
      metadataEnvelope.operationID == metadata.operation.operationID
    else { throw AuthorityDomainError(code: .staleOperation) }
    try await remote.confirmOwnerClaim()
    let secrets = try AuthoritySecretPayloadCodec.decode(
      reply.secretPayload, descriptor: metadata.configuration)
    let configuration = try SensitiveBytes(
      copying: configurationData,
      maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
    reply = AuthorityXPCReply(response: Data())
    return try RedeemedTunnelStart(
      operation: metadata.operation, lease: metadata.lease,
      configuration: configuration, secrets: secrets)
  }
  public func attestReady(_ attestation: ReadyAttestation) async throws {
    let acknowledgement = try await acknowledgement(
      .attestReady(attestation), operation: attestation.operation.operationID)
    try requireRevision(
      acknowledgement.revision,
      after: attestation.operation.authorityRevision,
      increments: 3)
  }

  public func attestStopped(_ attestation: StoppedAttestation) async throws {
    await remote.noteOwnerStopped()
    let acknowledgement = try await acknowledgement(
      .attestStopped(attestation), operation: attestation.operation.operationID)
    try requireRevision(
      acknowledgement.revision,
      after: attestation.operation.authorityRevision,
      allowedIncrements: 3...5)
  }

  private func acknowledgement(
    _ command: AuthorityCommand, operation: AuthorityIdentifier
  ) async throws -> AuthorityAcknowledgement {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: command)
    let reply = try await perform(
      method: method(for: command), request: AuthorityV1Codec.encode(envelope))
    let acknowledgement = try correlated(
      AuthorityAcknowledgement.self, data: reply.response,
      requestID: requestID, operationID: operation)
    guard acknowledgement.operationID == operation else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    return acknowledgement
  }

  private func requireRevision(
    _ actual: UInt64,
    after base: UInt64,
    increments: UInt64
  ) throws {
    let (expected, overflow) = base.addingReportingOverflow(increments)
    guard !overflow, actual == expected else {
      throw AuthorityDomainError(code: .staleOperation)
    }
  }

  private func requireRevision(
    _ actual: UInt64,
    after base: UInt64,
    allowedIncrements: ClosedRange<UInt64>
  ) throws {
    let (minimum, minimumOverflow) =
      base.addingReportingOverflow(allowedIncrements.lowerBound)
    let (maximum, maximumOverflow) =
      base.addingReportingOverflow(allowedIncrements.upperBound)
    guard !minimumOverflow, !maximumOverflow,
      (minimum...maximum).contains(actual)
    else { throw AuthorityDomainError(code: .staleOperation) }
  }

  private func ensureHandshake() async throws {
    guard !negotiated else { return }
    let requestID = AuthorityIdentifier(UUID())
    let request = HandshakeRequest(version: try AuthorityProtocolVersion())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .handshake(request))
    let reply = try await perform(
      method: .handshake, request: AuthorityV1Codec.encode(envelope))
    let response = try correlated(
      HandshakeResponse.self, data: reply.response,
      requestID: requestID, operationID: nil)
    guard response == (try HandshakeResponse.v1()) else {
      throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
    }
    negotiated = true
  }

  private func perform(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data? = nil, secretPayload: Data? = nil
  ) async throws -> AuthorityXPCReply {
    var attempt = 0
    while true {
      do {
        return try await remote.call(
          method: method, request: request,
          configuration: configuration, secretPayload: secretPayload)
      } catch {
        let domain = AuthorityXPCErrorContract.domainError(error)
        guard attempt == 0,
          domain.code.allowsAutomaticRetry(for: method.operationClass)
        else { throw domain }
        attempt += 1
        negotiated = false
      }
    }
  }
  private func correlated<Payload: AuthorityV1WireModel>(
    _ payload: Payload.Type, data: Data,
    requestID: AuthorityIdentifier, operationID: AuthorityIdentifier?
  ) throws -> Payload {
    let envelope = try AuthorityV1Codec.decodeResponse(payload, from: data)
    guard envelope.requestID == requestID,
      envelope.operationID == operationID
    else { throw AuthorityDomainError(code: .staleOperation) }
    return envelope.result
  }

  private func method(for command: AuthorityCommand) -> AuthorityXPCMethod {
    switch command {
    case .handshake: .handshake
    case .prepareStart: .prepareStart
    case .bindProxyOwner: .bindProxyOwner
    case .redeemTunnelTicket: .redeemTunnelTicket
    case .attestReady: .attestReady
    case .beginStop: .beginStop
    case .completeStop: .completeStop
    case .reconcileOff: .reconcileOff
    case .attestStopped: .attestStopped
    case .cancelPrepared: .cancelPrepared
    case .snapshot: .snapshot
    }
  }
}
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
    let connection = connected()
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

  private func connected() -> NSXPCConnection {
    lock.withLock {
      if let connection { return connection }
      let value = NSXPCConnection(
        machServiceName: machServiceName, options: .privileged)
      value.setCodeSigningRequirement(
        GlobalAuthorityConnectionContract.authorityDesignatedRequirement)
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
      return value
    }
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
    }
  }
}
