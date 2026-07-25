import Foundation

public actor BoundedAuthorityXPCClient: AuthorityClient, EngineOwnerAuthorityClient {
  private let remote: any AuthorityRemoteCalling
  private let ownerOperation: OperationContext?
  private let ownerLeaseID: AuthorityIdentifier?
  private var negotiated = false

  public init(
    remote: any AuthorityRemoteCalling,
    ownerOperation: OperationContext? = nil,
    ownerLeaseID: AuthorityIdentifier? = nil
  ) {
    self.remote = remote
    self.ownerOperation = ownerOperation
    self.ownerLeaseID = ownerLeaseID
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
    return try AuthorityPreparedStartCodec.decode(
      reply.response, requestID: requestID,
      operationID: request.operation.operationID)
  }

  public func cancelPrepared(
    _ context: OperationContext, revision: UInt64
  ) async throws {
    let request = try CancelPreparedRequest(
      operation: context, expectedRevision: revision)
    _ = try await acknowledgement(.cancelPrepared(request), operation: context.operationID)
  }
  public func beginStop(_ request: BeginStopRequest) async throws -> StopDirective {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .beginStop(request))
    let reply = try await perform(
      method: .beginStop, request: AuthorityV1Codec.encode(envelope))
    return try correlated(
      StopDirective.self, data: reply.response,
      requestID: requestID, operationID: request.operation.operationID)
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

  public func bind(_ capability: OwnerCapability) async throws -> LeaseView {
    defer { capability.erase() }
    let context = try ownerContext()
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let request = BindProxyOwnerRequest(
      operation: context.operation, leaseID: context.leaseID,
      capability: capability)
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .bindProxyOwner(request))
    let reply = try await perform(
      method: .bindProxyOwner, request: AuthorityV1Codec.encode(envelope))
    return try correlated(
      LeaseView.self, data: reply.response, requestID: requestID,
      operationID: context.operation.operationID)
  }

  public func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    defer { ticket.erase() }
    let context = try ownerContext()
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let request = RedeemTunnelTicketRequest(
      operation: context.operation, leaseID: context.leaseID, ticket: ticket)
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .redeemTunnelTicket(request))
    var reply = try await perform(
      method: .redeemTunnelTicket, request: AuthorityV1Codec.encode(envelope))
    guard let configurationData = reply.configuration else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    let metadata = try correlated(
      RedeemedTunnelMetadata.self, data: reply.response,
      requestID: requestID, operationID: context.operation.operationID)
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
    _ = try await acknowledgement(
      .attestReady(attestation), operation: attestation.operation.operationID)
  }

  public func attestStopped(_ attestation: StoppedAttestation) async throws {
    _ = try await acknowledgement(
      .attestStopped(attestation), operation: attestation.operation.operationID)
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
    return try correlated(
      AuthorityAcknowledgement.self, data: reply.response,
      requestID: requestID, operationID: operation)
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

  private func ownerContext() throws
    -> (operation: OperationContext, leaseID: AuthorityIdentifier)
  {
    guard let ownerOperation, let ownerLeaseID else {
      throw AuthorityDomainError(code: .staleOperation)
    }
    return (ownerOperation, ownerLeaseID)
  }

  private func method(for command: AuthorityCommand) -> AuthorityXPCMethod {
    switch command {
    case .handshake: .handshake
    case .prepareStart: .prepareStart
    case .bindProxyOwner: .bindProxyOwner
    case .redeemTunnelTicket: .redeemTunnelTicket
    case .attestReady: .attestReady
    case .beginStop: .beginStop
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

public final class AuthorityEventReceiver: NSObject,
  CFWGlobalAuthorityEventSinkProtocol, @unchecked Sendable
{
  public let queue = BoundedAuthorityEventQueue()
  private let disconnect: @Sendable () -> Void

  public init(disconnect: @escaping @Sendable () -> Void) {
    self.disconnect = disconnect
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
  private let machServiceName: String
  private let timeout: Duration
  private var connection: NSXPCConnection?

  public init(
    machServiceName: String =
      "YKUPL7Z869.group.com.bill.clashformac.global-authority",
    timeout: Duration = .seconds(5)
  ) {
    self.machServiceName = machServiceName
    self.timeout = timeout
  }
  public func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let connection = connected()
    return try await withCheckedThrowingContinuation { continuation in
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
        } catch {}
      }
    }
  }

  public func invalidate() async {
    let value = lock.withLock {
      let value = connection
      connection = nil
      return value
    }
    value?.invalidate()
  }

  private func connected() -> NSXPCConnection {
    lock.withLock {
      if let connection { return connection }
      let value = NSXPCConnection(
        machServiceName: machServiceName, options: .privileged)
      value.remoteObjectInterface = NSXPCInterface(
        with: CFWGlobalAuthorityXPCProtocol.self)
      let box = WeakXPCConnectionBox(value)
      let receiver = AuthorityEventReceiver { box.connection?.invalidate() }
      value.exportedInterface = NSXPCInterface(
        with: CFWGlobalAuthorityEventSinkProtocol.self)
      value.exportedObject = receiver
      value.interruptionHandler = { [weak self] in
        self?.clear(box.connection)
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
    lock.withLock {
      guard connection === expected else { return }
      connection = nil
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
    case .attestStopped:
      proxy.attestStopped(request, reply: simpleReply)
    case .cancelPrepared:
      proxy.cancelPrepared(request, reply: simpleReply)
    case .snapshot:
      proxy.snapshot(request, reply: simpleReply)
    }
  }
}
