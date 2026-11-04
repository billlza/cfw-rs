import Foundation

public actor BoundedAuthorityXPCClient: AuthorityClient, ProxyOwnerAuthorityClient {
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

  public func ownerLeaseStatus(_ leaseID: AuthorityIdentifier) async throws -> OwnerLeaseStatus {
    try await ensureHandshake()
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID,
      command: .ownerLeaseStatus(OwnerLeaseStatusRequest(leaseID: leaseID)))
    let reply = try await perform(
      method: .ownerLeaseStatus, request: AuthorityV1Codec.encode(envelope))
    return try correlated(
      OwnerLeaseStatusResponse.self, data: reply.response,
      requestID: requestID, operationID: nil
    ).status
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
        guard attempt == 0, method.retriesAfterRetryableFailure,
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
    case .ownerLeaseStatus: .ownerLeaseStatus
    }
  }
}
