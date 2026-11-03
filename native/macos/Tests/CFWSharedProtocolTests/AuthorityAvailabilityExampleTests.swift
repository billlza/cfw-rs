import Foundation
import Testing

@testable import CFWSharedProtocol

// Task 2.6 examples: a missing or unavailable Authority fails closed, and only
// the exact operation and revision is acknowledged.
// MARK: - Missing/unavailable Authority produces a stable typed failure

/// Records every remote call and always reports the Authority as unavailable.
private final class UnavailableAuthorityRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private var invoked: [AuthorityXPCMethod] = []

  var invokedMethods: [AuthorityXPCMethod] { lock.withLock { invoked } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    lock.withLock { invoked.append(method) }
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func invalidate() async {}
}

private final class OperationAcknowledgementRemote:
  AuthorityRemoteCalling, @unchecked Sendable
{
  enum Reply: Equatable {
    case exact
    case wrongOperation
    case wrongRevision
  }

  private let lock = NSLock()
  private let reply: Reply
  private var methodCounts: [String: Int] = [:]
  private var ownerStoppedCountValue = 0

  init(reply: Reply) { self.reply = reply }

  func count(_ method: AuthorityXPCMethod) -> Int {
    lock.withLock { methodCounts["\(method)"] ?? 0 }
  }

  var ownerStoppedCount: Int { lock.withLock { ownerStoppedCountValue } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    if method == .handshake {
      return AuthorityXPCReply(
        response: try AuthorityV1Codec.encodeResponse(
          AuthorityResponseEnvelope(
            requestID: envelope.requestID,
            operationID: nil,
            result: try HandshakeResponse.v1())))
    }
    lock.withLock { methodCounts["\(method)", default: 0] += 1 }
    let operation: OperationContext
    let exactRevision: UInt64
    switch (method, envelope.command) {
    case (.cancelPrepared, .cancelPrepared(let cancellation)):
      operation = cancellation.operation
      exactRevision = cancellation.expectedRevision + 2
    case (.attestReady, .attestReady(let attestation)):
      operation = attestation.operation
      exactRevision = attestation.operation.authorityRevision + 3
    case (.attestStopped, .attestStopped(let attestation)):
      operation = attestation.operation
      exactRevision = attestation.operation.authorityRevision + 3
    default:
      throw AuthorityDomainError(code: .invalidMessage)
    }
    let acknowledgement = try AuthorityAcknowledgement(
      operationID:
        reply == .wrongOperation
        ? AuthorityIdentifier(UUID()) : operation.operationID,
      revision:
        reply == .wrongRevision
        ? exactRevision - 1 : exactRevision)
    return AuthorityXPCReply(
      response: try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID,
          operationID: operation.operationID,
          result: acknowledgement)))
  }

  func noteOwnerStopped() async {
    lock.withLock { ownerStoppedCountValue += 1 }
  }

  func invalidate() async {}
}

private final class ProxyBindReplyRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private let leaseState: AuthorityLeaseState
  private var confirmedClaimsValue = 0

  init(leaseState: AuthorityLeaseState) { self.leaseState = leaseState }

  var confirmedClaims: Int { lock.withLock { confirmedClaimsValue } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    if method == .handshake {
      return AuthorityXPCReply(
        response: try AuthorityV1Codec.encodeResponse(
          AuthorityResponseEnvelope(
            requestID: envelope.requestID,
            operationID: nil,
            result: try HandshakeResponse.v1())))
    }
    guard method == .bindProxyOwner,
      case .bindProxyOwner(let binding) = envelope.command
    else { throw AuthorityDomainError(code: .invalidMessage) }
    defer { binding.capability.erase() }
    let lease = try LeaseView(
      leaseID: binding.leaseID,
      operation: binding.operation,
      state: leaseState,
      expiryMonotonic: 10_000)
    return AuthorityXPCReply(
      response: try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID,
          operationID: binding.operation.operationID,
          result: lease)))
  }

  func confirmOwnerClaim() async throws {
    lock.withLock { confirmedClaimsValue += 1 }
  }

  func invalidate() async {}
}

/// Answers an owner's lease status as scripted, or fails every status query
/// with `failure`, and records what it was asked.
private final class LeaseStatusRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private let status: OwnerLeaseStatus
  private let failure: AuthorityDomainError?
  private var askedValue: [AuthorityIdentifier] = []
  private var methodsValue: [AuthorityXPCMethod] = []

  init(status: OwnerLeaseStatus, failure: AuthorityDomainError? = nil) {
    self.status = status
    self.failure = failure
  }

  var asked: [AuthorityIdentifier] { lock.withLock { askedValue } }
  var methods: [AuthorityXPCMethod] { lock.withLock { methodsValue } }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    lock.withLock { methodsValue.append(method) }
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    if method == .handshake {
      return AuthorityXPCReply(
        response: try AuthorityV1Codec.encodeResponse(
          AuthorityResponseEnvelope(
            requestID: envelope.requestID, operationID: nil,
            result: try HandshakeResponse.v1())))
    }
    guard method == .ownerLeaseStatus, case .ownerLeaseStatus(let request) = envelope.command
    else { throw AuthorityDomainError(code: .invalidMessage) }
    lock.withLock { askedValue.append(request.leaseID) }
    if let failure { throw failure }
    return AuthorityXPCReply(
      response: try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID, operationID: nil,
          result: OwnerLeaseStatusResponse(status: status))))
  }

  func invalidate() async {}
}

/// An owner asks after one lease over its own read-only method, and reads the
/// answer the Authority correlated with its request.
@Test(arguments: [OwnerLeaseStatus.held, .quarantined, .absent, .notReady])
func anOwnerAsksAfterItsLeaseOverItsOwnMethod(status: OwnerLeaseStatus) async throws {
  let remote = LeaseStatusRemote(status: status)
  let client = BoundedAuthorityXPCClient(remote: remote)
  let leaseID = AuthorityIdentifier(UUID())
  #expect(try await client.ownerLeaseStatus(leaseID) == status)
  #expect(remote.asked == [leaseID])
  #expect(remote.methods == [.handshake, .ownerLeaseStatus])
  #expect(AuthorityXPCMethod.ownerLeaseStatus.operationClass == .idempotentReadOnly)
}

/// The owner asks after its lease within the Host's wait for its stop reply,
/// so it asks once, within its own bound, even after a failure another
/// read-only call would retry.
@Test func anOwnerAsksAfterItsLeaseOnceWithinItsOwnBound() async throws {
  let timeout = AuthorityDomainError(code: .globalAuthorityTimeout)
  #expect(timeout.code.allowsAutomaticRetry(for: .idempotentReadOnly))
  let remote = LeaseStatusRemote(status: .held, failure: timeout)
  let client = BoundedAuthorityXPCClient(remote: remote)
  await #expect(throws: timeout) {
    _ = try await client.ownerLeaseStatus(AuthorityIdentifier(UUID()))
  }
  #expect(remote.methods == [.handshake, .ownerLeaseStatus])
  #expect(!AuthorityXPCMethod.ownerLeaseStatus.retriesAfterRetryableFailure)
  #expect(AuthorityXPCMethod.snapshot.retriesAfterRetryableFailure)

  let usual = Duration.seconds(5)
  #expect(AuthorityXPCMethod.ownerLeaseStatus.replyTimeout(within: usual) == .seconds(1))
  #expect(
    AuthorityXPCMethod.ownerLeaseStatus.replyTimeout(within: .milliseconds(200))
      == .milliseconds(200))
  #expect(AuthorityXPCMethod.attestStopped.replyTimeout(within: usual) == usual)
  #expect(AuthorityXPCMethod.snapshot.replyTimeout(within: usual) == usual)
}

@Test func unavailableAuthorityFailsClosedWithoutReachingAnyMutation() async throws {
  let remote = UnavailableAuthorityRemote()
  let client = BoundedAuthorityXPCClient(remote: remote)

  let operation = try exampleTunnelOperation()
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: 512, configSHA256: operation.configSHA256,
    identitySHA256: operation.identitySHA256,
    credentialAudience: try testCredentialAudience(), credentialSlots: [],
    tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: operation.authorityRevision,
    configuration: descriptor)
  let configuration = try SensitiveBytes(
    copying: Data(repeating: 0x41, count: 512), maximumCount: 512)
  let secrets = try SensitiveBytes(
    copying: Data(repeating: 0x42, count: 32), maximumCount: 32)

  var thrown: AuthorityDomainError?
  do {
    _ = try await client.prepare(request, configuration: configuration, secrets: secrets)
  } catch let error as AuthorityDomainError {
    thrown = error
  }

  // The failure is the stable typed Authority-unavailable error.
  #expect(thrown?.code == .globalAuthorityUnavailable)
  #expect(thrown?.nativeBridgeFailure.code == .globalAuthorityUnavailable)
  // Only the read-only handshake was attempted; the prepare mutation never
  // reached the remote, and there is no fallback call.
  #expect(remote.invokedMethods == [.handshake])
  #expect(!remote.invokedMethods.contains(.prepareStart))
  // Transported secret material is erased on the failure path.
  #expect(configuration.isErased)
  #expect(secrets.isErased)
}

@Test func cancellationAcceptsOnlyTheExactOperationAndDurableRevision() async throws {
  let operation = try exampleTunnelOperation()

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.cancelPrepared(
    operation,
    revision: operation.authorityRevision + 1)
  #expect(exactRemote.count(.cancelPrepared) == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.cancelPrepared(
        operation,
        revision: operation.authorityRevision + 1)
    }
    // A semantically invalid mutation ACK is terminal and is never retried.
    #expect(remote.count(.cancelPrepared) == 1)
  }
}

@Test func readyAcceptsOnlyTheExactOperationAndDurableRevision() async throws {
  let operation = try exampleTunnelOperation()
  let attestation = try ReadyAttestation(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()),
    runtimeDigest: operation.identitySHA256,
    ownerRole: .provider,
    readyFlags: .all,
    packetPumpLimits: PacketPumpLimits(
      maximumQueuedPackets: 32,
      maximumQueuedBytes: 131_072,
      maximumPacketBytes: 1_500,
      maximumReadBatch: 16),
    monotonicTimestamp: 2_000)

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.attestReady(attestation)
  #expect(exactRemote.count(.attestReady) == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.attestReady(attestation)
    }
    #expect(remote.count(.attestReady) == 1)
  }
}

@Test func stoppedAcceptsOnlyTheExactOperationAndLifecycleRevisionWindow() async throws {
  let operation = try exampleTunnelOperation()
  let attestation = try StoppedAttestation(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()),
    libboxStopped: true,
    transportClosed: true,
    osRestored: true,
    monotonicTimestamp: 3_000)

  let exactRemote = OperationAcknowledgementRemote(reply: .exact)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  try await exactClient.attestStopped(attestation)
  #expect(exactRemote.count(.attestStopped) == 1)
  #expect(exactRemote.ownerStoppedCount == 1)

  for fault in [
    OperationAcknowledgementRemote.Reply.wrongOperation,
    .wrongRevision,
  ] {
    let remote = OperationAcknowledgementRemote(reply: fault)
    let client = BoundedAuthorityXPCClient(remote: remote)
    await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
      try await client.attestStopped(attestation)
    }
    #expect(remote.count(.attestStopped) == 1)
    #expect(remote.ownerStoppedCount == 1)
  }
}

@Test func ownerHeartbeatStartsOnlyAfterAnExactStartingLeaseIsValidated() async throws {
  let operation = try exampleProxyOperation()
  let context = try ProxyOwnerContext(
    operation: operation,
    leaseID: AuthorityIdentifier(UUID()))

  let exactRemote = ProxyBindReplyRemote(leaseState: .starting)
  let exactClient = BoundedAuthorityXPCClient(remote: exactRemote)
  let exactLease = try await exactClient.bind(
    OwnerCapability(
      copying: Data(repeating: 0x41, count: AuthorityV1Limits.capabilityBytes)),
    context: context)
  #expect(exactLease.operation == operation)
  #expect(exactLease.leaseID == context.leaseID)
  #expect(exactRemote.confirmedClaims == 1)

  let invalidRemote = ProxyBindReplyRemote(leaseState: .active)
  let invalidClient = BoundedAuthorityXPCClient(remote: invalidRemote)
  await #expect(throws: AuthorityDomainError(code: .staleOperation)) {
    _ = try await invalidClient.bind(
      OwnerCapability(
        copying: Data(repeating: 0x42, count: AuthorityV1Limits.capabilityBytes)),
      context: context)
  }
  #expect(invalidRemote.confirmedClaims == 0)
}
