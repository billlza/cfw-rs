import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWAppleNetwork

// MARK: - Fakes

private final class FakeAuthorityClient: AuthorityClient, @unchecked Sendable {
  private let lock = NSLock()
  private var prepareCountValue = 0
  private var snapshotCountValue = 0
  private var recordedRequests: [PrepareStartRequest] = []
  private let snapshotResult: Result<AuthoritySnapshot, Error>
  var prepareResultFactory: (@Sendable (PrepareStartRequest) throws -> PreparedStart)?

  init(snapshot: AuthoritySnapshot) { snapshotResult = .success(snapshot) }
  init(snapshotError: Error) { snapshotResult = .failure(snapshotError) }

  var prepareCount: Int { lock.withLock { prepareCountValue } }
  var snapshotCount: Int { lock.withLock { snapshotCountValue } }
  var requests: [PrepareStartRequest] { lock.withLock { recordedRequests } }

  func prepare(
    _ request: PrepareStartRequest,
    configuration: SensitiveBytes, secrets: SensitiveBytes?
  ) async throws -> PreparedStart {
    configuration.erase()
    secrets?.erase()
    lock.withLock {
      prepareCountValue += 1
      recordedRequests.append(request)
    }
    guard let prepareResultFactory else {
      throw AuthorityDomainError(code: .invalidMessage)
    }
    return try prepareResultFactory(request)
  }

  func cancelPrepared(_ context: OperationContext, revision: UInt64) async throws {}

  func beginStop(_ request: BeginStopRequest) async throws -> StopDirective {
    throw AuthorityDomainError(code: .invalidMessage)
  }

  func completeStop(_ request: CompleteStopRequest) async throws {
    throw AuthorityDomainError(code: .invalidMessage)
  }

  func reconcileOff(
    _ request: ReconcileOffRequest
  ) async throws -> ReconcileOffReceipt {
    throw AuthorityDomainError(code: .invalidMessage)
  }

  func snapshot() async throws -> AuthoritySnapshot {
    lock.withLock { snapshotCountValue += 1 }
    return try snapshotResult.get()
  }
}

/// Counts calls per method and echoes a valid handshake so the client negotiates,
/// then fails the configured methods with a retryable transport error. Exercises
/// the real bounded Host Authority client's retry classification.
private final class CountingAuthorityRemote: AuthorityRemoteCalling, @unchecked Sendable {
  private let lock = NSLock()
  private var counts: [String: Int] = [:]
  private let failingMethods: Set<String>
  private let failCode: AuthorityErrorCode

  init(
    failingMethods: Set<AuthorityXPCMethod>,
    failCode: AuthorityErrorCode = .globalAuthorityTimeout
  ) {
    self.failingMethods = Set(failingMethods.map(Self.key))
    self.failCode = failCode
  }

  func count(_ method: AuthorityXPCMethod) -> Int {
    lock.withLock { counts[Self.key(method)] ?? 0 }
  }

  func call(
    method: AuthorityXPCMethod, request: Data,
    configuration: Data?, secretPayload: Data?
  ) async throws -> AuthorityXPCReply {
    lock.withLock { counts[Self.key(method), default: 0] += 1 }
    if method == .handshake {
      let envelope = try AuthorityV1Codec.decodeRequest(request)
      let data = try AuthorityV1Codec.encodeResponse(
        AuthorityResponseEnvelope(
          requestID: envelope.requestID, operationID: nil,
          result: try HandshakeResponse.v1()))
      return AuthorityXPCReply(response: data)
    }
    if failingMethods.contains(Self.key(method)) {
      throw AuthorityDomainError(code: failCode)
    }
    throw AuthorityDomainError(code: .invalidMessage)
  }

  func invalidate() async {}

  private static func key(_ method: AuthorityXPCMethod) -> String { "\(method)" }
}

// MARK: - Builders

private let installationA = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
private let installationB = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

private func tunnelDescriptor(
  installationID: UUID,
  sha: String = String(repeating: "ab", count: 32),
  identity: String = String(repeating: "cd", count: 32)
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true, mtu: 1_500),
    credentialAudience: try appleCredentialAudience(),
    installationID: installationID,
    epoch: 1, generation: 1, byteCount: 2,
    sha256: SHA256Digest(hex: sha),
    identitySHA256: SHA256Digest(hex: identity))
}

private func offSnapshot(
  installationID: UUID, revision: UInt64 = 3
) throws -> AuthoritySnapshot {
  let cursor = try ReplayCursor(
    installationID: AuthorityIdentifier(installationID),
    acceptedEpoch: 1, acceptedGeneration: 1, revision: revision,
    previousRecordSHA256: SHA256Digest(hex: String(repeating: "0", count: 64)))
  return try AuthoritySnapshot(
    protocolVersion: AuthorityProtocolVersion(), state: .off, revision: revision,
    replayCursor: cursor, leaseView: nil, lastFailure: nil, consoleUID: 501)
}

private func preparedTicket(
  for request: PrepareStartRequest, byte: UInt8 = 0xAB
) throws -> PreparedStart {
  try PreparedStart(
    operation: request.operation, leaseID: AuthorityIdentifier(UUID()),
    ticket: StartTicket(copying: Data(repeating: byte, count: AuthorityV1Limits.ticketBytes)),
    ownerCapability: nil, expiresMonotonic: 10_000,
    preferenceDescriptorSHA256: request.operation.identitySHA256)
}

private func operationContext(revision: UInt64 = 5) throws -> OperationContext {
  let root = try RootContext(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  return try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .tunnel,
    configSHA256: digest, identitySHA256: digest, ownerUID: 501,
    authorityRevision: revision)
}

private func sharedProtocolSource(_ fileName: String) throws -> String {
  let url = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // CFWAppleNetworkTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // macos
    .appendingPathComponent("Sources/CFWSharedProtocol/\(fileName)")
  return try String(contentsOf: url, encoding: .utf8)
}

// MARK: - Tests

@Suite(.serialized)
struct AuthorityBackedTunnelStartPreparerTests {
  @Test func preparesTunnelStartThroughAuthorityAndReturnsOnlyTheTicket() async throws {
    let descriptor = try tunnelDescriptor(installationID: installationA)
    let client = FakeAuthorityClient(snapshot: try offSnapshot(installationID: installationA))
    client.prepareResultFactory = { try preparedTicket(for: $0, byte: 0xC7) }
    let enrollment = AuthorityInstallationEnrollment()
    let preparer = AuthorityBackedTunnelStartPreparer(
      authority: client, enrollment: enrollment, ownerUID: 501)

    let prepared = try await preparer.prepareTunnelStart(
      HostTunnelStartPreparation(
        descriptor: descriptor, configuration: Data("{}".utf8), credentialPayload: nil))

    #expect(prepared.descriptor == descriptor)
    let ticketBytes = try prepared.ticket.withUnsafeBytes { Data($0) }
    #expect(ticketBytes == Data(repeating: 0xC7, count: AuthorityV1Limits.ticketBytes))
    #expect(client.prepareCount == 1)
    #expect(await enrollment.installationID == descriptor.installationID)

    // The Authority received the enrolled installation and expected revision.
    let request = client.requests.first
    #expect(request?.operation.root.installationID.rawValue == descriptor.installationID)
    #expect(request?.operation.mode == .tunnel)
    #expect(request?.expectedRevision == 3)
    #expect(request?.operation.authorityRevision == 3)
  }

  @Test func secondEnrollmentOfDifferentInstallationFailsClosedWithoutReachingAuthority()
    async throws
  {
    let first = try tunnelDescriptor(installationID: installationA)
    let client = FakeAuthorityClient(snapshot: try offSnapshot(installationID: installationA))
    client.prepareResultFactory = { try preparedTicket(for: $0) }
    let enrollment = AuthorityInstallationEnrollment()
    let preparer = AuthorityBackedTunnelStartPreparer(
      authority: client, enrollment: enrollment, ownerUID: 501)

    _ = try await preparer.prepareTunnelStart(
      HostTunnelStartPreparation(
        descriptor: first, configuration: Data("{}".utf8), credentialPayload: nil))
    #expect(client.prepareCount == 1)

    // Enrollment is immutable: a different installation ID is rejected fail-closed
    // and never reaches the Authority.
    let second = try tunnelDescriptor(installationID: installationB)
    await #expect(throws: AuthorityDomainError(code: .replayRejected)) {
      try await preparer.prepareTunnelStart(
        HostTunnelStartPreparation(
          descriptor: second, configuration: Data("{}".utf8), credentialPayload: nil))
    }
    #expect(client.prepareCount == 1)
    #expect(client.snapshotCount == 1)
    #expect(await enrollment.installationID == installationA)
  }

  @Test func reenrollingTheSameInstallationIsIdempotent() async throws {
    let enrollment = AuthorityInstallationEnrollment()
    #expect(try await enrollment.enroll(installationA) == installationA)
    #expect(try await enrollment.enroll(installationA) == installationA)
    await #expect(throws: AuthorityInstallationEnrollment.EnrollmentError.installationImmutable) {
      _ = try await enrollment.enroll(installationB)
    }
  }

  @Test func boundedTimeoutSurfacesStableTypedTimeoutError() async throws {
    let descriptor = try tunnelDescriptor(installationID: installationA)
    let client = FakeAuthorityClient(
      snapshotError: AuthorityDomainError(code: .globalAuthorityTimeout))
    let preparer = AuthorityBackedTunnelStartPreparer(authority: client, ownerUID: 501)

    await #expect(throws: AuthorityDomainError(code: .globalAuthorityTimeout)) {
      try await preparer.prepareTunnelStart(
        HostTunnelStartPreparation(
          descriptor: descriptor, configuration: Data("{}".utf8), credentialPayload: nil))
    }
    #expect(client.prepareCount == 0)
  }

  @Test func connectionInterruptionFailsClosedWithTypedError() async throws {
    let descriptor = try tunnelDescriptor(installationID: installationA)
    let client = FakeAuthorityClient(
      snapshotError: AuthorityDomainError(code: .globalAuthorityInterrupted))
    let preparer = AuthorityBackedTunnelStartPreparer(authority: client, ownerUID: 501)

    await #expect(throws: AuthorityDomainError(code: .globalAuthorityInterrupted)) {
      try await preparer.prepareTunnelStart(
        HostTunnelStartPreparation(
          descriptor: descriptor, configuration: Data("{}".utf8), credentialPayload: nil))
    }
    #expect(client.prepareCount == 0)
  }

  @Test func recoveringAuthorityFailsClosedBeforePreparation() async throws {
    let descriptor = try tunnelDescriptor(installationID: installationA)
    let client = FakeAuthorityClient(
      snapshotError: AuthorityDomainError(code: .globalAuthorityRecovering))
    let preparer = AuthorityBackedTunnelStartPreparer(authority: client, ownerUID: 501)

    await #expect(throws: AuthorityDomainError(code: .globalAuthorityRecovering)) {
      try await preparer.prepareTunnelStart(
        HostTunnelStartPreparation(
          descriptor: descriptor, configuration: Data("{}".utf8), credentialPayload: nil))
    }
    #expect(client.prepareCount == 0)
  }

  @Test func idempotentReadRetriesOnceWhileMutationDoesNotRetry() async throws {
    // An idempotent read (snapshot) is retried once on a retryable transport error.
    let readRemote = CountingAuthorityRemote(failingMethods: [.snapshot])
    let readClient = BoundedAuthorityXPCClient(remote: readRemote)
    await #expect(throws: AuthorityDomainError(code: .globalAuthorityTimeout)) {
      _ = try await readClient.snapshot()
    }
    #expect(readRemote.count(.handshake) == 1)
    #expect(readRemote.count(.snapshot) == 2)

    // A mutation (cancelPrepared) is never retried, even on the same retryable code.
    let mutateRemote = CountingAuthorityRemote(failingMethods: [.cancelPrepared])
    let mutateClient = BoundedAuthorityXPCClient(remote: mutateRemote)
    let context = try operationContext()
    await #expect(throws: AuthorityDomainError(code: .globalAuthorityTimeout)) {
      try await mutateClient.cancelPrepared(context, revision: context.authorityRevision)
    }
    #expect(mutateRemote.count(.cancelPrepared) == 1)
  }

  @Test func publicBridgeCommandBoundaryExcludesRawAuthorityCommands() throws {
    let source = try sharedProtocolSource("NativeBridgeCommand.swift")
    let forbidden = [
      "prepareStart", "prepare_start",
      "redeemTunnelTicket", "redeem_tunnel_ticket",
      "bindProxyOwner", "bind_proxy_owner",
      "attestReady", "attest_ready",
      "attestStopped", "attest_stopped",
      "cancelPrepared", "cancel_prepared",
      "handshake",
    ]
    for token in forbidden {
      #expect(
        !source.contains(token),
        "Public bridge command surface must not expose raw Authority command \(token).")
    }
  }
}
