import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation

struct SnapshotObservation: Codable, Sendable {
  let snapshot: AuthoritySnapshot
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32

  var stateSHA256: String { get throws { try CFWAdversarialFixtureSupport.stateSHA256(snapshot) } }
}

struct RejectedPeerObservation: Codable, Sendable {
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
}

final class AuthorityWireSession: @unchecked Sendable {
  private let remote: NSXPCGlobalAuthorityRemote
  private var negotiated = false

  init(role: AuthorityRole = .host, timeout: Duration = .seconds(5)) {
    remote = NSXPCGlobalAuthorityRemote(role: role, timeout: timeout)
  }

  func invalidate() async { await remote.invalidate() }

  func handshake() async throws {
    guard !negotiated else { return }
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID,
      command: .handshake(HandshakeRequest(version: try AuthorityProtocolVersion())))
    let request = try AuthorityV1Codec.encode(envelope)
    let reply = try await remote.call(
      method: .handshake, request: request, configuration: nil, secretPayload: nil)
    let response = try AuthorityV1Codec.decodeResponse(
      HandshakeResponse.self, from: reply.response)
    guard response.requestID == requestID, response.operationID == nil,
      response.result == (try HandshakeResponse.v1())
    else { throw FixtureError.authorityResponseInvalid }
    negotiated = true
  }

  func snapshot() async throws -> SnapshotObservation {
    try await handshake()
    let request = try makeSnapshotRequest()
    let response = try await performSnapshotRequest(request)
    return SnapshotObservation(
      snapshot: response,
      requestSHA256: sha256(request),
      process: try currentProcessObservation(),
      effectiveUserIdentifier: UInt32(geteuid()),
      auditSessionIdentifier: audit_session_self())
  }

  func makeSnapshotRequest() throws -> Data {
    let envelope = try AuthorityRequestEnvelope(
      requestID: AuthorityIdentifier(UUID()), command: .snapshot(SnapshotRequest()))
    return try AuthorityV1Codec.encode(envelope)
  }

  func performSnapshotRequest(_ request: Data) async throws -> AuthoritySnapshot {
    let envelope = try AuthorityV1Codec.decodeRequest(request)
    guard case .snapshot = envelope.command else { throw FixtureError.authorityResponseInvalid }
    let reply = try await remote.call(
      method: .snapshot, request: request, configuration: nil, secretPayload: nil)
    let response = try AuthorityV1Codec.decodeResponse(
      AuthoritySnapshot.self, from: reply.response)
    guard response.requestID == envelope.requestID, response.operationID == nil else {
      throw FixtureError.authorityResponseInvalid
    }
    return response.result
  }

  func prepareSystemProxy(
    configuration: Data, operationID: UUID = UUID(), profileID: UUID = UUID()
  ) async throws -> (prepared: PreparedStart, request: Data) {
    let observed = try await snapshot()
    guard observed.snapshot.state == .off, observed.snapshot.leaseView == nil else {
      throw FixtureError.cleanupContaminated
    }
    let digest = try SHA256Digest(hex: sha256(configuration))
    let identityMaterial = Data("cfw-adversarial-fixture-identity-v1".utf8) + configuration
    let identityDigest = try SHA256Digest(hex: sha256(identityMaterial))
    let root: RootContext
    if let cursor = observed.snapshot.replayCursor {
      let (generation, overflow) = cursor.acceptedGeneration.addingReportingOverflow(1)
      guard !overflow else { throw FixtureError.authorityResponseInvalid }
      root = try RootContext(
        installationID: cursor.installationID,
        epoch: cursor.acceptedEpoch,
        generation: generation)
    } else {
      root = try RootContext(
        installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
    }
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(operationID),
      root: root,
      mode: .systemProxy,
      configSHA256: digest,
      identitySHA256: identityDigest,
      ownerUID: UInt32(geteuid()),
      authorityRevision: observed.snapshot.revision)
    let descriptor = try AuthorityConfigurationDescriptor(
      byteCount: UInt32(configuration.count),
      configSHA256: digest,
      identitySHA256: identityDigest,
      credentialAudience: CredentialAudience(
        profileID: profileID, profileDigest: identityDigest),
      credentialSlots: [],
      tunnelOptions: nil)
    let prepare = try PrepareStartRequest(
      operation: operation,
      expectedRevision: observed.snapshot.revision,
      configuration: descriptor)
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .prepareStart(prepare))
    let request = try AuthorityV1Codec.encode(envelope)
    let reply = try await remote.call(
      method: .prepareStart,
      request: request,
      configuration: configuration,
      secretPayload: nil)
    let prepared = try AuthorityPreparedStartCodec.decode(
      reply.response,
      requestID: requestID,
      operationID: operation.operationID)
    guard prepared.operation == operation else {
      prepared.erase()
      throw FixtureError.authorityResponseInvalid
    }
    return (prepared, request)
  }

  func cancelPrepared(_ prepared: PreparedStart) async throws {
    let observed = try await snapshot()
    guard observed.snapshot.state == .preparing,
      let lease = observed.snapshot.leaseView,
      lease.operation == prepared.operation,
      lease.leaseID == prepared.leaseID
    else { throw FixtureError.cleanupContaminated }
    let request = try CancelPreparedRequest(
      operation: prepared.operation,
      expectedRevision: observed.snapshot.revision)
    let requestID = AuthorityIdentifier(UUID())
    let envelope = try AuthorityRequestEnvelope(
      requestID: requestID, command: .cancelPrepared(request))
    let encoded = try AuthorityV1Codec.encode(envelope)
    let reply = try await remote.call(
      method: .cancelPrepared,
      request: encoded,
      configuration: nil,
      secretPayload: nil)
    let response = try AuthorityV1Codec.decodeResponse(
      AuthorityAcknowledgement.self, from: reply.response)
    guard response.requestID == requestID,
      response.operationID == prepared.operation.operationID,
      response.result.operationID == prepared.operation.operationID
    else { throw FixtureError.authorityResponseInvalid }
    prepared.erase()
    let clean = try await snapshot()
    guard clean.snapshot.state == .off, clean.snapshot.leaseView == nil else {
      throw FixtureError.cleanupContaminated
    }
  }

  func replayPrepare(
    request: Data, configuration: Data
  ) async throws -> AuthorityErrorCode {
    do {
      _ = try await remote.call(
        method: .prepareStart,
        request: request,
        configuration: configuration,
        secretPayload: nil)
      throw FixtureError.authorityResponseInvalid
    } catch let error as AuthorityDomainError {
      return error.code
    }
  }
}

func directSnapshot() async throws -> SnapshotObservation {
  let session = AuthorityWireSession()
  do {
    let observation = try await session.snapshot()
    await session.invalidate()
    return observation
  } catch {
    await session.invalidate()
    throw error
  }
}

func rejectedHostHandshake() async throws -> RejectedPeerObservation {
  let remote = NSXPCGlobalAuthorityRemote(role: .host, timeout: .seconds(5))
  let process = try currentProcessObservation()
  let requestID = AuthorityIdentifier(UUID())
  let envelope = try AuthorityRequestEnvelope(
    requestID: requestID,
    command: .handshake(HandshakeRequest(version: try AuthorityProtocolVersion())))
  let request = try AuthorityV1Codec.encode(envelope)
  do {
    _ = try await remote.call(
      method: .handshake, request: request, configuration: nil, secretPayload: nil)
    await remote.invalidate()
    throw FixtureError.authorityResponseInvalid
  } catch let error as AuthorityDomainError {
    await remote.invalidate()
    switch error.code {
    case .globalAuthorityInterrupted:
      break
    case .globalAuthorityUnavailable, .globalAuthorityTimeout,
      .globalAuthorityRegistrationRequired:
      throw FixtureError.physicalPreconditionUnavailable
    default:
      throw FixtureError.authorityResponseInvalid
    }
    return RejectedPeerObservation(
      requestSHA256: sha256(request),
      process: process,
      effectiveUserIdentifier: UInt32(geteuid()),
      auditSessionIdentifier: audit_session_self())
  }
}

struct ReplayOperationObservation: Sendable {
  let requestSHA256: String
  let before: SnapshotObservation
  let after: SnapshotObservation
}

func exerciseReplayedOperation() async throws -> ReplayOperationObservation {
  let configuration = Data("{\"fixture\":\"replayed-operation\"}".utf8)
  let session = AuthorityWireSession()
  do {
    let prepared = try await session.prepareSystemProxy(configuration: configuration)
    try await session.cancelPrepared(prepared.prepared)
    let before = try await session.snapshot()
    guard before.snapshot.state == .off else { throw FixtureError.cleanupContaminated }
    let code = try await session.replayPrepare(
      request: prepared.request, configuration: configuration)
    guard code == .replayRejected else { throw FixtureError.authorityResponseInvalid }
    let after = try await session.snapshot()
    guard after.snapshot.state == .off,
      try before.stateSHA256 == after.stateSHA256
    else { throw FixtureError.cleanupContaminated }
    await session.invalidate()
    return ReplayOperationObservation(
      requestSHA256: sha256(prepared.request), before: before, after: after)
  } catch {
    await session.invalidate()
    throw error
  }
}

struct CanaryCycleObservation: Codable, Sendable {
  let requestSHA256: String
  let cleanSnapshot: SnapshotObservation
}

func exerciseCanaryCycle(_ canary: Data) async throws -> CanaryCycleObservation {
  guard !canary.isEmpty, canary.count <= 4_096 else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let session = AuthorityWireSession()
  do {
    let prepared = try await session.prepareSystemProxy(configuration: canary)
    try await session.cancelPrepared(prepared.prepared)
    let clean = try await session.snapshot()
    guard clean.snapshot.state == .off, clean.snapshot.leaseView == nil else {
      throw FixtureError.cleanupContaminated
    }
    await session.invalidate()
    return CanaryCycleObservation(
      requestSHA256: sha256(prepared.request), cleanSnapshot: clean)
  } catch {
    await session.invalidate()
    throw error
  }
}
