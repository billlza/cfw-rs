import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

private final class ServiceJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private(set) var states: [AuthorityCommittedState] = []

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      states.append(state)
      return try AuthorityJournalHead(
        sequence: UInt64(states.count), committedLength: UInt64(states.count),
        recordSHA256: serviceDigest(Data("journal-\(states.count)".utf8)))
    }
  }

  var count: Int { lock.withLock { states.count } }
}

private struct ExhaustedServiceJournal: AuthorityJournalCommitting {
  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    throw AuthorityJournalStorageError.capacityExhausted
  }
}

private struct ServiceRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private struct ServiceClock: AuthorityMonotonicClock {
  func nowMilliseconds() -> UInt64 { 1_000 }
}

private func serviceDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map {
      String(format: "%02x", $0)
    }.joined())
}

private func servicePeer(_ role: AuthorityRole = .host) throws -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: try serviceDigest(Data("connection".utf8)),
    pid: 42, euid: role == .provider ? 0 : 501,
    auditSessionID: role == .provider ? 0 : 7,
    role: role, consoleUID: 501)
}
private struct ServiceFixture {
  let request: PrepareStartRequest
  let configuration: Data
  let secretPayload: Data
  let secretMarker: String
}

private func serviceFixture() throws -> ServiceFixture {
  let configuration = Data("{\"outbounds\":[]}".utf8)
  let configDigest = try serviceDigest(configuration)
  let identityDigest = try serviceDigest(Data("identity".utf8))
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let slot = try CredentialSlot(
    reference: reference, target: .trojanPassword,
    outboundIndex: 0, jsonPointer: "/outbounds/0/password")
  let operation = try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
    mode: .tunnel, configSHA256: configDigest,
    identitySHA256: identityDigest, ownerUID: 501,
    authorityRevision: 1)
  let descriptor = try AuthorityConfigurationDescriptor(
    byteCount: UInt32(configuration.count), configSHA256: configDigest,
    identitySHA256: identityDigest,
    credentialAudience: CredentialAudience(profileID: UUID(), profileDigest: identityDigest),
    credentialSlots: [slot],
    tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
  let request = try PrepareStartRequest(
    operation: operation, expectedRevision: 1,
    configuration: descriptor)
  let marker = "credential-marker-never-serialize"
  let secretSlot = try AuthoritySecretSlot(
    reference: reference, copying: Data(marker.utf8))
  let material = try AuthoritySecretMaterial(slots: [secretSlot])
  let encodedPayload = try AuthoritySecretPayloadCodec.encode(material)
  let encoded = try #require(encodedPayload)
  let payload = try encoded.withUnsafeBytes { Data($0) }
  encoded.erase()
  material.erase()
  return ServiceFixture(
    request: request, configuration: configuration,
    secretPayload: payload, secretMarker: marker)
}

private func serviceObjects() throws -> (
  journal: ServiceJournal,
  core: GlobalAuthorityServiceCore,
  service: AuthenticatedAuthorityPeerService
) {
  let journal = ServiceJournal()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(), journal: journal,
    randomness: ServiceRandomness(), clock: ServiceClock())
  let peer = try servicePeer()
  let service = AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: peer, reauthorize: { peer }, core: core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
  return (journal, core, service)
}

private func authorityError(_ value: NSError?) -> AuthorityErrorCode? {
  guard let value,
    let raw = value.userInfo[AuthorityXPCErrorContract.stableCodeKey] as? String
  else { return nil }
  return AuthorityErrorCode(rawValue: raw)
}
@Test func connectionAuthenticationCompletesBeforeExport() throws {
  var exports = 0
  let denied = AuthorityConnectionAdmission.authorizeBeforeExport(
    authorize: { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) },
    export: { _ in exports += 1 })
  #expect(!denied)
  #expect(exports == 0)

  let admitted = AuthorityConnectionAdmission.authorizeBeforeExport(
    authorize: { try servicePeer() },
    export: { _ in exports += 1 })
  #expect(admitted)
  #expect(exports == 1)
}

@Test func journalCapacityExhaustionIsExplicitAndDoesNotMutateAuthorityState() throws {
  let fixture = try serviceFixture()
  let core = GlobalAuthorityServiceCore(
    reducer: try .unEnrolledOff(),
    journal: ExhaustedServiceJournal(),
    randomness: ServiceRandomness(),
    clock: ServiceClock())
  let peer = try servicePeer()

  do {
    _ = try core.prepare(
      fixture.request,
      configuration: fixture.configuration,
      secretPayload: fixture.secretPayload,
      peer: peer)
    Issue.record("Journal capacity exhaustion must reject the prepare")
  } catch let error as AuthorityDomainError {
    #expect(error.code == .journalCapacityExhausted)
  }

  let snapshot = try core.snapshot(peer: peer)
  #expect(snapshot.state == .off)
  #expect(snapshot.revision == 1)
  #expect(snapshot.leaseView == nil)
}

@Test func malformedOversizeAndWrongCommandFailBeforeMutation() throws {
  let objects = try serviceObjects()
  let fixture = try serviceFixture()
  var observed: [AuthorityErrorCode?] = []

  objects.service.prepareStart(
    Data("{}".utf8), configuration: fixture.configuration,
    secretPayload: fixture.secretPayload
  ) { _, error in observed.append(authorityError(error)) }

  objects.service.prepareStart(
    Data(repeating: 0, count: AuthorityV1Limits.maximumEnvelopeBytes + 1),
    configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { _, error in observed.append(authorityError(error)) }

  let snapshotEnvelope = try AuthorityRequestEnvelope(
    requestID: AuthorityIdentifier(UUID()),
    command: .snapshot(SnapshotRequest()))
  objects.service.prepareStart(
    try AuthorityV1Codec.encode(snapshotEnvelope),
    configuration: fixture.configuration, secretPayload: fixture.secretPayload
  ) { _, error in observed.append(authorityError(error)) }

  #expect(observed == [.invalidMessage, .invalidMessage, .invalidMessage])
  #expect(objects.journal.count == 0)
}

@Test func prepareUsesCanonicalCorrelationAndSnapshotContainsNoSecret() throws {
  let objects = try serviceObjects()
  let fixture = try serviceFixture()
  let prepareID = AuthorityIdentifier(UUID())
  let prepareEnvelope = try AuthorityRequestEnvelope(
    requestID: prepareID, command: .prepareStart(fixture.request))
  var preparedData: Data?
  var prepareError: NSError?
  objects.service.prepareStart(
    try AuthorityV1Codec.encode(prepareEnvelope),
    configuration: fixture.configuration,
    secretPayload: fixture.secretPayload
  ) { data, error in
    preparedData = data
    prepareError = error
  }
  #expect(prepareError == nil)
  let prepared = try AuthorityPreparedStartCodec.decode(
    #require(preparedData), requestID: prepareID,
    operationID: fixture.request.operation.operationID)
  #expect(prepared.operation == fixture.request.operation)
  prepared.ticket?.erase()

  let snapshotID = AuthorityIdentifier(UUID())
  let snapshotEnvelope = try AuthorityRequestEnvelope(
    requestID: snapshotID, command: .snapshot(SnapshotRequest()))
  var snapshotData: Data?
  objects.service.snapshot(try AuthorityV1Codec.encode(snapshotEnvelope)) { data, error in
    #expect(error == nil)
    snapshotData = data
  }
  let bytes = try #require(snapshotData)
  #expect(!String(decoding: bytes, as: UTF8.self).contains(fixture.secretMarker))
  let snapshot = try AuthorityV1Codec.decodeResponse(
    AuthoritySnapshot.self, from: bytes)
  #expect(snapshot.requestID == snapshotID)
  #expect(snapshot.result.state == .preparing)
  #expect(objects.journal.count == 2)
  #expect(objects.journal.states.first?.transition == .enrollOff)
  #expect(objects.journal.states.first?.state == .off)
  #expect(objects.journal.states.first?.epoch == 0)
  #expect(objects.journal.states.first?.generation == 0)
  #expect(objects.journal.states.last?.transition == .prepare)
}
