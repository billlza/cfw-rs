import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

private enum RecoveryReconciliationFixtureError: Error {
  case setup
}

private func recoveryDigest(
  _ value: String
) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: Data(value.utf8)).map {
      String(format: "%02x", $0)
    }.joined())
}

private func recoveryPeer(
  role: AuthorityRole = .host,
  euid: UInt32? = nil,
  consoleUID: UInt32? = 501
) throws -> PeerIdentity {
  PeerIdentity(
    connectionIdentityDigest: try recoveryDigest("\(role.rawValue)-connection"),
    pid: 42,
    euid: euid ?? (role == .provider ? 0 : 501),
    auditSessionID: role == .provider ? 0 : 7,
    role: role,
    consoleUID: consoleUID)
}

private func recoveryCommittedState(
  _ state: AuthorityState,
  revision: UInt64 = 11
) throws -> AuthorityCommittedState {
  let transition: AuthorityJournalTransition
  switch state {
  case .off:
    transition = .globalOff
  case .active:
    transition = .ready
  case .stopping:
    transition = .beginStop
  default:
    throw RecoveryReconciliationFixtureError.setup
  }
  let hasOperation = state != .off
  return try AuthorityCommittedState(
    installationID: AuthorityIdentifier(
      UUID(uuidString: "11111111-1111-1111-1111-111111111111")!),
    epoch: 3,
    generation: 5,
    revision: revision,
    transition: transition,
    state: state,
    operationID: hasOperation
      ? AuthorityIdentifier(
        UUID(uuidString: "22222222-2222-2222-2222-222222222222")!) : nil,
    mode: hasOperation ? .tunnel : nil,
    configSHA256: hasOperation ? recoveryDigest("configuration") : nil,
    leaseID: hasOperation
      ? AuthorityIdentifier(
        UUID(uuidString: "33333333-3333-3333-3333-333333333333")!) : nil,
    ownerUID: hasOperation ? 501 : nil)
}

private func temporaryRecoveryDirectory() throws -> URL {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "cfw-authority-reconcile-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(
    at: root, withIntermediateDirectories: false)
  guard chmod(root.path, 0o700) == 0,
    let canonicalPath = realpath(root.path, nil)
  else {
    throw RecoveryReconciliationFixtureError.setup
  }
  defer { free(canonicalPath) }
  return URL(
    fileURLWithPath: String(cString: canonicalPath), isDirectory: true)
}

private func withTemporaryRecoveryDirectory<Result>(
  _ body: (URL, InMemoryAuthorityJournalAnchorStore) throws -> Result
) throws -> Result {
  let root = try temporaryRecoveryDirectory()
  defer { try? FileManager.default.removeItem(at: root) }
  return try body(root, InMemoryAuthorityJournalAnchorStore())
}

private func seedRecoveryJournal(
  at root: URL,
  anchor: InMemoryAuthorityJournalAnchorStore,
  state: AuthorityState
) throws {
  let store = try DescriptorRelativeAuthorityJournalStore(
    testingRootPath: root.path, expectedOwnerUID: getuid(),
    anchorStore: anchor)
  _ = try store.appendCommitted(
    AuthorityCommittedState(
      installationID: AuthorityIdentifier(
        UUID(uuidString: "11111111-1111-1111-1111-111111111111")!),
      epoch: 0, generation: 0, revision: 10,
      transition: .enrollOff, state: .off,
      operationID: nil, mode: nil, configSHA256: nil,
      leaseID: nil, ownerUID: nil))
  _ = try store.appendCommitted(recoveryCommittedState(state))
}

private func exactRecoveryRequest(
  cursor: ReplayCursor,
  proxyOwnershipCleared: Bool = true,
  proxyListenerClosed: Bool = true,
  systemConfigurationRestored: Bool = true,
  providerOwnershipCleared: Bool = true,
  libboxStopped: Bool = true,
  packetPumpClosed: Bool = true,
  managedTunnel: RecoveryManagedTunnelStatus = .disconnected
) throws -> ReconcileOffRequest {
  try ReconcileOffRequest(
    expectedRevision: cursor.revision,
    replayCursor: cursor,
    proxy: RecoveryProxyOffEvidence(
      ownershipCleared: proxyOwnershipCleared,
      listenerClosed: proxyListenerClosed,
      effectiveSystemConfigurationRestored: systemConfigurationRestored),
    provider: RecoveryProviderOffEvidence(
      ownershipCleared: providerOwnershipCleared,
      libboxStopped: libboxStopped,
      packetPumpClosed: packetPumpClosed),
    managedTunnel: managedTunnel)
}

private func expectedRecoveryAction(
  for state: AuthorityState
) throws -> AuthorityRecoveryAction {
  switch state {
  case .off:
    .verifyOff
  case .active:
    .reattestOwner
  case .stopping:
    .stopOwner
  default:
    throw RecoveryReconciliationFixtureError.setup
  }
}

private func reconcileRestartedJournal(
  at root: URL,
  anchor: InMemoryAuthorityJournalAnchorStore,
  expectedInitialState: AuthorityState,
  managedTunnel: RecoveryManagedTunnelStatus
) throws -> ReconcileOffReceipt {
  let store = try DescriptorRelativeAuthorityJournalStore(
    testingRootPath: root.path, expectedOwnerUID: getuid(),
    anchorStore: anchor)
  let recovery = store.recover()
  #expect(
    recovery.posture
      == .recovering(try expectedRecoveryAction(for: expectedInitialState)))
  let reducer = try GlobalAuthorityReducer.reconciled(from: recovery)
  let core = GlobalAuthorityServiceCore(reducer: reducer, journal: store)
  #expect(core.authorityState == .recovering)
  let snapshot = try core.snapshot(peer: recoveryPeer())
  let cursor = try #require(snapshot.replayCursor)
  let request = try exactRecoveryRequest(
    cursor: cursor, managedTunnel: managedTunnel)
  let requestID = AuthorityIdentifier(UUID())
  let envelope = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: requestID, command: .reconcileOff(request)))
  let peer = try recoveryPeer()
  let service = AuthenticatedAuthorityPeerService(
    peerID: UUID(), peer: peer, reauthorize: { peer }, core: core,
    concurrency: AuthorityConcurrencyGate(), events: AuthorityEventHub())
  var responseData: Data?
  var responseError: NSError?
  service.reconcileOff(envelope) { data, error in
    responseData = data
    responseError = error
  }
  if let responseError { throw responseError }
  let response = try AuthorityV1Codec.decodeResponse(
    ReconcileOffReceipt.self, from: try #require(responseData))
  #expect(response.requestID == requestID)
  #expect(response.operationID == nil)
  #expect(response.result.replayCursor == cursor)
  return response.result
}

private func withRecoveredCore<Result>(
  at root: URL,
  anchor: InMemoryAuthorityJournalAnchorStore,
  _ body: (
    GlobalAuthorityServiceCore,
    ReplayCursor,
    DescriptorRelativeAuthorityJournalStore
  ) throws -> Result
) throws -> Result {
  let store = try DescriptorRelativeAuthorityJournalStore(
    testingRootPath: root.path, expectedOwnerUID: getuid(),
    anchorStore: anchor)
  let recovery = store.recover()
  let reducer = try GlobalAuthorityReducer.reconciled(from: recovery)
  let cursor = try #require(reducer.replayCursor)
  let core = GlobalAuthorityServiceCore(reducer: reducer, journal: store)
  return try body(core, cursor, store)
}

private func recoveryAuthorityCode<Result>(
  _ body: () throws -> Result
) -> AuthorityErrorCode? {
  do {
    _ = try body()
    return nil
  } catch let error as AuthorityDomainError {
    return error.code
  } catch {
    return nil
  }
}

@Test func descriptorRelativeRestartRequiresExplicitExactOffReconciliation() throws {
  let cases: [(AuthorityState, RecoveryManagedTunnelStatus)] = [
    (.off, .disconnected),
    (.active, .invalid),
    (.stopping, .disconnected),
  ]

  for (initialState, managedTunnel) in cases {
    try withTemporaryRecoveryDirectory { root, anchor in
      try seedRecoveryJournal(at: root, anchor: anchor, state: initialState)
      let receipt = try reconcileRestartedJournal(
        at: root,
        anchor: anchor,
        expectedInitialState: initialState,
        managedTunnel: managedTunnel)
      #expect(receipt.revision == 12)
      #expect(receipt.replayCursor.revision == 11)

      let reopened = try DescriptorRelativeAuthorityJournalStore(
        testingRootPath: root.path, expectedOwnerUID: getuid(),
        anchorStore: anchor)
      let finalRecovery = reopened.recover()
      #expect(finalRecovery.head?.sequence == 3)
      #expect(finalRecovery.committedState?.revision == 12)
      #expect(finalRecovery.committedState?.state == .off)
      #expect(finalRecovery.committedState?.transition == .reconcileOff)
      #expect(finalRecovery.committedState?.operationID == nil)
      #expect(finalRecovery.posture == .recovering(.verifyOff))
    }
  }
}

@Test func recoveryReconciliationRejectsIdentityAndCursorMismatchWithoutCommit() throws {
  try withTemporaryRecoveryDirectory { root, anchor in
    try seedRecoveryJournal(at: root, anchor: anchor, state: .active)
    try withRecoveredCore(at: root, anchor: anchor) { core, cursor, store in
      let exact = try exactRecoveryRequest(cursor: cursor)
      #expect(
        recoveryAuthorityCode {
          try core.reconcileOff(exact, peer: recoveryPeer(role: .provider))
        } == .globalAuthorityIdentityRejected)
      #expect(
        recoveryAuthorityCode {
          try core.reconcileOff(
            exact,
            peer: recoveryPeer(role: .host, euid: 502, consoleUID: 501))
        } == .globalAuthorityIdentityRejected)

      let staleCursor = try ReplayCursor(
        installationID: cursor.installationID,
        acceptedEpoch: cursor.acceptedEpoch,
        acceptedGeneration: cursor.acceptedGeneration,
        revision: cursor.revision - 1,
        previousRecordSHA256: cursor.previousRecordSHA256)
      let staleRequest = try exactRecoveryRequest(cursor: staleCursor)
      #expect(
        recoveryAuthorityCode {
          try core.reconcileOff(staleRequest, peer: recoveryPeer())
        } == .staleOperation)

      let wrongLineage = try ReplayCursor(
        installationID: AuthorityIdentifier(UUID()),
        acceptedEpoch: cursor.acceptedEpoch,
        acceptedGeneration: cursor.acceptedGeneration,
        revision: cursor.revision,
        previousRecordSHA256: cursor.previousRecordSHA256)
      let wrongLineageRequest = try exactRecoveryRequest(cursor: wrongLineage)
      #expect(
        recoveryAuthorityCode {
          try core.reconcileOff(wrongLineageRequest, peer: recoveryPeer())
        } == .replayRejected)

      #expect(core.authorityState == .recovering)
      #expect(core.currentRevision == cursor.revision)
      #expect(store.recover().head?.sequence == 2)
    }
  }
}

@Test func recoveryReconciliationRejectsEveryMissingExternalProof() throws {
  try withTemporaryRecoveryDirectory { root, anchor in
    try seedRecoveryJournal(at: root, anchor: anchor, state: .stopping)
    try withRecoveredCore(at: root, anchor: anchor) { core, cursor, store in
      let incompleteRequests = try [
        exactRecoveryRequest(cursor: cursor, proxyOwnershipCleared: false),
        exactRecoveryRequest(cursor: cursor, proxyListenerClosed: false),
        exactRecoveryRequest(cursor: cursor, systemConfigurationRestored: false),
        exactRecoveryRequest(cursor: cursor, providerOwnershipCleared: false),
        exactRecoveryRequest(cursor: cursor, libboxStopped: false),
        exactRecoveryRequest(cursor: cursor, packetPumpClosed: false),
        exactRecoveryRequest(cursor: cursor, managedTunnel: .connecting),
        exactRecoveryRequest(cursor: cursor, managedTunnel: .connected),
        exactRecoveryRequest(cursor: cursor, managedTunnel: .unknown),
      ]
      for request in incompleteRequests {
        #expect(
          recoveryAuthorityCode {
            try core.reconcileOff(request, peer: recoveryPeer())
          } == .cleanupUnproven)
      }
      #expect(core.authorityState == .recovering)
      #expect(core.currentRevision == cursor.revision)
      #expect(store.recover().head?.sequence == 2)
    }
  }
}

@Test func recoveryReconciliationDoesNotTrustWireForInternalTransientState() throws {
  try withTemporaryRecoveryDirectory { root, anchor in
    try seedRecoveryJournal(at: root, anchor: anchor, state: .off)
    let store = try DescriptorRelativeAuthorityJournalStore(
      testingRootPath: root.path, expectedOwnerUID: getuid(),
      anchorStore: anchor)
    let recovery = store.recover()
    let recovered = try GlobalAuthorityReducer.reconciled(from: recovery)
    let cursor = try #require(recovered.replayCursor)
    let request = try exactRecoveryRequest(cursor: cursor)

    for flags in [(capability: true, secret: false), (capability: false, secret: true)] {
      let reducer = try GlobalAuthorityReducer.recovering(
        revision: cursor.revision,
        replayCursor: cursor,
        retainsCapabilityOrTicket: flags.capability,
        retainsSecretBuffer: flags.secret)
      let core = GlobalAuthorityServiceCore(reducer: reducer, journal: store)
      #expect(
        recoveryAuthorityCode {
          try core.reconcileOff(request, peer: recoveryPeer())
        } == .cleanupUnproven)
      #expect(core.authorityState == .recovering)
    }

    let quarantined = try GlobalAuthorityReducer(
      state: .quarantined,
      revision: cursor.revision,
      replayCursor: cursor)
    let quarantinedCore = GlobalAuthorityServiceCore(
      reducer: quarantined, journal: store)
    #expect(
      recoveryAuthorityCode {
        try quarantinedCore.reconcileOff(request, peer: recoveryPeer())
      } == .quarantined)
    #expect(quarantinedCore.authorityState == .quarantined)
    #expect(store.recover().head?.sequence == 2)
  }
}

@Test func reconcileOffWireSchemaIsCanonicalAndCannotSupplyInternalProof() throws {
  let cursor = try ReplayCursor(
    installationID: AuthorityIdentifier(UUID()),
    acceptedEpoch: 3,
    acceptedGeneration: 5,
    revision: 11,
    previousRecordSHA256: recoveryDigest("journal-head"))
  let request = try exactRecoveryRequest(cursor: cursor)
  let requestID = AuthorityIdentifier(UUID())
  let encoded = try AuthorityV1Codec.encode(
    AuthorityRequestEnvelope(
      requestID: requestID,
      command: .reconcileOff(request)))
  let decoded = try AuthorityV1Codec.decodeRequest(encoded)
  guard case .reconcileOff(let decodedRequest) = decoded.command else {
    Issue.record("reconcile_off decoded as a different command")
    return
  }
  #expect(decoded.requestID == requestID)
  #expect(decodedRequest == request)

  var object = try #require(
    JSONSerialization.jsonObject(with: encoded) as? [String: Any])
  var command = try #require(object["command"] as? [String: Any])
  var payload = try #require(command["payload"] as? [String: Any])
  payload["capability_or_ticket_cleared"] = true
  command["payload"] = payload
  object["command"] = command
  let injected = try JSONSerialization.data(
    withJSONObject: object,
    options: [.sortedKeys, .withoutEscapingSlashes])
  #expect(throws: AuthorityV1ValidationError.self) {
    try AuthorityV1Codec.decodeRequest(injected)
  }

  payload.removeValue(forKey: "provider")
  payload.removeValue(forKey: "capability_or_ticket_cleared")
  command["payload"] = payload
  object["command"] = command
  let missing = try JSONSerialization.data(
    withJSONObject: object,
    options: [.sortedKeys, .withoutEscapingSlashes])
  #expect(throws: AuthorityV1ValidationError.self) {
    try AuthorityV1Codec.decodeRequest(missing)
  }
}
