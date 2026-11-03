import CFWAppleNetwork
import CFWCredentialTransport
import CryptoKit
import Foundation
import Testing

@testable import CFWCredentialVault
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// An edited profile's rebind keeps both native credential audiences, and an
// offline profile probe takes no network ownership and starts no mode.
private struct ForbiddenProfileProbeOperationLease: NativeHostOperationLeaseAcquiring {
  func acquire() throws -> any NativeHostOperationLeaseHolding {
    throw UnusedSystemProxyStartPreparerError.unexpectedInvocation
  }
}

private final class RebindTestStore: CredentialVaultBlobStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: StoredCredentialVaultBlob?
  func load() throws -> StoredCredentialVaultBlob? { lock.withLock { blob } }
  func compareAndSwap(expectedRevision: UUID?, newRevision: UUID, data: Data) throws {
    try lock.withLock {
      guard blob?.revision == expectedRevision else {
        throw CredentialVaultError.compareAndSwapConflict
      }
      blob = StoredCredentialVaultBlob(data: data, revision: newRevision)
    }
  }
}

@Test func editedProfileRebindRetainsBothExactNativeCredentialAudiences() async throws {
  let previous = try preflightRequest().systemProxyRequest.credentialAudience
  let next = CredentialAudience(
    profileID: previous.profileID,
    profileDigest: try SHA256Digest(hex: String(repeating: "cd", count: 32)))
  let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let slot = try CredentialSlot(
    reference: reference, target: .trojanPassword, outboundIndex: 0,
    jsonPointer: "/outbounds/0/password")
  var material = try CredentialMaterial(entries: [
    CredentialMaterialEntry(reference: reference, secret: Data("isolated-rebind-secret".utf8))
  ])
  defer { material.erase() }
  let vault = CredentialVault(testingStore: RebindTestStore())
  _ = try vault.provision(audience: previous, requiredReferences: [reference], material: material)
  #expect(try vault.presence(audience: next, of: [reference]).allSatisfy { !$0.present })
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = makePreflightCoordinator(proxy: proxy, tunnel: tunnel, credentialVault: vault)
  let request = try CredentialRebindRequest(
    previousAudience: previous, audience: next, slots: [slot])
  let wire = try JSONEncoder().encode(
    NativeRequestEnvelope(command: .rebindProfileCredentials(request)))
  #expect(!String(decoding: wire, as: UTF8.self).contains("isolated-rebind-secret"))
  let decoded = try NativeBridgeProtocolCodec.decodeRequest(wire)
  for _ in 0..<2 {
    guard case .credentialReceipt(let receipt) = try await coordinator.execute(decoded.command)
    else {
      Issue.record("credential rebind did not return a receipt")
      return
    }
    #expect(receipt.profileDigest == next.profileDigest)
  }
  for audience in [previous, next] {
    var resolved = try vault.resolve(audience: audience, slots: [slot])
    defer { resolved.erase() }
    #expect(resolved.entries.count == 1)
    #expect(try vault.presence(audience: audience, of: [reference]).allSatisfy(\.present))
  }
  // Provider refresh combines unchanged, rebound local nodes with credentials
  // for new downloaded nodes in the same candidate audience.
  let addedReference = CredentialReference(id: UUID(), kind: .trojanPassword)
  let required = [reference, addedReference].sorted { $0.id.uuidString < $1.id.uuidString }
  let provision = try CredentialProvisionRequest(
    audience: next, requiredReferences: required,
    entries: [CredentialProvisionEntry(reference: addedReference, secret: "new-provider-secret")])
  guard case .credentialReceipt = try await coordinator.execute(.provisionCredentials(provision))
  else {
    Issue.record("partial provider provisioning did not return a receipt")
    return
  }
  #expect(try vault.presence(audience: next, of: required).allSatisfy(\.present))
  #expect(try vault.presence(audience: previous, of: [reference]).allSatisfy(\.present))
  #expect(try vault.presence(audience: previous, of: [addedReference]).allSatisfy { !$0.present })
  let wrong = CredentialAudience(
    profileID: previous.profileID,
    profileDigest: try SHA256Digest(hex: String(repeating: "ef", count: 32)))
  await #expect(throws: (any Error).self) {
    try await coordinator.execute(
      .rebindProfileCredentials(
        CredentialRebindRequest(previousAudience: wrong, audience: next, slots: [slot])))
  }
  #expect(throws: (any Error).self) {
    try CredentialRebindRequest(
      previousAudience: previous,
      audience: CredentialAudience(profileID: UUID(), profileDigest: next.profileDigest),
      slots: [slot])
  }
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}

@Test func offlineProfileProbeDoesNotAcquireNetworkOwnershipOrStartEitherMode() async throws {
  let proxy = RecordingProxyAgent()
  let tunnel = RecordingTunnelHost()
  let coordinator = NativeBridgeCoordinator(
    proxy: proxy, systemProxyPreparer: UnusedSystemProxyStartPreparer(), tunnel: tunnel,
    engineLease: AvailableEngineLease(), credentialVault: EmptyCredentialVault(),
    hostOperationLease: ForbiddenProfileProbeOperationLease(),
    serviceBuildObserver: FixedCurrentServiceBuildObserver())
  let request = try ProfileDelayTestRequest(
    audience: preflightRequest().systemProxyRequest.credentialAudience,
    configJSON: #"{"outbounds":[{"type":"direct","tag":"node"}]}"#,
    credentialSlots: [], proxies: ["node"], timeoutMS: 5000)
  let envelope = NativeRequestEnvelope(requestID: UUID(), command: .testProfileDelays(request))
  let decoded = try NativeBridgeProtocolCodec.decodeRequest(JSONEncoder().encode(envelope))
  let result = try await coordinator.execute(decoded.command)
  #expect(
    result == .profileDelays([try ProfileProxyDelay(name: "node", delay: 42, errorKind: nil)]))
  #expect(await proxy.mutationCounts() == (0, 0))
  #expect(await proxy.validationCount() == 0)
  #expect(await tunnel.mutationCounts() == (install: 0, cancel: 0, start: 0, stop: 0))
}
