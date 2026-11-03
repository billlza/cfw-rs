import CFWAppleNetwork
import CFWCredentialTransport
import CryptoKit
import Foundation
import Testing

@testable import CFWCredentialVault
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// Credential garbage collection protects the active and managed tunnel
// credential references.
private final class RecordingGarbageCollectionVault:
  NativeCredentialVaulting, @unchecked Sendable
{
  private let lock = NSLock()
  private var previewReferences: [CredentialReference] = []

  func provision(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CFWCredentialVault.CredentialVaultReceipt {
    _ = requiredReferences
    _ = material
    return CFWCredentialVault.CredentialVaultReceipt(audience: audience)
  }

  func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CFWCredentialVault.CredentialPresence] {
    references.map { CFWCredentialVault.CredentialPresence(reference: $0, present: true) }
  }

  func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
    _ = slots
    return .empty
  }

  func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    lock.withLock { previewReferences = request.catalog.flatMap(\.references) }
    return try CredentialGarbageCollectionPreview(
      snapshotDigest: request.snapshotDigest,
      vaultRevision: #require(
        UUID(uuidString: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
      ),
      orphanBindings: []
    )
  }

  func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    _ = request
    throw CredentialVaultError.garbageCollectionConfirmationExpired
  }

  func capturedReferences() -> [CredentialReference] {
    lock.withLock { previewReferences }
  }
}

@Test func garbageCollectionProtectsActiveAndManagedTunnelCredentialReferences() async throws {
  let activeReference = CredentialReference(
    id: try #require(UUID(uuidString: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")),
    kind: .trojanPassword
  )
  let pendingReference = CredentialReference(
    id: try #require(UUID(uuidString: "cccccccc-cccc-4ccc-8ccc-cccccccccccc")),
    kind: .shadowsocksPassword
  )
  let activeDescriptor = try preflightDescriptor(slot: .systemProxy, reference: activeReference)
  let pendingDescriptor = try preflightDescriptor(slot: .tunnel, reference: pendingReference)
  let proxy = RecordingProxyAgent(
    observedSnapshot: .proxyActive(configuration: activeDescriptor, sequence: 1)
  )
  let tunnel = RecordingTunnelHost(
    managedConfiguration: pendingDescriptor
  )
  let vault = RecordingGarbageCollectionVault()
  let coordinator = makePreflightCoordinator(
    proxy: proxy,
    tunnel: tunnel,
    credentialVault: vault
  )
  let request = try CredentialGarbageCollectionRequest(
    snapshotDigest: CFWSharedProtocol.SHA256Digest(hex: String(repeating: "ab", count: 32)),
    catalog: []
  )

  _ = try await coordinator.execute(.previewCredentialGarbageCollection(request))
  #expect(vault.capturedReferences() == [activeReference, pendingReference])
}
