import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWCredentialVault

private final class InMemoryVaultStore: CredentialVaultBlobStoring, @unchecked Sendable {
  private let lock = NSLock()
  private var blob: StoredCredentialVaultBlob?

  init(blob: StoredCredentialVaultBlob? = nil) {
    self.blob = blob
  }

  func load() throws -> StoredCredentialVaultBlob? {
    lock.withLock { blob }
  }

  func compareAndSwap(
    expectedRevision: UUID?,
    newRevision: UUID,
    data: Data
  ) throws {
    try lock.withLock {
      guard blob?.revision == expectedRevision else {
        throw CredentialVaultError.compareAndSwapConflict
      }
      blob = StoredCredentialVaultBlob(data: data, revision: newRevision)
    }
  }

  func snapshot() -> StoredCredentialVaultBlob? {
    lock.withLock { blob }
  }
}

private let profileID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
private let firstID = UUID(uuidString: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")!
private let secondID = UUID(uuidString: "cccccccc-cccc-4ccc-8ccc-cccccccccccc")!
private let thirdID = UUID(uuidString: "dddddddd-dddd-4ddd-8ddd-dddddddddddd")!

private func reference(
  _ id: UUID,
  kind: CredentialKind = .shadowsocksPassword
) -> CredentialReference {
  CredentialReference(id: id, kind: kind)
}

private func material(
  _ values: [(CredentialReference, String)]
) throws -> CredentialMaterial {
  try CredentialMaterial(
    entries: values.map {
      try CredentialMaterialEntry(reference: $0.0, secret: Data($0.1.utf8))
    }
  )
}

@Test func vaultRejectsInvalidAccessGroup() {
  #expect(throws: CredentialVaultError.invalidAccessGroup) {
    try CredentialVault(accessGroup: "invalid")
  }
}

@Test func existingAndMissingReferencesCommitAsOneBatch() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let first = reference(firstID)
  let second = reference(secondID, kind: .trojanPassword)
  var initial = try material([(first, "first-secret")])
  defer { initial.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [first],
    material: initial
  )

  var missingOnly = try material([(second, "second-secret")])
  defer { missingOnly.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [first, second],
    material: missingOnly
  )

  #expect(
    try vault.presence(of: [first, second])
      == [
        CredentialPresence(reference: first, present: true),
        CredentialPresence(reference: second, present: true),
      ]
  )
}

@Test func missingRequiredReferenceRollsBackWholeBatch() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let first = reference(firstID)
  let second = reference(secondID)
  var supplied = try material([(first, "first-secret")])
  defer { supplied.erase() }

  #expect(throws: CredentialVaultError.missingCredential(secondID)) {
    try vault.provision(
      profileID: profileID,
      requiredReferences: [first, second],
      material: supplied
    )
  }
  #expect(store.snapshot() == nil)
}

@Test func immutableConflictDoesNotChangeTheVault() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let first = reference(firstID)
  var original = try material([(first, "original-secret")])
  defer { original.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [first],
    material: original
  )
  let before = store.snapshot()

  var changed = try material([(first, "changed-secret")])
  defer { changed.erase() }
  #expect(throws: CredentialVaultError.immutableConflict(firstID)) {
    try vault.provision(
      profileID: profileID,
      requiredReferences: [first],
      material: changed
    )
  }
  #expect(store.snapshot() == before)
}

@Test func concurrentProvisionRetriesCASWithoutLosingEitherEntry() async throws {
  let store = InMemoryVaultStore()
  let first = reference(firstID)
  let second = reference(secondID, kind: .trojanPassword)
  try await withThrowingTaskGroup(of: Void.self) { group in
    for (reference, secret) in [(first, "first-secret"), (second, "second-secret")] {
      group.addTask {
        let vault = CredentialVault(testingStore: store)
        var value = try material([(reference, secret)])
        defer { value.erase() }
        _ = try vault.provision(
          profileID: profileID,
          requiredReferences: [reference],
          material: value
        )
      }
    }
    try await group.waitForAll()
  }
  let vault = CredentialVault(testingStore: store)
  #expect(try vault.presence(of: [first, second]).allSatisfy(\.present))
}

@Test func timingSafeComparisonRetainsLengthDifferencesAboveOneByte() {
  #expect(
    !CredentialVault.timingSafeEqual(
      Data(repeating: 0, count: 1),
      Data(repeating: 0, count: 257)
    )
  )
}

@Test func persistedControlCharacterSecretIsCorruptNotPresent() throws {
  struct Entry: Codable {
    let reference: CredentialReference
    let secret: Data
  }
  struct Document: Codable {
    let schemaVersion: UInt16
    let revision: UUID
    let entries: [Entry]
  }
  let revision = UUID()
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let data = try encoder.encode(
    Document(
      schemaVersion: CredentialVaultConstants.schemaVersion,
      revision: revision,
      entries: [Entry(reference: reference(firstID), secret: Data([0]))]
    )
  )
  let store = InMemoryVaultStore(
    blob: StoredCredentialVaultBlob(data: data, revision: revision)
  )
  let vault = CredentialVault(testingStore: store)
  #expect(throws: CredentialVaultError.corrupt) {
    try vault.presence(of: [reference(firstID)])
  }
}

@Test func garbageCollectionPreservesLiveSharedReferenceAndDeletesExactOrphan() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let shared = reference(firstID)
  let orphan = reference(secondID, kind: .trojanPassword)
  var initial = try material([(shared, "shared-secret"), (orphan, "orphan-secret")])
  defer { initial.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [shared, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(
      snapshotDigest: digest,
      liveReferences: [shared]
    )
  )
  #expect(preview.orphanReferences == [orphan])
  #expect(preview.orphanCount == 1)

  let receipt = try vault.commitGarbageCollection(
    CredentialGarbageCollectionCommitRequest(
      snapshotDigest: digest,
      liveReferences: [shared],
      expectedVaultRevision: preview.vaultRevision,
      expectedOrphanReferences: preview.orphanReferences
    )
  )
  #expect(receipt.deletedCount == 1)
  #expect(receipt.vaultRevision != preview.vaultRevision)
  #expect(
    try vault.presence(of: [shared, orphan])
      == [
        CredentialPresence(reference: shared, present: true),
        CredentialPresence(reference: orphan, present: false),
      ]
  )
}

@Test func concurrentProvisionExpiresGarbageCollectionWithoutDeletion() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let live = reference(firstID)
  let orphan = reference(secondID)
  let concurrent = reference(thirdID, kind: .trojanPassword)
  var initial = try material([(live, "live-secret"), (orphan, "orphan-secret")])
  defer { initial.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [live, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "cd", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(snapshotDigest: digest, liveReferences: [live])
  )

  var added = try material([(concurrent, "concurrent-secret")])
  defer { added.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [concurrent],
    material: added
  )
  let beforeCommit = store.snapshot()
  #expect(throws: CredentialVaultError.garbageCollectionConfirmationExpired) {
    try vault.commitGarbageCollection(
      CredentialGarbageCollectionCommitRequest(
        snapshotDigest: digest,
        liveReferences: [live],
        expectedVaultRevision: preview.vaultRevision,
        expectedOrphanReferences: preview.orphanReferences
      )
    )
  }
  #expect(store.snapshot() == beforeCommit)
  #expect(try vault.presence(of: [orphan, concurrent]).allSatisfy { $0.present })
}

@Test func changedOrphanConfirmationAndMissingLiveReferenceDeleteNothing() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let live = reference(firstID)
  let orphan = reference(secondID)
  let missing = reference(thirdID)
  var initial = try material([(live, "live-secret"), (orphan, "orphan-secret")])
  defer { initial.erase() }
  _ = try vault.provision(
    profileID: profileID,
    requiredReferences: [live, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "ef", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(snapshotDigest: digest, liveReferences: [live])
  )
  let beforeCommit = store.snapshot()
  #expect(throws: CredentialVaultError.garbageCollectionConfirmationExpired) {
    try vault.commitGarbageCollection(
      CredentialGarbageCollectionCommitRequest(
        snapshotDigest: digest,
        liveReferences: [live],
        expectedVaultRevision: preview.vaultRevision,
        expectedOrphanReferences: []
      )
    )
  }
  #expect(store.snapshot() == beforeCommit)
  #expect(throws: CredentialVaultError.missingCredential(thirdID)) {
    try vault.previewGarbageCollection(
      CredentialGarbageCollectionRequest(
        snapshotDigest: digest,
        liveReferences: [live, missing]
      )
    )
  }
  #expect(store.snapshot() == beforeCommit)
}

@Test func missingVaultCannotProduceDeletionPreview() throws {
  let vault = CredentialVault(testingStore: InMemoryVaultStore())
  let digest = try SHA256Digest(hex: String(repeating: "01", count: 32))
  #expect(throws: CredentialVaultError.missingVault) {
    try vault.previewGarbageCollection(
      CredentialGarbageCollectionRequest(snapshotDigest: digest, liveReferences: [])
    )
  }
}
