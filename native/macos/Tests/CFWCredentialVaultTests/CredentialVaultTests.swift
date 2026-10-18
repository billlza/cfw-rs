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

private func audience(
  profileID: String = profileID,
  digest: String = String(repeating: "11", count: 32)
) throws -> CredentialAudience {
  CredentialAudience(
    profileID: UUID(uuidString: profileID)!,
    profileDigest: try SHA256Digest(hex: digest)
  )
}

private func catalog(
  _ references: [CredentialReference],
  audience: CredentialAudience? = nil
) throws -> [CredentialProfileCatalogEntry] {
  [
    try CredentialProfileCatalogEntry(
      audience: audience ?? (try selfAudience()),
      references: references
    )
  ]
}

private func selfAudience() throws -> CredentialAudience {
  try audience()
}

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
    audience: try audience(),
    requiredReferences: [first],
    material: initial
  )

  var missingOnly = try material([(second, "second-secret")])
  defer { missingOnly.erase() }
  _ = try vault.provision(
    audience: try audience(),
    requiredReferences: [first, second],
    material: missingOnly
  )

  #expect(
    try vault.presence(audience: audience(), of: [first, second])
      == [
        CredentialPresence(reference: first, present: true),
        CredentialPresence(reference: second, present: true),
      ]
  )
}

@Test func modernProtocolReferencesProvisionAndResolveWithoutKindConflation() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let anytls = reference(firstID, kind: .anytlsPassword)
  let tuicUUID = reference(secondID, kind: .tuicUUID)
  let tuicPassword = reference(thirdID, kind: .tuicPassword)
  let references = [anytls, tuicUUID, tuicPassword]
  var supplied = try material([
    (anytls, "anytls-secret"),
    (tuicUUID, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"),
    (tuicPassword, "tuic-secret"),
  ])
  defer { supplied.erase() }

  _ = try vault.provision(
    audience: try audience(),
    requiredReferences: references,
    material: supplied
  )
  #expect(try vault.presence(audience: audience(), of: references).allSatisfy(\.present))

  var resolved = try vault.resolve(
    audience: audience(),
    slots: [
      try CredentialSlot(
        reference: anytls,
        target: .anytlsPassword,
        outboundIndex: 0,
        jsonPointer: "/outbounds/0/password"
      ),
      try CredentialSlot(
        reference: tuicUUID,
        target: .tuicUUID,
        outboundIndex: 1,
        jsonPointer: "/outbounds/1/uuid"
      ),
      try CredentialSlot(
        reference: tuicPassword,
        target: .tuicPassword,
        outboundIndex: 1,
        jsonPointer: "/outbounds/1/password"
      ),
    ]
  )
  defer { resolved.erase() }
  #expect(resolved.entries.map(\.reference) == references)
  #expect(resolved.entries[0].withSecretBytes { $0 == Data("anytls-secret".utf8) })
  #expect(
    resolved.entries[1].withSecretBytes {
      $0 == Data("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee".utf8)
    }
  )
  #expect(resolved.entries[2].withSecretBytes { $0 == Data("tuic-secret".utf8) })

  let beforeMismatch = store.snapshot()
  let wrongKind = reference(firstID, kind: .tuicPassword)
  var mismatched = try material([(wrongKind, "wrong-kind")])
  defer { mismatched.erase() }
  #expect(throws: CredentialVaultError.kindMismatch(firstID)) {
    try vault.provision(
      audience: audience(),
      requiredReferences: [anytls],
      material: mismatched
    )
  }
  #expect(store.snapshot() == beforeMismatch)
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
      audience: try audience(),
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
    audience: try audience(),
    requiredReferences: [first],
    material: original
  )
  let before = store.snapshot()

  var changed = try material([(first, "changed-secret")])
  defer { changed.erase() }
  #expect(throws: CredentialVaultError.immutableConflict(firstID)) {
    try vault.provision(
      audience: try audience(),
      requiredReferences: [first],
      material: changed
    )
  }
  #expect(store.snapshot() == before)
}

@Test func credentialUUIDIsImmutableAcrossProfileAudiences() throws {
  let store = InMemoryVaultStore()
  let vault = CredentialVault(testingStore: store)
  let first = reference(firstID)
  let originalAudience = try audience(digest: String(repeating: "11", count: 32))
  let replacementAudience = try audience(digest: String(repeating: "22", count: 32))
  let rejectedAudience = try audience(digest: String(repeating: "33", count: 32))

  var original = try material([(first, "stable-secret")])
  defer { original.erase() }
  _ = try vault.provision(
    audience: originalAudience,
    requiredReferences: [first],
    material: original
  )

  var unchanged = try material([(first, "stable-secret")])
  defer { unchanged.erase() }
  _ = try vault.provision(
    audience: replacementAudience,
    requiredReferences: [first],
    material: unchanged
  )
  #expect(try vault.presence(audience: originalAudience, of: [first]).allSatisfy(\.present))
  #expect(try vault.presence(audience: replacementAudience, of: [first]).allSatisfy(\.present))
  let beforeConflict = store.snapshot()

  var changed = try material([(first, "changed-secret")])
  defer { changed.erase() }
  #expect(throws: CredentialVaultError.immutableConflict(firstID)) {
    try vault.provision(
      audience: rejectedAudience,
      requiredReferences: [first],
      material: changed
    )
  }
  #expect(store.snapshot() == beforeConflict)
  #expect(try vault.presence(audience: rejectedAudience, of: [first]).allSatisfy { !$0.present })
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
          audience: try audience(),
          requiredReferences: [reference],
          material: value
        )
      }
    }
    try await group.waitForAll()
  }
  let vault = CredentialVault(testingStore: store)
  #expect(try vault.presence(audience: audience(), of: [first, second]).allSatisfy(\.present))
}

@Test func timingSafeComparisonRetainsLengthDifferencesAboveOneByte() {
  #expect(
    !CredentialVault.timingSafeEqual(
      Data(repeating: 0, count: 1),
      Data(repeating: 0, count: 257)
    )
  )
}

@Test func persistedInvalidSecretIsCorruptNotPresent() throws {
  struct Entry: Codable {
    let audience: CredentialAudience
    let reference: CredentialReference
    let secret: Data
  }
  struct Document: Codable {
    let schemaVersion: UInt16
    let revision: UUID
    let entries: [Entry]
  }
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  for (kind, secret) in [
    (CredentialKind.shadowsocksPassword, Data([0])),
    (CredentialKind.tuicUUID, Data("not-a-canonical-uuid".utf8)),
  ] {
    let revision = UUID()
    let storedReference = reference(firstID, kind: kind)
    let data = try encoder.encode(
      Document(
        schemaVersion: CredentialVaultConstants.schemaVersion,
        revision: revision,
        entries: [
          Entry(
            audience: try audience(),
            reference: storedReference,
            secret: secret
          )
        ]
      )
    )
    let store = InMemoryVaultStore(
      blob: StoredCredentialVaultBlob(data: data, revision: revision)
    )
    let vault = CredentialVault(testingStore: store)
    #expect(throws: CredentialVaultError.corrupt) {
      try vault.presence(audience: audience(), of: [storedReference])
    }
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
    audience: try audience(),
    requiredReferences: [shared, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "ab", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(
      snapshotDigest: digest,
      catalog: try catalog([shared])
    )
  )
  #expect(
    preview.orphanBindings
      == [CredentialBinding(audience: try audience(), reference: orphan)]
  )
  #expect(preview.orphanCount == 1)

  let receipt = try vault.commitGarbageCollection(
    CredentialGarbageCollectionCommitRequest(
      snapshotDigest: digest,
      catalog: try catalog([shared]),
      expectedVaultRevision: preview.vaultRevision,
      expectedOrphanBindings: preview.orphanBindings
    )
  )
  #expect(receipt.deletedCount == 1)
  #expect(receipt.vaultRevision != preview.vaultRevision)
  #expect(
    try vault.presence(audience: audience(), of: [shared, orphan])
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
    audience: try audience(),
    requiredReferences: [live, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "cd", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(snapshotDigest: digest, catalog: try catalog([live]))
  )

  var added = try material([(concurrent, "concurrent-secret")])
  defer { added.erase() }
  _ = try vault.provision(
    audience: try audience(),
    requiredReferences: [concurrent],
    material: added
  )
  let beforeCommit = store.snapshot()
  #expect(throws: CredentialVaultError.garbageCollectionConfirmationExpired) {
    try vault.commitGarbageCollection(
      CredentialGarbageCollectionCommitRequest(
        snapshotDigest: digest,
        catalog: try catalog([live]),
        expectedVaultRevision: preview.vaultRevision,
        expectedOrphanBindings: preview.orphanBindings
      )
    )
  }
  #expect(store.snapshot() == beforeCommit)
  #expect(
    try vault.presence(audience: audience(), of: [orphan, concurrent])
      .allSatisfy { $0.present }
  )
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
    audience: try audience(),
    requiredReferences: [live, orphan],
    material: initial
  )
  let digest = try SHA256Digest(hex: String(repeating: "ef", count: 32))
  let preview = try vault.previewGarbageCollection(
    CredentialGarbageCollectionRequest(snapshotDigest: digest, catalog: try catalog([live]))
  )
  let beforeCommit = store.snapshot()
  #expect(throws: CredentialVaultError.garbageCollectionConfirmationExpired) {
    try vault.commitGarbageCollection(
      CredentialGarbageCollectionCommitRequest(
        snapshotDigest: digest,
        catalog: try catalog([live]),
        expectedVaultRevision: preview.vaultRevision,
        expectedOrphanBindings: []
      )
    )
  }
  #expect(store.snapshot() == beforeCommit)
  #expect(throws: CredentialVaultError.missingCredential(thirdID)) {
    try vault.previewGarbageCollection(
      CredentialGarbageCollectionRequest(
        snapshotDigest: digest,
        catalog: try catalog([live, missing])
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
      CredentialGarbageCollectionRequest(snapshotDigest: digest, catalog: [])
    )
  }
}
