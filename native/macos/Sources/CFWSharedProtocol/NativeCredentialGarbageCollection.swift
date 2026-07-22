import Foundation

public struct CredentialGarbageCollectionRequest: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let liveReferences: [CredentialReference]

  public init(snapshotDigest: SHA256Digest, liveReferences: [CredentialReference]) throws {
    try Self.validateCanonicalReferences(liveReferences)
    self.snapshotDigest = snapshotDigest
    self.liveReferences = liveReferences
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case liveReferences = "live_references"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      snapshotDigest: container.decode(SHA256Digest.self, forKey: .snapshotDigest),
      liveReferences: container.decode([CredentialReference].self, forKey: .liveReferences)
    )
  }

  static func validateCanonicalReferences(
    _ references: [CredentialReference]
  ) throws {
    guard references.count <= NativeBridgeProtocolConstants.maximumCredentialVaultReferences
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    let sorted = references.sorted(by: Self.referencePrecedes)
    guard sorted == references else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var identifiers = Set<UUID>()
    guard references.allSatisfy({ identifiers.insert($0.id).inserted }) else {
      throw NativeBridgeProtocolError.duplicateCredentialPointer
    }
  }

  static func referencePrecedes(
    _ left: CredentialReference,
    _ right: CredentialReference
  ) -> Bool {
    let leftID = left.id.uuidString.lowercased()
    let rightID = right.id.uuidString.lowercased()
    if leftID != rightID {
      return leftID < rightID
    }
    return left.kind.rawValue < right.kind.rawValue
  }
}

public struct CredentialGarbageCollectionPreview: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let vaultRevision: UUID
  public let orphanReferences: [CredentialReference]
  public let orphanCount: UInt32

  public init(
    snapshotDigest: SHA256Digest,
    vaultRevision: UUID,
    orphanReferences: [CredentialReference]
  ) throws {
    try CredentialGarbageCollectionRequest.validateCanonicalReferences(orphanReferences)
    guard let orphanCount = UInt32(exactly: orphanReferences.count) else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.snapshotDigest = snapshotDigest
    self.vaultRevision = vaultRevision
    self.orphanReferences = orphanReferences
    self.orphanCount = orphanCount
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case vaultRevision = "vault_revision"
    case orphanReferences = "orphan_references"
    case orphanCount = "orphan_count"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let revisionText = try container.decode(String.self, forKey: .vaultRevision)
    guard revisionText == revisionText.lowercased(),
      let revision = UUID(uuidString: revisionText),
      revision.uuidString.lowercased() == revisionText
    else {
      throw NativeBridgeProtocolError.invalidContext
    }
    let references = try container.decode(
      [CredentialReference].self,
      forKey: .orphanReferences
    )
    try self.init(
      snapshotDigest: container.decode(SHA256Digest.self, forKey: .snapshotDigest),
      vaultRevision: revision,
      orphanReferences: references
    )
    guard orphanCount == (try container.decode(UInt32.self, forKey: .orphanCount)) else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(snapshotDigest, forKey: .snapshotDigest)
    try container.encode(vaultRevision.uuidString.lowercased(), forKey: .vaultRevision)
    try container.encode(orphanReferences, forKey: .orphanReferences)
    try container.encode(orphanCount, forKey: .orphanCount)
  }
}

public struct CredentialGarbageCollectionCommitRequest: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let liveReferences: [CredentialReference]
  public let expectedVaultRevision: UUID
  public let expectedOrphanReferences: [CredentialReference]

  public init(
    snapshotDigest: SHA256Digest,
    liveReferences: [CredentialReference],
    expectedVaultRevision: UUID,
    expectedOrphanReferences: [CredentialReference]
  ) throws {
    try CredentialGarbageCollectionRequest.validateCanonicalReferences(liveReferences)
    try CredentialGarbageCollectionRequest.validateCanonicalReferences(expectedOrphanReferences)
    self.snapshotDigest = snapshotDigest
    self.liveReferences = liveReferences
    self.expectedVaultRevision = expectedVaultRevision
    self.expectedOrphanReferences = expectedOrphanReferences
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case liveReferences = "live_references"
    case expectedVaultRevision = "expected_vault_revision"
    case expectedOrphanReferences = "expected_orphan_references"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let revisionText = try container.decode(String.self, forKey: .expectedVaultRevision)
    guard revisionText == revisionText.lowercased(),
      let revision = UUID(uuidString: revisionText),
      revision.uuidString.lowercased() == revisionText
    else {
      throw NativeBridgeProtocolError.invalidContext
    }
    try self.init(
      snapshotDigest: container.decode(SHA256Digest.self, forKey: .snapshotDigest),
      liveReferences: container.decode([CredentialReference].self, forKey: .liveReferences),
      expectedVaultRevision: revision,
      expectedOrphanReferences: container.decode(
        [CredentialReference].self,
        forKey: .expectedOrphanReferences
      )
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(snapshotDigest, forKey: .snapshotDigest)
    try container.encode(liveReferences, forKey: .liveReferences)
    try container.encode(
      expectedVaultRevision.uuidString.lowercased(),
      forKey: .expectedVaultRevision
    )
    try container.encode(expectedOrphanReferences, forKey: .expectedOrphanReferences)
  }
}

public struct CredentialGarbageCollectionReceipt: Codable, Equatable, Sendable {
  public let vaultRevision: UUID
  public let deletedCount: UInt32

  public init(vaultRevision: UUID, deletedCount: UInt32) {
    self.vaultRevision = vaultRevision
    self.deletedCount = deletedCount
  }

  private enum CodingKeys: String, CodingKey {
    case vaultRevision = "vault_revision"
    case deletedCount = "deleted_count"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let revisionText = try container.decode(String.self, forKey: .vaultRevision)
    guard revisionText == revisionText.lowercased(),
      let revision = UUID(uuidString: revisionText),
      revision.uuidString.lowercased() == revisionText
    else {
      throw NativeBridgeProtocolError.invalidContext
    }
    self.init(
      vaultRevision: revision,
      deletedCount: try container.decode(UInt32.self, forKey: .deletedCount)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(vaultRevision.uuidString.lowercased(), forKey: .vaultRevision)
    try container.encode(deletedCount, forKey: .deletedCount)
  }
}
