import Foundation

public struct CredentialGarbageCollectionRequest: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let catalog: [CredentialProfileCatalogEntry]

  public init(
    snapshotDigest: SHA256Digest,
    catalog: [CredentialProfileCatalogEntry]
  ) throws {
    try Self.validateCanonicalCatalog(catalog)
    self.snapshotDigest = snapshotDigest
    self.catalog = catalog
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case catalog
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      snapshotDigest: container.decode(SHA256Digest.self, forKey: .snapshotDigest),
      catalog: container.decode([CredentialProfileCatalogEntry].self, forKey: .catalog)
    )
  }

  static func validateCanonicalCatalog(
    _ catalog: [CredentialProfileCatalogEntry]
  ) throws {
    guard catalog.count <= NativeBridgeProtocolConstants.maximumCredentialCatalogProfiles,
      catalog.sorted(by: catalogEntryPrecedes) == catalog
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var audiences = Set<CredentialAudience>()
    var totalBindings = 0
    for entry in catalog {
      guard audiences.insert(entry.audience).inserted else {
        throw NativeBridgeProtocolError.duplicateCredentialPointer
      }
      let (next, overflow) = totalBindings.addingReportingOverflow(entry.references.count)
      guard !overflow,
        next <= NativeBridgeProtocolConstants.maximumCredentialVaultReferences
      else {
        throw NativeBridgeProtocolError.invalidCredentialSlot
      }
      totalBindings = next
    }
  }

  static func validateCanonicalBindings(
    _ bindings: [CredentialBinding]
  ) throws {
    guard bindings.count <= NativeBridgeProtocolConstants.maximumCredentialVaultReferences,
      bindings.sorted(by: CredentialBinding.canonicalPrecedes) == bindings
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var unique = Set<CredentialBinding>()
    guard bindings.allSatisfy({ unique.insert($0).inserted }) else {
      throw NativeBridgeProtocolError.duplicateCredentialPointer
    }
  }

  public static func catalogEntryPrecedes(
    _ left: CredentialProfileCatalogEntry,
    _ right: CredentialProfileCatalogEntry
  ) -> Bool {
    let leftID = left.audience.profileID.uuidString.lowercased()
    let rightID = right.audience.profileID.uuidString.lowercased()
    if leftID != rightID {
      return leftID < rightID
    }
    return left.audience.profileDigest.hex < right.audience.profileDigest.hex
  }

  public var bindings: [CredentialBinding] {
    catalog.flatMap { entry in
      entry.references.map {
        CredentialBinding(audience: entry.audience, reference: $0)
      }
    }
  }
}

public struct CredentialGarbageCollectionPreview: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let vaultRevision: UUID
  public let orphanBindings: [CredentialBinding]
  public let orphanCount: UInt32

  public init(
    snapshotDigest: SHA256Digest,
    vaultRevision: UUID,
    orphanBindings: [CredentialBinding]
  ) throws {
    try CredentialGarbageCollectionRequest.validateCanonicalBindings(orphanBindings)
    guard let orphanCount = UInt32(exactly: orphanBindings.count) else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.snapshotDigest = snapshotDigest
    self.vaultRevision = vaultRevision
    self.orphanBindings = orphanBindings
    self.orphanCount = orphanCount
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case vaultRevision = "vault_revision"
    case orphanBindings = "orphan_bindings"
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
    let bindings = try container.decode(
      [CredentialBinding].self,
      forKey: .orphanBindings
    )
    try self.init(
      snapshotDigest: container.decode(SHA256Digest.self, forKey: .snapshotDigest),
      vaultRevision: revision,
      orphanBindings: bindings
    )
    guard orphanCount == (try container.decode(UInt32.self, forKey: .orphanCount)) else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(snapshotDigest, forKey: .snapshotDigest)
    try container.encode(vaultRevision.uuidString.lowercased(), forKey: .vaultRevision)
    try container.encode(orphanBindings, forKey: .orphanBindings)
    try container.encode(orphanCount, forKey: .orphanCount)
  }
}

public struct CredentialGarbageCollectionCommitRequest: Codable, Equatable, Sendable {
  public let snapshotDigest: SHA256Digest
  public let catalog: [CredentialProfileCatalogEntry]
  public let expectedVaultRevision: UUID
  public let expectedOrphanBindings: [CredentialBinding]

  public init(
    snapshotDigest: SHA256Digest,
    catalog: [CredentialProfileCatalogEntry],
    expectedVaultRevision: UUID,
    expectedOrphanBindings: [CredentialBinding]
  ) throws {
    try CredentialGarbageCollectionRequest.validateCanonicalCatalog(catalog)
    try CredentialGarbageCollectionRequest.validateCanonicalBindings(expectedOrphanBindings)
    self.snapshotDigest = snapshotDigest
    self.catalog = catalog
    self.expectedVaultRevision = expectedVaultRevision
    self.expectedOrphanBindings = expectedOrphanBindings
  }

  private enum CodingKeys: String, CodingKey {
    case snapshotDigest = "snapshot_digest"
    case catalog
    case expectedVaultRevision = "expected_vault_revision"
    case expectedOrphanBindings = "expected_orphan_bindings"
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
      catalog: container.decode([CredentialProfileCatalogEntry].self, forKey: .catalog),
      expectedVaultRevision: revision,
      expectedOrphanBindings: container.decode(
        [CredentialBinding].self,
        forKey: .expectedOrphanBindings
      )
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(snapshotDigest, forKey: .snapshotDigest)
    try container.encode(catalog, forKey: .catalog)
    try container.encode(
      expectedVaultRevision.uuidString.lowercased(),
      forKey: .expectedVaultRevision
    )
    try container.encode(expectedOrphanBindings, forKey: .expectedOrphanBindings)
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
