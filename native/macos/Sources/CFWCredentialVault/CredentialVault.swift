import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

public struct CredentialVault: Sendable {
  private static let maximumCASAttempts = 8
  private let store: any CredentialVaultBlobStoring

  public init(accessGroup: String) throws {
    store = try DataProtectionKeychainCredentialVaultStore(accessGroup: accessGroup)
  }

  init(testingStore: any CredentialVaultBlobStoring) {
    store = testingStore
  }

  public func provision(
    profileID: String,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt {
    guard profileID == profileID.lowercased(),
      let profileUUID = UUID(uuidString: profileID),
      profileUUID.uuidString.lowercased() == profileID
    else {
      throw CredentialVaultError.invalidProfileIdentifier
    }
    guard requiredReferences.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw CredentialVaultError.capacityExceeded
    }
    var requiredByID: [UUID: CredentialReference] = [:]
    for reference in requiredReferences {
      guard requiredByID.updateValue(reference, forKey: reference.id) == nil else {
        throw CredentialVaultError.duplicateReference(reference.id)
      }
    }
    for supplied in material.entries {
      guard let required = requiredByID[supplied.reference.id] else {
        throw CredentialVaultError.unexpectedCredential(supplied.reference.id)
      }
      guard required.kind == supplied.reference.kind else {
        throw CredentialVaultError.kindMismatch(supplied.reference.id)
      }
    }
    for _ in 0..<Self.maximumCASAttempts {
      var stored = try store.load()
      defer { stored?.erase() }
      var document = try decode(stored)
      defer { erase(&document) }
      var byID = Dictionary(uniqueKeysWithValues: document.entries.map { ($0.reference.id, $0) })
      let suppliedIDs = Set(material.entries.map(\.reference.id))
      for required in requiredReferences {
        if let existing = byID[required.id] {
          guard existing.reference.kind == required.kind else {
            throw CredentialVaultError.kindMismatch(required.id)
          }
        } else if !suppliedIDs.contains(required.id) {
          throw CredentialVaultError.missingCredential(required.id)
        }
      }
      for requested in material.entries {
        if let existing = byID[requested.reference.id] {
          let requestedSecret = requested.withSecretBytes { $0 }
          guard existing.reference.kind == requested.reference.kind,
            Self.timingSafeEqual(existing.secret, requestedSecret)
          else {
            throw CredentialVaultError.immutableConflict(requested.reference.id)
          }
        } else {
          let requestedSecret = requested.withSecretBytes { $0 }
          byID[requested.reference.id] = CredentialVaultEntry(
            reference: requested.reference,
            secret: requestedSecret
          )
        }
      }
      guard byID.count <= CredentialVaultConstants.maximumEntries else {
        throw CredentialVaultError.capacityExceeded
      }
      let newRevision = UUID()
      document = CredentialVaultDocument(
        schemaVersion: CredentialVaultConstants.schemaVersion,
        revision: newRevision,
        entries: byID.values.sorted {
          $0.reference.id.uuidString < $1.reference.id.uuidString
        }
      )
      var encoded = try encode(document)
      defer {
        encoded.resetBytes(in: encoded.startIndex..<encoded.endIndex)
        encoded.removeAll(keepingCapacity: false)
      }
      do {
        try store.compareAndSwap(
          expectedRevision: stored?.revision,
          newRevision: newRevision,
          data: encoded
        )
        return CredentialVaultReceipt(profileID: profileUUID)
      } catch CredentialVaultError.compareAndSwapConflict {
        continue
      }
    }
    throw CredentialVaultError.compareAndSwapConflict
  }

  public func presence(of references: [CredentialReference]) throws -> [CredentialPresence] {
    guard references.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw CredentialVaultError.capacityExceeded
    }
    var seen = Set<UUID>()
    for reference in references where !seen.insert(reference.id).inserted {
      throw CredentialVaultError.duplicateReference(reference.id)
    }
    var stored = try store.load()
    defer { stored?.erase() }
    var document = try decode(stored)
    defer { erase(&document) }
    let byID = Dictionary(uniqueKeysWithValues: document.entries.map { ($0.reference.id, $0) })
    return try references.map { reference in
      guard let existing = byID[reference.id] else {
        return CredentialPresence(reference: reference, present: false)
      }
      guard existing.reference.kind == reference.kind else {
        throw CredentialVaultError.kindMismatch(reference.id)
      }
      return CredentialPresence(reference: reference, present: true)
    }
  }

  public func resolve(slots: [CredentialSlot]) throws -> CredentialMaterial {
    guard slots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw CredentialVaultError.capacityExceeded
    }
    var required: [UUID: CredentialReference] = [:]
    for slot in slots {
      if let existing = required[slot.reference.id], existing.kind != slot.reference.kind {
        throw CredentialVaultError.kindMismatch(slot.reference.id)
      }
      required[slot.reference.id] = slot.reference
    }
    var stored = try store.load()
    defer { stored?.erase() }
    var document = try decode(stored)
    defer { erase(&document) }
    let byID = Dictionary(uniqueKeysWithValues: document.entries.map { ($0.reference.id, $0) })
    let entries = try required.values.sorted {
      $0.id.uuidString < $1.id.uuidString
    }.map { reference -> CredentialMaterialEntry in
      guard let stored = byID[reference.id] else {
        throw CredentialVaultError.missingCredential(reference.id)
      }
      guard stored.reference.kind == reference.kind else {
        throw CredentialVaultError.kindMismatch(reference.id)
      }
      return try CredentialMaterialEntry(reference: reference, secret: stored.secret)
    }
    return try CredentialMaterial(entries: entries)
  }

  /// Produces a non-secret, revision-bound deletion preview. Every reference
  /// supplied by the repository or native runtime must already exist with the
  /// same kind; otherwise maintenance fails without writing the Keychain.
  public func previewGarbageCollection(
    _ request: CredentialGarbageCollectionRequest
  ) throws -> CredentialGarbageCollectionPreview {
    guard var stored = try store.load() else {
      throw CredentialVaultError.missingVault
    }
    defer { stored.erase() }
    var document = try decode(stored)
    defer { erase(&document) }
    let orphans = try orphanReferences(
      in: document,
      preserving: request.liveReferences
    )
    return try CredentialGarbageCollectionPreview(
      snapshotDigest: request.snapshotDigest,
      vaultRevision: stored.revision,
      orphanReferences: orphans
    )
  }

  /// Deletes exactly the orphan set shown by a prior preview in one Keychain
  /// compare-and-swap. There is deliberately no retry: any concurrent
  /// provision, runtime-reference change, or stale confirmation invalidates
  /// the whole transaction and leaves the prior blob intact.
  public func commitGarbageCollection(
    _ request: CredentialGarbageCollectionCommitRequest
  ) throws -> CredentialGarbageCollectionReceipt {
    guard var stored = try store.load() else {
      throw CredentialVaultError.missingVault
    }
    defer { stored.erase() }
    guard stored.revision == request.expectedVaultRevision else {
      throw CredentialVaultError.garbageCollectionConfirmationExpired
    }
    var document = try decode(stored)
    defer { erase(&document) }
    let actualOrphans = try orphanReferences(
      in: document,
      preserving: request.liveReferences
    )
    guard actualOrphans == request.expectedOrphanReferences else {
      throw CredentialVaultError.garbageCollectionConfirmationExpired
    }
    guard !actualOrphans.isEmpty else {
      return CredentialGarbageCollectionReceipt(
        vaultRevision: stored.revision,
        deletedCount: 0
      )
    }
    let orphanIDs = Set(actualOrphans.map(\.id))
    var retained: [CredentialVaultEntry] = []
    retained.reserveCapacity(document.entries.count - actualOrphans.count)
    for index in document.entries.indices {
      if orphanIDs.contains(document.entries[index].reference.id) {
        // Scrub the document-owned buffer before removing the entry. Erasing
        // only a loop copy would not reliably clear this storage under Data's
        // copy-on-write semantics.
        document.entries[index].erase()
      } else {
        retained.append(document.entries[index])
      }
    }
    document.entries.removeAll(keepingCapacity: false)
    let newRevision = UUID()
    document = CredentialVaultDocument(
      schemaVersion: CredentialVaultConstants.schemaVersion,
      revision: newRevision,
      entries: retained
    )
    var encoded = try encode(document)
    defer {
      encoded.resetBytes(in: encoded.startIndex..<encoded.endIndex)
      encoded.removeAll(keepingCapacity: false)
    }
    do {
      try store.compareAndSwap(
        expectedRevision: stored.revision,
        newRevision: newRevision,
        data: encoded
      )
    } catch CredentialVaultError.compareAndSwapConflict {
      throw CredentialVaultError.garbageCollectionConfirmationExpired
    }
    guard let deletedCount = UInt32(exactly: actualOrphans.count) else {
      throw CredentialVaultError.capacityExceeded
    }
    return CredentialGarbageCollectionReceipt(
      vaultRevision: newRevision,
      deletedCount: deletedCount
    )
  }

  private func orphanReferences(
    in document: CredentialVaultDocument,
    preserving liveReferences: [CredentialReference]
  ) throws -> [CredentialReference] {
    let byID = Dictionary(
      uniqueKeysWithValues: document.entries.map {
        ($0.reference.id, $0.reference)
      })
    for live in liveReferences {
      guard let existing = byID[live.id] else {
        throw CredentialVaultError.missingCredential(live.id)
      }
      guard existing.kind == live.kind else {
        throw CredentialVaultError.kindMismatch(live.id)
      }
    }
    let liveIDs = Set(liveReferences.map(\.id))
    return document.entries.lazy
      .map(\.reference)
      .filter { !liveIDs.contains($0.id) }
      .sorted {
        let leftID = $0.id.uuidString.lowercased()
        let rightID = $1.id.uuidString.lowercased()
        if leftID != rightID {
          return leftID < rightID
        }
        return $0.kind.rawValue < $1.kind.rawValue
      }
  }

  private func decode(_ stored: StoredCredentialVaultBlob?) throws -> CredentialVaultDocument {
    guard var stored else {
      return CredentialVaultDocument(
        schemaVersion: CredentialVaultConstants.schemaVersion,
        revision: UUID(),
        entries: []
      )
    }
    defer { stored.erase() }
    guard !stored.data.isEmpty,
      stored.data.count <= CredentialVaultConstants.maximumDocumentBytes
    else {
      throw CredentialVaultError.corrupt
    }
    try validateWireShape(stored.data)
    let document: CredentialVaultDocument
    do {
      document = try JSONDecoder().decode(CredentialVaultDocument.self, from: stored.data)
    } catch {
      throw CredentialVaultError.corrupt
    }
    guard document.schemaVersion == CredentialVaultConstants.schemaVersion,
      document.revision == stored.revision,
      document.entries.count <= CredentialVaultConstants.maximumEntries,
      try encode(document) == stored.data
    else {
      throw CredentialVaultError.corrupt
    }
    var seen = Set<UUID>()
    var total = 0
    for entry in document.entries {
      guard seen.insert(entry.reference.id).inserted,
        !entry.secret.isEmpty,
        entry.secret.count <= CredentialMaterialConstants.maximumSecretBytes,
        let secretText = String(data: entry.secret, encoding: .utf8),
        secretText.unicodeScalars.contains(where: {
          CharacterSet.controlCharacters.contains($0)
        }) == false
      else {
        throw CredentialVaultError.corrupt
      }
      total = try total.addingChecked(entry.secret.count)
      guard total <= CredentialMaterialConstants.maximumTotalSecretBytes else {
        throw CredentialVaultError.corrupt
      }
    }
    guard
      document.entries.map(\.reference.id.uuidString)
        == document.entries.map(\.reference.id.uuidString).sorted()
    else {
      throw CredentialVaultError.corrupt
    }
    return document
  }

  private func encode(_ document: CredentialVaultDocument) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(document)
    guard data.count <= CredentialVaultConstants.maximumDocumentBytes else {
      throw CredentialVaultError.capacityExceeded
    }
    return data
  }

  private func validateWireShape(_ data: Data) throws {
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw CredentialVaultError.corrupt
    }
    guard let root = value as? [String: Any],
      Set(root.keys) == ["schemaVersion", "revision", "entries"],
      root["schemaVersion"] is NSNumber,
      root["revision"] is String,
      let entries = root["entries"] as? [Any]
    else {
      throw CredentialVaultError.corrupt
    }
    for value in entries {
      guard let entry = value as? [String: Any], Set(entry.keys) == ["reference", "secret"],
        entry["secret"] is String,
        let reference = entry["reference"] as? [String: Any],
        Set(reference.keys) == ["id", "kind"],
        reference["id"] is String, reference["kind"] is String
      else {
        throw CredentialVaultError.corrupt
      }
    }
  }

  private func erase(_ document: inout CredentialVaultDocument) {
    for index in document.entries.indices {
      document.entries[index].erase()
    }
    document.entries.removeAll(keepingCapacity: false)
  }

  static func timingSafeEqual(_ first: Data, _ second: Data) -> Bool {
    let maximum = max(first.count, second.count)
    var difference = first.count ^ second.count
    for index in 0..<maximum {
      let left = index < first.count ? first[index] : 0
      let right = index < second.count ? second[index] : 0
      difference |= Int(left ^ right)
    }
    return difference == 0
  }
}

extension FixedWidthInteger {
  fileprivate func addingChecked(_ other: Self) throws -> Self {
    let (result, overflow) = addingReportingOverflow(other)
    guard !overflow else {
      throw CredentialVaultError.capacityExceeded
    }
    return result
  }
}
