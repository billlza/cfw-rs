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
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    material: CredentialMaterial
  ) throws -> CredentialVaultReceipt {
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
      var byBinding = Dictionary(
        uniqueKeysWithValues: document.entries.map {
          (CredentialBinding(audience: $0.audience, reference: $0.reference), $0)
        })
      let suppliedIDs = Set(material.entries.map(\.reference.id))
      for required in requiredReferences {
        let binding = CredentialBinding(audience: audience, reference: required)
        if let existing = byBinding[binding] {
          guard existing.reference.kind == required.kind else {
            throw CredentialVaultError.kindMismatch(required.id)
          }
        } else if !suppliedIDs.contains(required.id) {
          throw CredentialVaultError.missingCredential(required.id)
        }
      }
      for requested in material.entries {
        let requestedSecret = requested.withSecretBytes { $0 }
        for existing in document.entries where existing.reference.id == requested.reference.id {
          guard existing.reference.kind == requested.reference.kind else {
            throw CredentialVaultError.kindMismatch(requested.reference.id)
          }
          guard Self.timingSafeEqual(existing.secret, requestedSecret) else {
            throw CredentialVaultError.immutableConflict(requested.reference.id)
          }
        }
        let binding = CredentialBinding(audience: audience, reference: requested.reference)
        if byBinding[binding] == nil {
          byBinding[binding] = CredentialVaultEntry(
            audience: audience,
            reference: requested.reference,
            secret: requestedSecret
          )
        }
      }
      guard byBinding.count <= CredentialVaultConstants.maximumEntries else {
        throw CredentialVaultError.capacityExceeded
      }
      let newRevision = UUID()
      document = CredentialVaultDocument(
        schemaVersion: CredentialVaultConstants.schemaVersion,
        revision: newRevision,
        entries: byBinding.values.sorted(by: Self.entryPrecedes)
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
        return CredentialVaultReceipt(audience: audience)
      } catch CredentialVaultError.compareAndSwapConflict {
        continue
      }
    }
    throw CredentialVaultError.compareAndSwapConflict
  }

  public func presence(
    audience: CredentialAudience,
    of references: [CredentialReference]
  ) throws -> [CredentialPresence] {
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
    let byBinding = Dictionary(
      uniqueKeysWithValues: document.entries.map {
        (CredentialBinding(audience: $0.audience, reference: $0.reference), $0)
      })
    return try references.map { reference in
      let binding = CredentialBinding(audience: audience, reference: reference)
      guard let existing = byBinding[binding] else {
        return CredentialPresence(reference: reference, present: false)
      }
      guard existing.reference.kind == reference.kind else {
        throw CredentialVaultError.kindMismatch(reference.id)
      }
      return CredentialPresence(reference: reference, present: true)
    }
  }

  public func resolve(
    audience: CredentialAudience,
    slots: [CredentialSlot]
  ) throws -> CredentialMaterial {
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
    let byBinding = Dictionary(
      uniqueKeysWithValues: document.entries.map {
        (CredentialBinding(audience: $0.audience, reference: $0.reference), $0)
      })
    let entries = try required.values.sorted {
      $0.id.uuidString < $1.id.uuidString
    }.map { reference -> CredentialMaterialEntry in
      let binding = CredentialBinding(audience: audience, reference: reference)
      guard let stored = byBinding[binding] else {
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
      preserving: request.bindings
    )
    return try CredentialGarbageCollectionPreview(
      snapshotDigest: request.snapshotDigest,
      vaultRevision: stored.revision,
      orphanBindings: orphans
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
      preserving: request.catalog.flatMap { entry in
        entry.references.map {
          CredentialBinding(audience: entry.audience, reference: $0)
        }
      }
    )
    guard actualOrphans == request.expectedOrphanBindings else {
      throw CredentialVaultError.garbageCollectionConfirmationExpired
    }
    guard !actualOrphans.isEmpty else {
      return CredentialGarbageCollectionReceipt(
        vaultRevision: stored.revision,
        deletedCount: 0
      )
    }
    let orphanBindings = Set(actualOrphans)
    var retained: [CredentialVaultEntry] = []
    retained.reserveCapacity(document.entries.count - actualOrphans.count)
    for index in document.entries.indices {
      let binding = CredentialBinding(
        audience: document.entries[index].audience,
        reference: document.entries[index].reference
      )
      if orphanBindings.contains(binding) {
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
    preserving liveBindings: [CredentialBinding]
  ) throws -> [CredentialBinding] {
    let storedBindings = Dictionary(
      uniqueKeysWithValues: document.entries.map {
        (
          CredentialBinding(audience: $0.audience, reference: $0.reference),
          $0.reference
        )
      })
    for live in liveBindings {
      guard let existing = storedBindings[live] else {
        throw CredentialVaultError.missingCredential(live.reference.id)
      }
      guard existing.kind == live.reference.kind else {
        throw CredentialVaultError.kindMismatch(live.reference.id)
      }
    }
    let live = Set(liveBindings)
    return document.entries.lazy
      .map { CredentialBinding(audience: $0.audience, reference: $0.reference) }
      .filter { !live.contains($0) }
      .sorted(by: CredentialBinding.canonicalPrecedes)
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
    let storedSchemaVersion = try validateWireShape(stored.data)
    guard storedSchemaVersion == CredentialVaultConstants.schemaVersion else {
      throw CredentialVaultError.unsupportedSchemaVersion(storedSchemaVersion)
    }
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
    var seen = Set<CredentialBinding>()
    var total = 0
    for entry in document.entries {
      let binding = CredentialBinding(audience: entry.audience, reference: entry.reference)
      guard seen.insert(binding).inserted,
        !entry.secret.isEmpty,
        entry.secret.count <= CredentialMaterialConstants.maximumSecretBytes,
        let secretText = String(data: entry.secret, encoding: .utf8),
        entry.reference.kind.admitsSecretSyntax(secretText),
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
      document.entries.sorted(by: Self.entryPrecedes) == document.entries
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

  private func validateWireShape(_ data: Data) throws -> UInt16 {
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw CredentialVaultError.corrupt
    }
    guard let root = value as? [String: Any],
      Set(root.keys) == ["schemaVersion", "revision", "entries"],
      let schemaVersion = root["schemaVersion"] as? NSNumber,
      root["revision"] is String,
      let entries = root["entries"] as? [Any]
    else {
      throw CredentialVaultError.corrupt
    }
    guard CFGetTypeID(schemaVersion) != CFBooleanGetTypeID(),
      let decodedVersion = UInt16(exactly: schemaVersion.uint64Value)
    else {
      throw CredentialVaultError.corrupt
    }
    if decodedVersion != CredentialVaultConstants.schemaVersion {
      return decodedVersion
    }
    for value in entries {
      guard let entry = value as? [String: Any],
        Set(entry.keys) == ["audience", "reference", "secret"],
        entry["secret"] is String,
        let audience = entry["audience"] as? [String: Any],
        Set(audience.keys) == ["profile_id", "profile_digest"],
        audience["profile_id"] is String, audience["profile_digest"] is String,
        let reference = entry["reference"] as? [String: Any],
        Set(reference.keys) == ["id", "kind"],
        reference["id"] is String, reference["kind"] is String
      else {
        throw CredentialVaultError.corrupt
      }
    }
    return decodedVersion
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

  private static func entryPrecedes(
    _ left: CredentialVaultEntry,
    _ right: CredentialVaultEntry
  ) -> Bool {
    CredentialBinding.canonicalPrecedes(
      CredentialBinding(audience: left.audience, reference: left.reference),
      CredentialBinding(audience: right.audience, reference: right.reference)
    )
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
