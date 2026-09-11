import CFWSharedProtocol
import Foundation

public enum CredentialMaterialConstants {
  public static let schemaVersion: UInt16 = 1
  public static let maximumSecretBytes = 16 * 1_024
  public static let maximumTotalSecretBytes = 448 * 1_024
  public static let maximumEncodedBytes = 512 * 1_024
}

public enum CredentialMaterialError: Error, Equatable, Sendable {
  case malformedPayload
  case unsupportedSchemaVersion(UInt16)
  case tooManyEntries
  case duplicateReference
  case secretTooLarge
  case totalSecretBytesExceeded
  case invalidSecret
  case missingReference(UUID)
  case unexpectedReference(UUID)
  case kindMismatch(UUID)
  case nonEmptyPlaceholder(String)
  case invalidConfiguration
  case configurationTooLarge
}

public struct CredentialMaterialEntry: Equatable, Sendable {
  public let reference: CredentialReference
  private(set) var secret: Data

  public init(reference: CredentialReference, secret: Data) throws {
    guard !secret.isEmpty,
      secret.count <= CredentialMaterialConstants.maximumSecretBytes,
      let value = String(data: secret, encoding: .utf8),
      !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
      reference.kind.admitsSecretSyntax(value)
    else {
      throw CredentialMaterialError.invalidSecret
    }
    self.reference = reference
    self.secret = secret
  }

  public mutating func erase() {
    secret.resetBytes(in: secret.startIndex..<secret.endIndex)
    secret.removeAll(keepingCapacity: false)
  }

  /// Exposes bytes only to the in-process vault/engine injection boundary.
  /// Callers must not retain, log, hash, or persist the returned value outside
  /// the dedicated credential vault.
  public func withSecretBytes<Result>(
    _ operation: (Data) throws -> Result
  ) rethrows -> Result {
    try operation(secret)
  }

  fileprivate func exposedSecret() -> Data { secret }
}

extension CredentialMaterialEntry: CustomDebugStringConvertible {
  public var debugDescription: String {
    "CredentialMaterialEntry(reference: \(reference), secret: [REDACTED])"
  }
}

public struct CredentialMaterial: Equatable, Sendable {
  public static let empty = CredentialMaterial(validatedEntries: [])
  public private(set) var entries: [CredentialMaterialEntry]

  public init(entries: [CredentialMaterialEntry]) throws {
    guard entries.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw CredentialMaterialError.tooManyEntries
    }
    var references = Set<UUID>()
    var total = 0
    for entry in entries {
      guard references.insert(entry.reference.id).inserted else {
        throw CredentialMaterialError.duplicateReference
      }
      total = try total.addingChecked(entry.exposedSecret().count)
      guard total <= CredentialMaterialConstants.maximumTotalSecretBytes else {
        throw CredentialMaterialError.totalSecretBytesExceeded
      }
    }
    self.entries = entries.sorted {
      $0.reference.id.uuidString < $1.reference.id.uuidString
    }
  }

  private init(validatedEntries: [CredentialMaterialEntry]) {
    entries = validatedEntries
  }

  /// Encodes the Authority's bounded XPC format, preserving descriptor order
  /// instead of the vault's UUID ordering. The caller owns and erases the result.
  public func authorityPayload(for slots: [CredentialSlot]) throws -> SensitiveBytes? {
    let references = try AuthoritySecretPayloadCodec.references(for: slots)
    let required = Set(references.map(\.id))
    let supplied = Dictionary(uniqueKeysWithValues: entries.map { ($0.reference.id, $0) })
    for entry in entries where !required.contains(entry.reference.id) {
      throw CredentialMaterialError.unexpectedReference(entry.reference.id)
    }
    var secrets: [AuthoritySecretSlot] = []
    defer { for secret in secrets { secret.erase() } }
    for reference in references {
      guard let entry = supplied[reference.id] else {
        throw CredentialMaterialError.missingReference(reference.id)
      }
      guard entry.reference.kind == reference.kind else {
        throw CredentialMaterialError.kindMismatch(reference.id)
      }
      secrets.append(
        try entry.withSecretBytes {
          try AuthoritySecretSlot(reference: reference, copying: $0)
        })
    }
    let material = try AuthoritySecretMaterial(slots: secrets)
    defer { material.erase() }
    return try AuthoritySecretPayloadCodec.encode(material)
  }

  public mutating func erase() {
    for index in entries.indices {
      entries[index].erase()
    }
    entries.removeAll(keepingCapacity: false)
  }
}

extension CredentialMaterial: CustomDebugStringConvertible {
  public var debugDescription: String {
    "CredentialMaterial(entries: [REDACTED \(entries.count) ENTRIES])"
  }
}

private struct CredentialMaterialWire: Codable {
  let schemaVersion: UInt16
  var entries: [CredentialMaterialEntryWire]
}

private struct CredentialMaterialEntryWire: Codable {
  let reference: CredentialReference
  var secret: Data
}

public enum EphemeralCredentialCodec {
  public static func encode(_ material: CredentialMaterial) throws -> Data {
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    var wire = CredentialMaterialWire(
      schemaVersion: CredentialMaterialConstants.schemaVersion,
      entries: material.entries.map {
        CredentialMaterialEntryWire(reference: $0.reference, secret: $0.exposedSecret())
      }
    )
    defer {
      for index in wire.entries.indices {
        wire.entries[index].secret.resetBytes(
          in: wire.entries[index].secret.startIndex..<wire.entries[index].secret.endIndex
        )
      }
    }
    let encoded = try encoder.encode(wire)
    guard encoded.count <= CredentialMaterialConstants.maximumEncodedBytes else {
      throw CredentialMaterialError.totalSecretBytesExceeded
    }
    return encoded
  }

  public static func decode(_ data: Data) throws -> CredentialMaterial {
    guard !data.isEmpty, data.count <= CredentialMaterialConstants.maximumEncodedBytes else {
      throw CredentialMaterialError.malformedPayload
    }
    try validateWireShape(data)
    var wire: CredentialMaterialWire
    do {
      wire = try PropertyListDecoder().decode(CredentialMaterialWire.self, from: data)
    } catch {
      throw CredentialMaterialError.malformedPayload
    }
    defer {
      for index in wire.entries.indices {
        wire.entries[index].secret.resetBytes(
          in: wire.entries[index].secret.startIndex..<wire.entries[index].secret.endIndex
        )
      }
    }
    guard wire.schemaVersion == CredentialMaterialConstants.schemaVersion else {
      throw CredentialMaterialError.unsupportedSchemaVersion(wire.schemaVersion)
    }
    return try CredentialMaterial(
      entries: wire.entries.map {
        try CredentialMaterialEntry(reference: $0.reference, secret: $0.secret)
      }
    )
  }

  private static func validateWireShape(_ data: Data) throws {
    let value: Any
    do {
      value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    } catch {
      throw CredentialMaterialError.malformedPayload
    }
    guard let root = value as? [String: Any], Set(root.keys) == ["schemaVersion", "entries"],
      root["schemaVersion"] is NSNumber,
      let entries = root["entries"] as? [Any]
    else {
      throw CredentialMaterialError.malformedPayload
    }
    for value in entries {
      guard let entry = value as? [String: Any], Set(entry.keys) == ["reference", "secret"],
        entry["secret"] is Data,
        let reference = entry["reference"] as? [String: Any],
        Set(reference.keys) == ["id", "kind"],
        reference["id"] is String, reference["kind"] is String
      else {
        throw CredentialMaterialError.malformedPayload
      }
    }
  }
}

public enum CredentialInjector {
  public static func inject(
    template: Data,
    slots: [CredentialSlot],
    material: CredentialMaterial
  ) throws -> Data {
    guard !template.isEmpty,
      template.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      var root = try JSONSerialization.jsonObject(with: template) as? [String: Any]
    else {
      throw CredentialMaterialError.invalidConfiguration
    }
    let requiredReferences = Dictionary(grouping: slots, by: { $0.reference.id })
    var supplied: [UUID: CredentialMaterialEntry] = [:]
    for entry in material.entries {
      guard requiredReferences[entry.reference.id] != nil else {
        throw CredentialMaterialError.unexpectedReference(entry.reference.id)
      }
      supplied[entry.reference.id] = entry
    }
    for (referenceID, referenceSlots) in requiredReferences {
      guard let entry = supplied[referenceID] else {
        throw CredentialMaterialError.missingReference(referenceID)
      }
      guard referenceSlots.allSatisfy({ $0.reference.kind == entry.reference.kind }) else {
        throw CredentialMaterialError.kindMismatch(referenceID)
      }
    }

    for slot in slots {
      let index = Int(slot.outboundIndex)
      let container = slot.target.configurationContainer
      guard var outbounds = root[container] as? [Any], index < outbounds.count,
        var outbound = outbounds[index] as? [String: Any],
        let entry = supplied[slot.reference.id],
        let secret = String(data: entry.exposedSecret(), encoding: .utf8)
      else {
        throw CredentialMaterialError.invalidConfiguration
      }
      switch slot.target {
      case .wireguardPrivateKey:
        guard outbound["type"] as? String == "wireguard", outbound["private_key"] as? String == ""
        else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        outbound["private_key"] = secret
      case .wireguardPreSharedKey:
        guard outbound["type"] as? String == "wireguard",
          var peers = outbound["peers"] as? [[String: Any]], peers.count == 1,
          peers[0]["pre_shared_key"] as? String == ""
        else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        peers[0]["pre_shared_key"] = secret
        outbound["peers"] = peers
      case .socks5Username:
        guard outbound["username"] as? String == "" else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        outbound["username"] = secret
      case .shadowsocksPassword, .trojanPassword, .hysteria2Password, .anytlsPassword,
        .tuicPassword, .socks5Password:
        guard outbound["password"] as? String == "" else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        outbound["password"] = secret
      case .vmessUUID, .vlessUUID, .tuicUUID:
        guard outbound["uuid"] as? String == "" else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        outbound["uuid"] = secret
      case .hysteria2ObfsPassword:
        guard var obfs = outbound["obfs"] as? [String: Any],
          obfs["password"] as? String == ""
        else {
          throw CredentialMaterialError.nonEmptyPlaceholder(slot.jsonPointer)
        }
        obfs["password"] = secret
        outbound["obfs"] = obfs
      }
      outbounds[index] = outbound
      root[container] = outbounds
    }
    let filled = try JSONSerialization.data(
      withJSONObject: root,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    guard filled.count <= Int(NativeProtocolConstants.maximumConfigurationBytes) else {
      throw CredentialMaterialError.configurationTooLarge
    }
    return filled
  }
}

extension FixedWidthInteger {
  fileprivate func addingChecked(_ other: Self) throws -> Self {
    let (result, overflow) = addingReportingOverflow(other)
    guard !overflow else {
      throw CredentialMaterialError.totalSecretBytesExceeded
    }
    return result
  }
}
