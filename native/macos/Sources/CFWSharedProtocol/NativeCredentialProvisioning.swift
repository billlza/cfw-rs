import Foundation

public struct CredentialProvisionEntry: Codable, Equatable, Sendable {
  public let reference: CredentialReference
  private var secret: Data

  public init(reference: CredentialReference, secret: String) throws {
    try self.init(reference: reference, secretBytes: Data(secret.utf8))
  }

  private init(reference: CredentialReference, secretBytes: Data) throws {
    guard !secretBytes.isEmpty,
      secretBytes.count <= 16 * 1_024,
      let value = String(data: secretBytes, encoding: .utf8),
      !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
      reference.kind.admitsSecretSyntax(value)
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.reference = reference
    secret = secretBytes
  }

  public func withSecretBytes<Result>(
    _ operation: (Data) throws -> Result
  ) rethrows -> Result {
    try operation(secret)
  }

  mutating func erase() {
    secret.resetBytes(in: secret.startIndex..<secret.endIndex)
    secret.removeAll(keepingCapacity: false)
  }

  private enum CodingKeys: String, CodingKey {
    case reference
    case secret
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    // JSON strings are an unavoidable transient created by JSONDecoder. Keep
    // it scoped to this initializer, immediately copy to erasable Data, and
    // never retain, log, hash, or echo it. Swift does not expose a supported
    // way to zeroize String storage, so this is a best-effort boundary rather
    // than a claim of complete process-memory zeroization.
    let decodedSecret = try container.decode(String.self, forKey: .secret)
    try self.init(
      reference: container.decode(CredentialReference.self, forKey: .reference),
      secretBytes: Data(decodedSecret.utf8)
    )
  }

  public func encode(to encoder: Encoder) throws {
    guard let value = String(data: secret, encoding: .utf8) else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(reference, forKey: .reference)
    try container.encode(value, forKey: .secret)
  }
}

extension CredentialProvisionEntry: CustomDebugStringConvertible {
  public var debugDescription: String {
    "CredentialProvisionEntry(reference: \(reference), secret: [REDACTED])"
  }
}

public struct CredentialProvisionRequest: Codable, Equatable, Sendable {
  public let audience: CredentialAudience
  public let requiredReferences: [CredentialReference]
  public private(set) var entries: [CredentialProvisionEntry]

  public init(
    audience: CredentialAudience,
    requiredReferences: [CredentialReference],
    entries: [CredentialProvisionEntry]
  ) throws {
    guard requiredReferences.count <= NativeBridgeProtocolConstants.maximumCredentialSlots,
      entries.count <= NativeBridgeProtocolConstants.maximumCredentialSlots,
      requiredReferences.sorted(by: CredentialReference.canonicalPrecedes) == requiredReferences,
      entries.map(\.reference).sorted(by: CredentialReference.canonicalPrecedes)
        == entries.map(\.reference)
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var requiredByID: [UUID: CredentialKind] = [:]
    for reference in requiredReferences {
      guard requiredByID.updateValue(reference.kind, forKey: reference.id) == nil else {
        throw NativeBridgeProtocolError.duplicateCredentialPointer
      }
    }
    var supplied = Set<UUID>()
    var totalBytes = 0
    for entry in entries {
      guard supplied.insert(entry.reference.id).inserted else {
        throw NativeBridgeProtocolError.duplicateCredentialPointer
      }
      guard requiredByID[entry.reference.id] == entry.reference.kind else {
        throw NativeBridgeProtocolError.invalidCredentialSlot
      }
      let (nextTotal, overflow) = entry.withSecretBytes {
        totalBytes.addingReportingOverflow($0.count)
      }
      guard !overflow else {
        throw NativeBridgeProtocolError.invalidCredentialSlot
      }
      totalBytes = nextTotal
      guard totalBytes <= 512 * 1_024 else {
        throw NativeBridgeProtocolError.invalidCredentialSlot
      }
    }
    self.audience = audience
    self.requiredReferences = requiredReferences
    self.entries = entries
  }

  private enum CodingKeys: String, CodingKey {
    case audience
    case requiredReferences = "required_references"
    case entries
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      audience: container.decode(CredentialAudience.self, forKey: .audience),
      requiredReferences: container.decode(
        [CredentialReference].self,
        forKey: .requiredReferences
      ),
      entries: container.decode([CredentialProvisionEntry].self, forKey: .entries)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(audience, forKey: .audience)
    try container.encode(requiredReferences, forKey: .requiredReferences)
    try container.encode(entries, forKey: .entries)
  }

  public mutating func erase() {
    for index in entries.indices {
      entries[index].erase()
    }
    entries.removeAll(keepingCapacity: false)
  }
}

public struct CredentialPresenceRequest: Codable, Equatable, Sendable {
  public let audience: CredentialAudience
  public let references: [CredentialReference]

  public init(audience: CredentialAudience, references: [CredentialReference]) throws {
    guard references.count <= NativeBridgeProtocolConstants.maximumCredentialSlots,
      references.sorted(by: CredentialReference.canonicalPrecedes) == references
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var ids = Set<UUID>()
    guard references.allSatisfy({ ids.insert($0.id).inserted }) else {
      throw NativeBridgeProtocolError.duplicateCredentialPointer
    }
    self.audience = audience
    self.references = references
  }

  private enum CodingKeys: String, CodingKey {
    case audience
    case references
  }
}

public struct NativeCredentialReceipt: Codable, Equatable, Sendable {
  public let profileID: UUID
  public let profileDigest: SHA256Digest

  public init(audience: CredentialAudience) {
    profileID = audience.profileID
    profileDigest = audience.profileDigest
  }

  private enum CodingKeys: String, CodingKey {
    case profileID = "profile_id"
    case profileDigest = "profile_digest"
  }
}

public struct NativeCredentialPresence: Codable, Equatable, Sendable {
  public let reference: CredentialReference
  public let present: Bool

  public init(reference: CredentialReference, present: Bool) {
    self.reference = reference
    self.present = present
  }
}
