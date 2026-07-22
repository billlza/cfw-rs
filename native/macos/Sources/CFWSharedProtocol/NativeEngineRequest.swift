import CryptoKit
import Foundation

public enum NativeBridgeProtocolConstants {
  public static let schemaVersion: UInt16 = 3
  public static let maximumRequestBytes = 1_048_576
  public static let maximumResponseBytes = 1_048_576
  public static let maximumFailureMessageBytes = 1_024
  public static let maximumCredentialSlots = 256
  public static let maximumCredentialOutbounds = 128
  public static let maximumCredentialVaultReferences = 512
}

public enum NativeBridgeProtocolError: Error, Equatable, Sendable {
  case messageTooLarge(actual: Int, maximum: Int)
  case unsupportedSchemaVersion(UInt16)
  case malformedEnvelope
  case invalidContext
  case invalidConfiguration
  case configurationDigestMismatch
  case configurationIdentityMismatch
  case invalidCredentialSlot
  case duplicateCredentialPointer
  case conflictingCredentialKind
  case nonEmptyCredentialPlaceholder
  case invalidCommand
  case invalidResponse
}

public struct EngineCommandContext: Codable, Equatable, Sendable {
  public let installationID: UUID
  public let configEpoch: UInt64
  public let generation: UInt64

  public init(installationID: UUID, configEpoch: UInt64, generation: UInt64) throws {
    guard configEpoch > 0, generation > 0 else {
      throw NativeBridgeProtocolError.invalidContext
    }
    self.installationID = installationID
    self.configEpoch = configEpoch
    self.generation = generation
  }

  public var descriptorInstallationID: UUID { installationID }

  private enum CodingKeys: String, CodingKey {
    case installationID = "installation_id"
    case configEpoch = "config_epoch"
    case generation
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let installationIDText = try container.decode(String.self, forKey: .installationID)
    guard installationIDText == installationIDText.lowercased(),
      let installationID = UUID(uuidString: installationIDText),
      installationID.uuidString.lowercased() == installationIDText
    else {
      throw NativeBridgeProtocolError.invalidContext
    }
    try self.init(
      installationID: installationID,
      configEpoch: container.decode(UInt64.self, forKey: .configEpoch),
      generation: container.decode(UInt64.self, forKey: .generation)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(installationID.uuidString.lowercased(), forKey: .installationID)
    try container.encode(configEpoch, forKey: .configEpoch)
    try container.encode(generation, forKey: .generation)
  }
}

public enum CredentialKind: String, Codable, CaseIterable, Sendable {
  case shadowsocksPassword = "shadowsocks_password"
  case vmessUUID = "vmess_uuid"
  case vlessUUID = "vless_uuid"
  case trojanPassword = "trojan_password"
  case hysteria2Password = "hysteria2_password"
  case hysteria2ObfsPassword = "hysteria2_obfs_password"
}

public enum CredentialTarget: String, Codable, CaseIterable, Sendable {
  case shadowsocksPassword = "shadowsocks_password"
  case vmessUUID = "vmess_uuid"
  case vlessUUID = "vless_uuid"
  case trojanPassword = "trojan_password"
  case hysteria2Password = "hysteria2_password"
  case hysteria2ObfsPassword = "hysteria2_obfs_password"

  fileprivate var credentialKind: CredentialKind {
    switch self {
    case .shadowsocksPassword: .shadowsocksPassword
    case .vmessUUID: .vmessUUID
    case .vlessUUID: .vlessUUID
    case .trojanPassword: .trojanPassword
    case .hysteria2Password: .hysteria2Password
    case .hysteria2ObfsPassword: .hysteria2ObfsPassword
    }
  }

  fileprivate var pointerSuffix: String {
    switch self {
    case .shadowsocksPassword, .trojanPassword, .hysteria2Password:
      "password"
    case .vmessUUID, .vlessUUID:
      "uuid"
    case .hysteria2ObfsPassword:
      "obfs/password"
    }
  }
}

public struct CredentialReference: Codable, Equatable, Hashable, Sendable {
  public let id: UUID
  public let kind: CredentialKind

  public init(id: UUID, kind: CredentialKind) {
    self.id = id
    self.kind = kind
  }

  private enum CodingKeys: String, CodingKey {
    case id
    case kind
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let idText = try container.decode(String.self, forKey: .id)
    guard idText == idText.lowercased(),
      let id = UUID(uuidString: idText),
      id.uuidString.lowercased() == idText
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.id = id
    kind = try container.decode(CredentialKind.self, forKey: .kind)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(id.uuidString.lowercased(), forKey: .id)
    try container.encode(kind, forKey: .kind)
  }
}

public struct CredentialSlot: Codable, Equatable, Sendable {
  public let reference: CredentialReference
  public let target: CredentialTarget
  public let outboundIndex: UInt16
  public let jsonPointer: String

  public init(
    reference: CredentialReference,
    target: CredentialTarget,
    outboundIndex: UInt16,
    jsonPointer: String
  ) throws {
    guard Int(outboundIndex) < NativeBridgeProtocolConstants.maximumCredentialOutbounds,
      reference.kind == target.credentialKind,
      jsonPointer == "/outbounds/\(outboundIndex)/\(target.pointerSuffix)"
    else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    self.reference = reference
    self.target = target
    self.outboundIndex = outboundIndex
    self.jsonPointer = jsonPointer
  }

  private enum CodingKeys: String, CodingKey {
    case reference
    case target
    case outboundIndex = "outbound_index"
    case jsonPointer = "json_pointer"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      reference: container.decode(CredentialReference.self, forKey: .reference),
      target: container.decode(CredentialTarget.self, forKey: .target),
      outboundIndex: container.decode(UInt16.self, forKey: .outboundIndex),
      jsonPointer: container.decode(String.self, forKey: .jsonPointer)
    )
  }
}

public struct EngineStartRequest: Codable, Equatable, Sendable {
  public let context: EngineCommandContext
  public let configJSON: String
  public let configContentDigest: SHA256Digest
  public let configDigest: SHA256Digest
  public let credentialSlots: [CredentialSlot]
  public let tunnelOptions: TunnelNetworkOptions?

  public init(
    context: EngineCommandContext,
    configJSON: String,
    configContentDigest: SHA256Digest,
    configDigest: SHA256Digest,
    credentialSlots: [CredentialSlot],
    tunnelOptions: TunnelNetworkOptions?
  ) throws {
    guard let configuration = configJSON.data(using: .utf8), !configuration.isEmpty,
      configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      let object = try? JSONSerialization.jsonObject(with: configuration),
      let root = object as? [String: Any]
    else {
      throw NativeBridgeProtocolError.invalidConfiguration
    }
    let contentDigest = SHA256.hash(data: configuration).hexString
    guard contentDigest == configContentDigest.hex else {
      throw NativeBridgeProtocolError.configurationDigestMismatch
    }
    try Self.validateCredentialSlots(credentialSlots, root: root)
    let expectedIdentity = try Self.identityDigest(
      configurationDigest: configContentDigest,
      credentialSlots: credentialSlots,
      mode: tunnelOptions == nil ? .systemProxy : .tunnel,
      tunnelOptions: tunnelOptions
    )
    guard expectedIdentity == configDigest else {
      throw NativeBridgeProtocolError.configurationIdentityMismatch
    }
    self.context = context
    self.configJSON = configJSON
    self.configContentDigest = configContentDigest
    self.configDigest = configDigest
    self.credentialSlots = credentialSlots
    self.tunnelOptions = tunnelOptions
  }

  private enum CodingKeys: String, CodingKey {
    case context
    case configJSON = "config_json"
    case configContentDigest = "config_content_digest"
    case configDigest = "config_digest"
    case credentialSlots = "credential_slots"
    case tunnelOptions = "tunnel_options"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      context: container.decode(EngineCommandContext.self, forKey: .context),
      configJSON: container.decode(String.self, forKey: .configJSON),
      configContentDigest: SHA256Digest(
        hex: container.decode(String.self, forKey: .configContentDigest)
      ),
      configDigest: SHA256Digest(hex: container.decode(String.self, forKey: .configDigest)),
      credentialSlots: container.decode([CredentialSlot].self, forKey: .credentialSlots),
      tunnelOptions: container.decodeIfPresent(TunnelNetworkOptions.self, forKey: .tunnelOptions)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(context, forKey: .context)
    try container.encode(configJSON, forKey: .configJSON)
    try container.encode(configContentDigest.hex, forKey: .configContentDigest)
    try container.encode(configDigest.hex, forKey: .configDigest)
    try container.encode(credentialSlots, forKey: .credentialSlots)
    try container.encodeIfPresent(tunnelOptions, forKey: .tunnelOptions)
  }

  public func descriptor(slot: ConfigurationSlot) throws -> ConfigurationDescriptor {
    let configuration = Data(configJSON.utf8)
    return try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: tunnelOptions,
      installationID: context.descriptorInstallationID,
      epoch: context.configEpoch,
      generation: context.generation,
      byteCount: UInt64(configuration.count),
      sha256: configContentDigest,
      identitySHA256: configDigest,
      credentialSlots: credentialSlots
    )
  }

  private static func validateCredentialSlots(
    _ slots: [CredentialSlot],
    root: [String: Any]
  ) throws {
    guard slots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var pointers = Set<String>()
    var referenceKinds: [UUID: CredentialKind] = [:]
    for slot in slots {
      guard pointers.insert(slot.jsonPointer).inserted else {
        throw NativeBridgeProtocolError.duplicateCredentialPointer
      }
      if let prior = referenceKinds.updateValue(slot.reference.kind, forKey: slot.reference.id),
        prior != slot.reference.kind
      {
        throw NativeBridgeProtocolError.conflictingCredentialKind
      }
      guard let outbounds = root["outbounds"] as? [Any],
        Int(slot.outboundIndex) < outbounds.count,
        let outbound = outbounds[Int(slot.outboundIndex)] as? [String: Any],
        Self.placeholder(in: outbound, target: slot.target) == ""
      else {
        throw NativeBridgeProtocolError.nonEmptyCredentialPlaceholder
      }
    }
  }

  private static func placeholder(
    in outbound: [String: Any],
    target: CredentialTarget
  ) -> String? {
    switch target {
    case .shadowsocksPassword, .trojanPassword, .hysteria2Password:
      outbound["password"] as? String
    case .vmessUUID, .vlessUUID:
      outbound["uuid"] as? String
    case .hysteria2ObfsPassword:
      (outbound["obfs"] as? [String: Any])?["password"] as? String
    }
  }

  private struct IdentityDocument: Encodable {
    let configurationSHA256: String
    let credentialSlots: [CredentialSlot]
    let mode: String
    let networkOptions: TunnelNetworkOptions?
    let schemaVersion: UInt16

    enum CodingKeys: String, CodingKey {
      case configurationSHA256 = "configuration_sha256"
      case credentialSlots = "credential_slots"
      case mode
      case networkOptions = "network_options"
      case schemaVersion = "schema_version"
    }

    func encode(to encoder: Encoder) throws {
      var container = encoder.container(keyedBy: CodingKeys.self)
      try container.encode(configurationSHA256, forKey: .configurationSHA256)
      try container.encode(credentialSlots, forKey: .credentialSlots)
      try container.encode(mode, forKey: .mode)
      if let networkOptions {
        try container.encode(networkOptions, forKey: .networkOptions)
      } else {
        try container.encodeNil(forKey: .networkOptions)
      }
      try container.encode(schemaVersion, forKey: .schemaVersion)
    }
  }

  private static func identityDigest(
    configurationDigest: SHA256Digest,
    credentialSlots: [CredentialSlot],
    mode: EngineMode,
    tunnelOptions: TunnelNetworkOptions?
  ) throws -> SHA256Digest {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(
      IdentityDocument(
        configurationSHA256: configurationDigest.hex,
        credentialSlots: credentialSlots,
        mode: mode == .systemProxy ? "system_proxy" : "tunnel",
        networkOptions: tunnelOptions,
        schemaVersion: NativeProtocolConstants.schemaVersion
      )
    )
    return SHA256Digest(validatedHex: SHA256.hash(data: data).hexString)
  }
}
