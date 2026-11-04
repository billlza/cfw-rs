import CryptoKit
import Foundation

public enum ConfigurationBytesValidationError: Error, Equatable, Sendable {
  case empty
  case tooLarge(actual: UInt64, maximum: UInt64)
  case byteCountMismatch(expected: UInt64, actual: UInt64)
  case digestMismatch(expected: String, actual: String)
  case invalidJSON
}

public enum ConfigurationSlot: String, Codable, CaseIterable, Sendable {
  case localProxy
  case systemProxy
  case tunnel

  public var engineMode: EngineMode {
    switch self {
    case .localProxy: .localProxy
    case .systemProxy: .systemProxy
    case .tunnel: .tunnel
    }
  }

  public var authorityMode: AuthorityMode {
    switch self {
    case .localProxy: .localProxy
    case .systemProxy: .systemProxy
    case .tunnel: .tunnel
    }
  }

  public var isProxyAgent: Bool { self == .localProxy || self == .systemProxy }

  public var fileName: String {
    switch self {
    case .localProxy:
      "local-proxy-config.json"
    case .systemProxy:
      "system-proxy-config.json"
    case .tunnel:
      "tunnel-config.json"
    }
  }
}

public struct TunnelNetworkOptions: Codable, Equatable, Sendable {
  public static let minimumMTU: UInt16 = 1_280
  public static let maximumMTU: UInt16 = 1_500
  public static let releasePacketTransportIPv4 = "35.194.216.98"

  public let ipv6Enabled: Bool
  public let bypassPrivateNetworks: Bool
  public let directIPv4Hosts: [String]
  public let mtu: UInt16
  public let systemProxyPort: UInt16?

  public init(
    ipv6Enabled: Bool,
    bypassPrivateNetworks: Bool = true,
    directIPv4Hosts: [String] = [],
    mtu: UInt16 = 1_500,
    systemProxyPort: UInt16? = nil
  ) throws {
    guard mtu >= Self.minimumMTU, mtu <= Self.maximumMTU,
      systemProxyPort != 0,
      directIPv4Hosts.isEmpty
        || directIPv4Hosts == [Self.releasePacketTransportIPv4]
    else {
      throw ProtocolValidationError.invalidTunnelOptions
    }
    self.ipv6Enabled = ipv6Enabled
    self.bypassPrivateNetworks = bypassPrivateNetworks
    self.directIPv4Hosts = directIPv4Hosts
    self.mtu = mtu
    self.systemProxyPort = systemProxyPort
  }

  private enum CodingKeys: String, CodingKey {
    case ipv6Enabled = "ipv6_enabled"
    case bypassPrivateNetworks = "bypass_private_networks"
    case directIPv4Hosts = "direct_ipv4_hosts"
    case mtu
    case systemProxyPort = "system_proxy_port"
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      ipv6Enabled: container.decode(Bool.self, forKey: .ipv6Enabled),
      bypassPrivateNetworks: container.decode(Bool.self, forKey: .bypassPrivateNetworks),
      directIPv4Hosts: container.decode([String].self, forKey: .directIPv4Hosts),
      mtu: container.decode(UInt16.self, forKey: .mtu),
      systemProxyPort: container.decodeIfPresent(UInt16.self, forKey: .systemProxyPort)
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(ipv6Enabled, forKey: .ipv6Enabled)
    try container.encode(bypassPrivateNetworks, forKey: .bypassPrivateNetworks)
    try container.encode(directIPv4Hosts, forKey: .directIPv4Hosts)
    try container.encode(mtu, forKey: .mtu)
    try container.encodeIfPresent(systemProxyPort, forKey: .systemProxyPort)
  }
}

public struct ConfigurationDescriptor: Codable, Equatable, Sendable {
  public let slot: ConfigurationSlot
  public let tunnelOptions: TunnelNetworkOptions?
  public let credentialAudience: CredentialAudience
  public let installationID: UUID
  public let epoch: UInt64
  public let generation: UInt64
  public let byteCount: UInt64
  public let sha256: SHA256Digest
  /// Product identity digest covering the exact bounded runtime configuration,
  /// credential-slot references, mode, and mode-specific network options.
  /// This is intentionally distinct from `sha256`, which authenticates the
  /// exact in-memory runtime configuration bytes.
  public let identitySHA256: SHA256Digest
  /// Secret-free, closed injection instructions bound by identitySHA256.
  public let credentialSlots: [CredentialSlot]

  public init(
    slot: ConfigurationSlot,
    tunnelOptions: TunnelNetworkOptions?,
    credentialAudience: CredentialAudience,
    installationID: UUID,
    epoch: UInt64,
    generation: UInt64,
    byteCount: UInt64,
    sha256: SHA256Digest,
    identitySHA256: SHA256Digest? = nil,
    credentialSlots: [CredentialSlot] = []
  ) throws {
    guard (slot == .tunnel) == (tunnelOptions != nil) else {
      throw ProtocolValidationError.invalidTunnelOptions
    }
    guard epoch > 0 else {
      throw ProtocolValidationError.invalidEpoch
    }
    guard generation > 0 else {
      throw ProtocolValidationError.invalidGeneration
    }
    guard byteCount > 0, byteCount <= NativeProtocolConstants.maximumConfigurationBytes else {
      throw ProtocolValidationError.invalidByteCount
    }
    self.slot = slot
    self.tunnelOptions = tunnelOptions
    self.credentialAudience = credentialAudience
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
    self.byteCount = byteCount
    self.sha256 = sha256
    self.identitySHA256 = identitySHA256 ?? sha256
    guard credentialSlots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw ProtocolValidationError.invalidDigest
    }
    self.credentialSlots = credentialSlots
  }

  private enum CodingKeys: String, CodingKey {
    case slot
    case tunnelOptions
    case credentialAudience
    case installationID
    case epoch
    case generation
    case byteCount
    case sha256
    case identitySHA256
    case credentialSlots
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      slot: container.decode(ConfigurationSlot.self, forKey: .slot),
      tunnelOptions: container.decodeIfPresent(
        TunnelNetworkOptions.self,
        forKey: .tunnelOptions
      ),
      credentialAudience: container.decode(
        CredentialAudience.self,
        forKey: .credentialAudience
      ),
      installationID: container.decode(UUID.self, forKey: .installationID),
      epoch: container.decode(UInt64.self, forKey: .epoch),
      generation: container.decode(UInt64.self, forKey: .generation),
      byteCount: container.decode(UInt64.self, forKey: .byteCount),
      sha256: container.decode(SHA256Digest.self, forKey: .sha256),
      identitySHA256: container.decode(SHA256Digest.self, forKey: .identitySHA256),
      credentialSlots: container.decode([CredentialSlot].self, forKey: .credentialSlots)
    )
  }
}

extension ConfigurationDescriptor {
  /// Validates one bounded in-memory configuration against the exact descriptor
  /// before it crosses an engine-owner boundary. This function performs no I/O
  /// and never logs or returns the configuration bytes.
  public func validateConfigurationBytes(_ configuration: Data) throws {
    guard !configuration.isEmpty else {
      throw ConfigurationBytesValidationError.empty
    }
    guard UInt64(configuration.count) <= NativeProtocolConstants.maximumConfigurationBytes else {
      throw ConfigurationBytesValidationError.tooLarge(
        actual: UInt64(configuration.count),
        maximum: NativeProtocolConstants.maximumConfigurationBytes
      )
    }
    let actualByteCount = UInt64(configuration.count)
    guard byteCount == actualByteCount else {
      throw ConfigurationBytesValidationError.byteCountMismatch(
        expected: byteCount,
        actual: actualByteCount
      )
    }
    let actualDigest = SHA256.hash(data: configuration)
      .map { String(format: "%02x", $0) }
      .joined()
    guard sha256.hex == actualDigest else {
      throw ConfigurationBytesValidationError.digestMismatch(
        expected: sha256.hex,
        actual: actualDigest
      )
    }
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: configuration, options: [])
    } catch {
      throw ConfigurationBytesValidationError.invalidJSON
    }
    guard let root = value as? [String: Any] else {
      throw ConfigurationBytesValidationError.invalidJSON
    }
    if slot == .localProxy {
      try Self.validateLocalProxyConfiguration(root)
    } else {
      try Self.validateLANConfiguration(root)
    }
  }

  static func validateLocalProxyConfiguration(_ root: [String: Any]) throws {
    try validateLANConfiguration(root)
    guard let inbounds = root["inbounds"] as? [[String: Any]], (1...2).contains(inbounds.count),
      inbounds.allSatisfy({
        $0["type"] as? String == "mixed"
          && ["cfw-system-proxy", "cfw-lan-proxy"].contains($0["tag"] as? String ?? "")
      }),
      inbounds.filter({ $0["tag"] as? String == "cfw-system-proxy" }).count == 1,
      let inbound = inbounds.first(where: { $0["tag"] as? String == "cfw-system-proxy" }),
      inbound["type"] as? String == "mixed",
      inbound["tag"] as? String == "cfw-system-proxy",
      inbound["listen"] as? String == "127.0.0.1",
      let port = inbound["listen_port"] as? NSNumber,
      CFGetTypeID(port) != CFBooleanGetTypeID(),
      port.doubleValue.rounded() == port.doubleValue,
      (1...65535).contains(port.doubleValue)
    else { throw NativeBridgeProtocolError.invalidConfiguration }
    if let systemProxy = inbound["set_system_proxy"] {
      guard let value = systemProxy as? NSNumber,
        CFGetTypeID(value) == CFBooleanGetTypeID(), !value.boolValue
      else { throw NativeBridgeProtocolError.invalidConfiguration }
    }
  }
}
