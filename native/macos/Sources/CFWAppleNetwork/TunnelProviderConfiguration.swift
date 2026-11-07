import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension

extension ConfigurationDescriptor {
  func providerConfiguration() throws -> [String: Any] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let credentialSlotsData = try encoder.encode(credentialSlots)
    return [
      "schemaVersion": String(NativeProtocolConstants.schemaVersion),
      "slot": slot.rawValue,
      "installationID": installationID.uuidString.lowercased(),
      "credentialProfileID": credentialAudience.profileID.uuidString.lowercased(),
      "credentialProfileDigest": credentialAudience.profileDigest.hex,
      "epoch": String(epoch),
      "generation": String(generation),
      "byteCount": String(byteCount),
      "sha256": sha256.hex,
      "identitySha256": identitySHA256.hex,
      "credentialSlots": credentialSlotsData,
    ].merging(tunnelProviderConfiguration) { _, new in new }
  }

  private var tunnelProviderConfiguration: [String: Any] {
    guard let tunnelOptions else {
      return [:]
    }
    var values: [String: Any] = [
      "ipv6Enabled": tunnelOptions.ipv6Enabled ? "true" : "false",
      "bypassPrivateNetworks": tunnelOptions.bypassPrivateNetworks ? "true" : "false",
      "directIPv4Hosts": tunnelOptions.directIPv4Hosts,
      "mtu": String(tunnelOptions.mtu),
    ]
    if let port = tunnelOptions.systemProxyPort { values["systemProxyPort"] = String(port) }
    return values
  }
}

extension NETunnelProviderManager {
  /// Reads persisted preferences for observation/recovery. Version 6 used the same
  /// descriptor fields before Local Proxy was introduced. Preserve its original
  /// identity while new preference writes and Provider starts require version 7.
  func configurationDescriptor() throws -> ConfigurationDescriptor {
    guard
      let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?
        .providerConfiguration,
      let schemaVersionValue = configuration["schemaVersion"] as? String,
      let schemaVersion = UInt16(schemaVersionValue),
      schemaVersion == 6 || schemaVersion == NativeProtocolConstants.schemaVersion,
      let slotRawValue = configuration["slot"] as? String,
      let slot = ConfigurationSlot(rawValue: slotRawValue),
      slot == .tunnel,
      let tunnelOptions = try Self.decodeTunnelOptions(
        configuration,
        slot: slot
      ),
      let installationIDValue = configuration["installationID"] as? String,
      let installationID = UUID(uuidString: installationIDValue),
      installationIDValue == installationID.uuidString.lowercased(),
      let credentialProfileIDValue = configuration["credentialProfileID"] as? String,
      let credentialProfileID = UUID(uuidString: credentialProfileIDValue),
      credentialProfileIDValue == credentialProfileID.uuidString.lowercased(),
      let credentialProfileDigest = configuration["credentialProfileDigest"] as? String,
      let epochValue = configuration["epoch"] as? String,
      let epoch = UInt64(epochValue),
      let generationValue = configuration["generation"] as? String,
      let generation = UInt64(generationValue),
      let byteCountValue = configuration["byteCount"] as? String,
      let byteCount = UInt64(byteCountValue),
      let digest = configuration["sha256"] as? String,
      let identityDigest = configuration["identitySha256"] as? String,
      let credentialSlotsData = configuration["credentialSlots"] as? Data,
      let credentialSlots = try? JSONDecoder().decode(
        [CredentialSlot].self,
        from: credentialSlotsData
      )
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    let descriptor = try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: tunnelOptions,
      credentialAudience: CredentialAudience(
        profileID: credentialProfileID,
        profileDigest: try SHA256Digest(hex: credentialProfileDigest)
      ),
      installationID: installationID,
      epoch: epoch,
      generation: generation,
      byteCount: byteCount,
      sha256: SHA256Digest(hex: digest),
      identitySHA256: SHA256Digest(hex: identityDigest),
      credentialSlots: credentialSlots
    )
    var canonical = try descriptor.providerConfiguration()
    canonical["schemaVersion"] = String(schemaVersion)
    guard
      NSDictionary(dictionary: configuration).isEqual(
        to: canonical
      )
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return descriptor
  }

  private static func decodeTunnelOptions(
    _ configuration: [String: Any],
    slot: ConfigurationSlot
  ) throws -> TunnelNetworkOptions? {
    guard slot == .tunnel else {
      return nil
    }
    guard let ipv6Value = configuration["ipv6Enabled"] as? String,
      let bypassPrivateNetworksValue = configuration["bypassPrivateNetworks"] as? String,
      let directIPv4Hosts = configuration["directIPv4Hosts"] as? [String],
      let mtuValue = configuration["mtu"] as? String,
      let mtu = UInt16(mtuValue)
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    let ipv6Enabled: Bool
    switch ipv6Value {
    case "true":
      ipv6Enabled = true
    case "false":
      ipv6Enabled = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    let bypassPrivateNetworks: Bool
    switch bypassPrivateNetworksValue {
    case "true":
      bypassPrivateNetworks = true
    case "false":
      bypassPrivateNetworks = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    let systemProxyPort: UInt16?
    if let value = configuration["systemProxyPort"] {
      guard let text = value as? String, let port = UInt16(text), port > 0,
        text == String(port)
      else { throw AppleNetworkError.providerResponseMismatch }
      systemProxyPort = port
    } else {
      systemProxyPort = nil
    }
    return try TunnelNetworkOptions(
      ipv6Enabled: ipv6Enabled,
      bypassPrivateNetworks: bypassPrivateNetworks,
      directIPv4Hosts: directIPv4Hosts,
      mtu: mtu,
      systemProxyPort: systemProxyPort
    )
  }
}
