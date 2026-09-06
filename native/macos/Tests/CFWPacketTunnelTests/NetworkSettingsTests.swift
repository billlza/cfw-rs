import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWPacketTunnel

private struct TunnelAddressPlanContract: Decodable {
  let schemaVersion: UInt8
  let ipv4Address: String
  let ipv4PrefixLength: UInt8
  let ipv4DnsPeer: String
  let ipv6Address: String
  let ipv6PrefixLength: UInt8
  let ipv6DnsPeer: String
}

private enum AddressContractTestError: Error {
  case invalidAddress(String)
}

private func addressBytes(_ address: String, family: Int32, count: Int) throws -> [UInt8] {
  var bytes = [UInt8](repeating: 0, count: count)
  let result = address.withCString { source in
    bytes.withUnsafeMutableBytes { destination in
      inet_pton(family, source, destination.baseAddress)
    }
  }
  guard result == 1 else {
    throw AddressContractTestError.invalidAddress(address)
  }
  return bytes
}

private func prefixContains(_ prefix: [UInt8], length: UInt8, address: [UInt8]) -> Bool {
  guard prefix.count == address.count, Int(length) <= prefix.count * 8 else {
    return false
  }
  let wholeBytes = Int(length) / 8
  guard prefix.prefix(wholeBytes) == address.prefix(wholeBytes) else {
    return false
  }
  let remainingBits = Int(length) % 8
  guard remainingBits > 0 else {
    return true
  }
  let mask = UInt8.max << UInt8(8 - remainingBits)
  return prefix[wholeBytes] & mask == address[wholeBytes] & mask
}

private func descriptor(
  ipv6Enabled: Bool,
  bypassPrivateNetworks: Bool = true,
  directIPv4Hosts: [String] = []
) throws -> ConfigurationDescriptor {
  try ConfigurationDescriptor(
    slot: .tunnel,
    tunnelOptions: TunnelNetworkOptions(
      ipv6Enabled: ipv6Enabled,
      bypassPrivateNetworks: bypassPrivateNetworks,
      directIPv4Hosts: directIPv4Hosts,
      mtu: 1_500
    ),
    credentialAudience: CredentialAudience(
      profileID: UUID(),
      profileDigest: SHA256Digest(hex: String(repeating: "ee", count: 32))),
    installationID: UUID(),
    epoch: 1,
    generation: 1,
    byteCount: 2,
    sha256: SHA256Digest(hex: String(repeating: "00", count: 32))
  )
}

@Test func sourceOwnedDirectIPv4HostBecomesAnExact32ExcludedRoute() throws {
  let settings = PacketTunnelProvider.networkSettings(
    descriptor: try descriptor(
      ipv6Enabled: true,
      bypassPrivateNetworks: false,
      directIPv4Hosts: [TunnelNetworkOptions.releasePacketTransportIPv4]
    )
  )
  let routes = settings.ipv4Settings?.excludedRoutes?.map {
    "\($0.destinationAddress)/\($0.destinationSubnetMask)"
  }
  #expect(routes == ["35.194.216.98/255.255.255.255"])
}

@Test func privateNetworkBypassIsBoundToNetworkSettings() throws {
  let bypassed = PacketTunnelProvider.networkSettings(
    descriptor: try descriptor(ipv6Enabled: true, bypassPrivateNetworks: true)
  )
  let ipv4Exclusions = Set(
    bypassed.ipv4Settings?.excludedRoutes?.map {
      "\($0.destinationAddress)/\($0.destinationSubnetMask)"
    } ?? []
  )
  #expect(
    ipv4Exclusions == [
      "127.0.0.0/255.0.0.0",
      "10.0.0.0/255.0.0.0",
      "172.16.0.0/255.240.0.0",
      "192.168.0.0/255.255.0.0",
      "169.254.0.0/255.255.0.0",
      "224.0.0.0/240.0.0.0",
      "255.255.255.255/255.255.255.255",
    ]
  )
  let ipv6Exclusions = Set(
    bypassed.ipv6Settings?.excludedRoutes?.map {
      "\($0.destinationAddress)/\($0.destinationNetworkPrefixLength.uint16Value)"
    } ?? []
  )
  #expect(ipv6Exclusions == ["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"])
  #expect(!ipv4Exclusions.contains("198.18.0.0/255.254.0.0"))

  let captured = PacketTunnelProvider.networkSettings(
    descriptor: try descriptor(ipv6Enabled: true, bypassPrivateNetworks: false)
  )
  #expect(captured.ipv4Settings?.excludedRoutes?.isEmpty ?? true)
  #expect(captured.ipv6Settings?.excludedRoutes?.isEmpty ?? true)
}

@Test func ipv4OnlyProjectionDoesNotPublishIPv6RoutesOrResolver() throws {
  let settings = PacketTunnelProvider.networkSettings(
    descriptor: try descriptor(ipv6Enabled: false)
  )

  #expect(settings.ipv4Settings?.addresses == ["198.18.64.1"])
  #expect(settings.ipv4Settings?.subnetMasks == ["255.255.255.252"])
  #expect(settings.ipv6Settings == nil)
  #expect(settings.dnsSettings?.servers == ["198.18.64.2"])
  #expect(settings.dnsSettings?.matchDomains == [""])
  #expect(settings.dnsSettings?.matchDomainsNoSearch == true)
  #expect(settings.mtu?.uint16Value == 1_500)
}

@Test func dualStackProjectionUsesTheMatching126IPv6Prefix() throws {
  let settings = PacketTunnelProvider.networkSettings(
    descriptor: try descriptor(ipv6Enabled: true)
  )

  #expect(settings.ipv6Settings?.addresses == ["2001:2:0:64::1"])
  #expect(settings.ipv6Settings?.networkPrefixLengths.map(\.uint16Value) == [126])
  #expect(
    settings.dnsSettings?.servers == ["198.18.64.2", "2001:2:0:64::2"]
  )
}

@Test func providerDNSPeersAreInsideTheirTunnelSubnetAndOutsideEveryBypassRoute() throws {
  let ipv4Interface = try addressBytes(TunnelAddressPlan.ipv4Address, family: AF_INET, count: 4)
  let ipv4Peer = try addressBytes(TunnelAddressPlan.ipv4DNSPeer, family: AF_INET, count: 4)
  #expect(
    prefixContains(
      ipv4Interface,
      length: TunnelAddressPlan.ipv4PrefixLength,
      address: ipv4Peer
    )
  )
  for (network, length) in [
    ("127.0.0.0", UInt8(8)),
    ("10.0.0.0", UInt8(8)),
    ("172.16.0.0", UInt8(12)),
    ("192.168.0.0", UInt8(16)),
    ("169.254.0.0", UInt8(16)),
    ("224.0.0.0", UInt8(4)),
    ("255.255.255.255", UInt8(32)),
  ] {
    #expect(
      !prefixContains(
        try addressBytes(network, family: AF_INET, count: 4),
        length: length,
        address: ipv4Peer
      )
    )
  }

  let ipv6Interface = try addressBytes(TunnelAddressPlan.ipv6Address, family: AF_INET6, count: 16)
  let ipv6Peer = try addressBytes(TunnelAddressPlan.ipv6DNSPeer, family: AF_INET6, count: 16)
  #expect(
    prefixContains(
      ipv6Interface,
      length: TunnelAddressPlan.ipv6PrefixLength,
      address: ipv6Peer
    )
  )
  for (network, length) in [
    ("::1", UInt8(128)),
    ("fc00::", UInt8(7)),
    ("fe80::", UInt8(10)),
    ("ff00::", UInt8(8)),
  ] {
    #expect(
      !prefixContains(
        try addressBytes(network, family: AF_INET6, count: 16),
        length: length,
        address: ipv6Peer
      )
    )
  }
}

@Test func swiftTunnelAddressPlanMatchesTheCrossLanguageContract() throws {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let contractURL =
    repositoryRoot
    .appendingPathComponent("contracts", isDirectory: true)
    .appendingPathComponent("tunnel-address-plan-v1.json")
  let contract = try JSONDecoder().decode(
    TunnelAddressPlanContract.self,
    from: Data(contentsOf: contractURL)
  )

  #expect(contract.schemaVersion == TunnelAddressPlan.schemaVersion)
  #expect(contract.ipv4Address == TunnelAddressPlan.ipv4Address)
  #expect(contract.ipv4PrefixLength == TunnelAddressPlan.ipv4PrefixLength)
  #expect(contract.ipv4DnsPeer == TunnelAddressPlan.ipv4DNSPeer)
  #expect(contract.ipv6Address == TunnelAddressPlan.ipv6Address)
  #expect(contract.ipv6PrefixLength == TunnelAddressPlan.ipv6PrefixLength)
  #expect(contract.ipv6DnsPeer == TunnelAddressPlan.ipv6DNSPeer)
}
