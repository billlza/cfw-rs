import Foundation

enum TunnelAddressPlan {
  static let schemaVersion: UInt8 = 1
  static let ipv4Address = "198.18.64.1"
  static let ipv4SubnetMask = "255.255.255.252"
  static let ipv4PrefixLength: UInt8 = 30
  static let ipv4DNSPeer = "198.18.64.2"
  static let ipv6Address = "2001:2:0:64::1"
  static let ipv6PrefixLength: UInt8 = 126
  static let ipv6DNSPeer = "2001:2:0:64::2"
}
