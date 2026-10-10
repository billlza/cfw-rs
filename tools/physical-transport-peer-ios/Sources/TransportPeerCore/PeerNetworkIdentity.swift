import Darwin
import Foundation

public struct PeerNetworkReceipt: Codable, Equatable, Sendable {
  public let interfaceName: String
  public let ipv4: String

  enum CodingKeys: String, CodingKey {
    case interfaceName = "interface_name"
    case ipv4
  }

  static let exactFields: Set<String> = ["interface_name", "ipv4"]

  public init(interfaceName: String, ipv4: String) throws {
    guard
      PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: interfaceName,
        address: ipv4
      )
    else {
      throw PeerContractError.malformed("Wi-Fi IPv4 identity")
    }
    self.interfaceName = interfaceName
    self.ipv4 = ipv4
  }
}

public enum PeerNetworkIdentity {
  public static func currentWiFiIPv4() throws -> PeerNetworkReceipt {
    var first: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&first) == 0, let first else {
      throw PeerContractError.malformed("Wi-Fi interface inventory")
    }
    defer { freeifaddrs(first) }

    let requiredFlags = UInt32(IFF_UP | IFF_RUNNING)
    var candidates = Set<String>()
    var cursor: UnsafeMutablePointer<ifaddrs>? = first
    while let entry = cursor?.pointee {
      defer { cursor = entry.ifa_next }
      guard String(cString: entry.ifa_name) == "en0",
        entry.ifa_flags & requiredFlags == requiredFlags,
        entry.ifa_flags & UInt32(IFF_LOOPBACK) == 0,
        let socketAddress = entry.ifa_addr,
        Int32(socketAddress.pointee.sa_family) == AF_INET
      else {
        continue
      }
      let ipv4Socket = UnsafeRawPointer(socketAddress).assumingMemoryBound(
        to: sockaddr_in.self
      )
      var rawAddress = ipv4Socket.pointee.sin_addr
      var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
      guard inet_ntop(AF_INET, &rawAddress, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil
      else {
        continue
      }
      guard let terminator = buffer.firstIndex(of: 0) else { continue }
      let value = String(
        decoding: buffer[..<terminator].map { UInt8(bitPattern: $0) },
        as: UTF8.self
      )
      if isControlledWiFiIPv4(interfaceName: "en0", address: value) {
        candidates.insert(value)
      }
    }
    guard candidates.count == 1, let address = candidates.first else {
      throw PeerContractError.malformed("unique Wi-Fi IPv4 identity")
    }
    return try PeerNetworkReceipt(interfaceName: "en0", ipv4: address)
  }

  public static func isControlledWiFiIPv4(
    interfaceName: String,
    address: String
  ) -> Bool {
    interfaceName == "en0" && isControlledLANIPv4(address)
  }

  public static func isControlledLANIPv4(_ address: String) -> Bool {
    var parsed = in_addr()
    guard address.withCString({ inet_pton(AF_INET, $0, &parsed) }) == 1 else {
      return false
    }
    let host = UInt32(bigEndian: parsed.s_addr)
    let first = UInt8((host >> 24) & 0xff)
    let second = UInt8((host >> 16) & 0xff)
    return first == 10
      || (first == 172 && (16...31).contains(second))
      || (first == 192 && second == 168)
  }
}
