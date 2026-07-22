import Darwin
import Foundation

public enum IPPacketError: Error, Equatable, Sendable {
  case emptyPacket
  case unsupportedVersion(UInt8)
}

public enum IPPacketFamily: Int32, Equatable, Sendable {
  case ipv4 = 2
  case ipv6 = 30

  public static func infer(from packet: Data) throws -> IPPacketFamily {
    guard let firstByte = packet.first else {
      throw IPPacketError.emptyPacket
    }
    switch firstByte >> 4 {
    case 4:
      return .ipv4
    case 6:
      return .ipv6
    case let version:
      throw IPPacketError.unsupportedVersion(version)
    }
  }

  public var addressFamily: NSNumber {
    NSNumber(value: rawValue)
  }
}
