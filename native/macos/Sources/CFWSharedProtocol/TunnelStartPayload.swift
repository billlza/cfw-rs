import CryptoKit
import Foundation

public enum TunnelStartPayloadError: Error, Equatable, Sendable {
  case malformed
  case nonCanonicalDescriptor
  case descriptorMismatch
  case configurationTooLarge(Int)
  case credentialPayloadTooLarge(Int)
  case credentialBindingMismatch
  case messageTooLarge(Int)
}

extension TunnelStartPayloadError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .malformed:
      return "Tunnel start payload is malformed."
    case .nonCanonicalDescriptor:
      return "Tunnel start descriptor is not canonically encoded."
    case .descriptorMismatch:
      return "Tunnel start configuration does not match its descriptor."
    case .configurationTooLarge(let count):
      return "Tunnel start configuration has \(count) bytes and exceeds the product limit."
    case .credentialPayloadTooLarge(let count):
      return "Tunnel credential payload has \(count) bytes and exceeds the product limit."
    case .credentialBindingMismatch:
      return "Tunnel credentials do not match the descriptor credential slots."
    case .messageTooLarge(let count):
      return "Tunnel start payload has \(count) bytes and exceeds the public channel limit."
    }
  }
}

public struct TunnelStartPayload: Sendable {
  public let descriptor: ConfigurationDescriptor
  public private(set) var configuration: Data
  public private(set) var credentialPayload: Data?

  fileprivate init(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?
  ) {
    self.descriptor = descriptor
    self.configuration = configuration
    self.credentialPayload = credentialPayload
  }

  public mutating func erase() {
    configuration.resetBytes(in: configuration.startIndex..<configuration.endIndex)
    configuration.removeAll(keepingCapacity: false)
    if var credentials = credentialPayload {
      credentialPayload = nil
      credentials.resetBytes(in: credentials.startIndex..<credentials.endIndex)
      credentials.removeAll(keepingCapacity: false)
    }
  }
}

/// Canonical framing used as the single value in `startVPNTunnel(options:)`.
/// The entire encoded value, including descriptor and credentials, is bounded
/// to the same 1 MiB limit enforced by the native XPC protocols.
public enum TunnelStartPayloadCodec {
  private static let magic = Data("CFWTUN01".utf8)
  private static let schemaVersion: UInt16 = 1
  private static let headerBytes = 24
  private static let maximumDescriptorBytes = 64 * 1_024
  private static let maximumJSONDepth = 64
  public static let maximumCredentialPayloadBytes = 512 * 1_024

  public static func encode(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?
  ) throws -> Data {
    try validate(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: credentialPayload
    )
    let descriptorData = try canonicalDescriptor(descriptor)
    guard descriptorData.count <= maximumDescriptorBytes else {
      throw TunnelStartPayloadError.malformed
    }
    var output = Data()
    output.reserveCapacity(
      headerBytes + descriptorData.count + configuration.count + (credentialPayload?.count ?? 0)
    )
    output.append(magic)
    append(schemaVersion, to: &output)
    append(UInt16(0), to: &output)
    append(try checkedUInt32(descriptorData.count), to: &output)
    append(try checkedUInt32(configuration.count), to: &output)
    append(try checkedUInt32(credentialPayload?.count ?? 0), to: &output)
    output.append(descriptorData)
    output.append(configuration)
    if let credentialPayload {
      output.append(credentialPayload)
    }
    guard output.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw TunnelStartPayloadError.messageTooLarge(output.count)
    }
    return output
  }

  public static func decode(_ data: Data) throws -> TunnelStartPayload {
    guard data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw TunnelStartPayloadError.messageTooLarge(data.count)
    }
    guard data.count >= headerBytes,
      data.prefix(magic.count) == magic
    else {
      throw TunnelStartPayloadError.malformed
    }
    var cursor = magic.count
    guard try readUInt16(data, cursor: &cursor) == schemaVersion,
      try readUInt16(data, cursor: &cursor) == 0
    else {
      throw TunnelStartPayloadError.malformed
    }
    let descriptorCount = Int(try readUInt32(data, cursor: &cursor))
    let configurationCount = Int(try readUInt32(data, cursor: &cursor))
    let credentialCount = Int(try readUInt32(data, cursor: &cursor))
    guard descriptorCount > 0, descriptorCount <= maximumDescriptorBytes,
      configurationCount > 0,
      configurationCount <= Int(NativeProtocolConstants.maximumConfigurationBytes),
      credentialCount <= maximumCredentialPayloadBytes
    else {
      throw TunnelStartPayloadError.malformed
    }
    let payloadCount = try descriptorCount.addingChecked(configurationCount)
      .addingChecked(credentialCount)
    guard cursor.addingReportingOverflow(payloadCount).overflow == false,
      cursor + payloadCount == data.count
    else {
      throw TunnelStartPayloadError.malformed
    }
    let descriptorData = data[cursor..<(cursor + descriptorCount)]
    cursor += descriptorCount
    let configuration = Data(data[cursor..<(cursor + configurationCount)])
    cursor += configurationCount
    let credentialPayload =
      credentialCount == 0
      ? nil
      : Data(data[cursor..<(cursor + credentialCount)])
    let descriptor: ConfigurationDescriptor
    do {
      descriptor = try JSONDecoder().decode(ConfigurationDescriptor.self, from: descriptorData)
    } catch {
      throw TunnelStartPayloadError.malformed
    }
    guard try canonicalDescriptor(descriptor) == descriptorData else {
      throw TunnelStartPayloadError.nonCanonicalDescriptor
    }
    try validate(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: credentialPayload
    )
    return TunnelStartPayload(
      descriptor: descriptor,
      configuration: configuration,
      credentialPayload: credentialPayload
    )
  }

  private static func validate(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?
  ) throws {
    guard descriptor.slot == .tunnel else {
      throw TunnelStartPayloadError.descriptorMismatch
    }
    guard !configuration.isEmpty,
      configuration.count <= Int(NativeProtocolConstants.maximumConfigurationBytes)
    else {
      throw TunnelStartPayloadError.configurationTooLarge(configuration.count)
    }
    guard UInt64(configuration.count) == descriptor.byteCount,
      SHA256.hash(data: configuration).hexDigest == descriptor.sha256.hex,
      let json = try? JSONSerialization.jsonObject(with: configuration),
      json is [String: Any],
      validateJSONDepth(json, depth: 1)
    else {
      throw TunnelStartPayloadError.descriptorMismatch
    }
    let credentialCount = credentialPayload?.count ?? 0
    guard credentialCount <= maximumCredentialPayloadBytes else {
      throw TunnelStartPayloadError.credentialPayloadTooLarge(credentialCount)
    }
    guard descriptor.credentialSlots.isEmpty == (credentialPayload == nil) else {
      throw TunnelStartPayloadError.credentialBindingMismatch
    }
  }

  private static func validateJSONDepth(_ value: Any, depth: Int) -> Bool {
    guard depth <= maximumJSONDepth else {
      return false
    }
    if let dictionary = value as? [String: Any] {
      return dictionary.values.allSatisfy { validateJSONDepth($0, depth: depth + 1) }
    }
    if let array = value as? [Any] {
      return array.allSatisfy { validateJSONDepth($0, depth: depth + 1) }
    }
    return value is String || value is NSNumber || value is NSNull
  }

  private static func canonicalDescriptor(_ descriptor: ConfigurationDescriptor) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(descriptor)
  }

  private static func append<Integer: FixedWidthInteger>(
    _ value: Integer,
    to output: inout Data
  ) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }

  private static func readUInt16(_ data: Data, cursor: inout Int) throws -> UInt16 {
    try read(data, cursor: &cursor, as: UInt16.self)
  }

  private static func readUInt32(_ data: Data, cursor: inout Int) throws -> UInt32 {
    try read(data, cursor: &cursor, as: UInt32.self)
  }

  private static func read<Integer: FixedWidthInteger>(
    _ data: Data,
    cursor: inout Int,
    as: Integer.Type
  ) throws -> Integer {
    let width = MemoryLayout<Integer>.size
    guard cursor <= data.count, width <= data.count - cursor else {
      throw TunnelStartPayloadError.malformed
    }
    var encoded: Integer = 0
    _ = withUnsafeMutableBytes(of: &encoded) { destination in
      data.copyBytes(to: destination, from: cursor..<(cursor + width))
    }
    cursor += width
    return Integer(bigEndian: encoded)
  }

  private static func checkedUInt32(_ value: Int) throws -> UInt32 {
    guard let value = UInt32(exactly: value) else {
      throw TunnelStartPayloadError.malformed
    }
    return value
  }
}

extension Digest {
  fileprivate var hexDigest: String {
    map { String(format: "%02x", $0) }.joined()
  }
}

extension Int {
  fileprivate func addingChecked(_ other: Int) throws -> Int {
    let result = addingReportingOverflow(other)
    guard !result.overflow else {
      throw TunnelStartPayloadError.malformed
    }
    return result.partialValue
  }
}
