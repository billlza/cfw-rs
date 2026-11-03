public struct SHA256Digest: Codable, Hashable, Sendable {
  public let hex: String

  public init(hex: String) throws {
    guard hex == hex.lowercased(), hex.utf8.count == 64,
      hex.utf8.allSatisfy({ byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      })
    else {
      throw ProtocolValidationError.invalidDigest
    }
    self.hex = hex
  }

  init(validatedHex: String) {
    hex = validatedHex
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    try self.init(hex: container.decode(String.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(hex)
  }
}
