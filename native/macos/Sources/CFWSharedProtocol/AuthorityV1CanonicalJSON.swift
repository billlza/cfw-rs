import CoreFoundation
import Foundation

extension AuthorityV1Codec {
  static func checkEnvelopeSize(_ data: Data) throws {
    guard !data.isEmpty else { throw AuthorityV1ValidationError.malformedEnvelope }
    guard data.count <= AuthorityV1Limits.maximumEnvelopeBytes else {
      throw AuthorityV1ValidationError.messageTooLarge(
        actual: data.count, maximum: AuthorityV1Limits.maximumEnvelopeBytes)
    }
  }

  static func parseCanonicalObject(_ data: Data) throws -> [String: Any] {
    let value: Any
    do { value = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) } catch
    { throw AuthorityV1ValidationError.malformedEnvelope }
    try validateShape(value, depth: 1)
    let object = try dictionary(value)
    guard try canonicalData(object) == data else {
      throw AuthorityV1ValidationError.noncanonicalRepresentation
    }
    return object
  }

  static func canonicalData(_ object: Any) throws -> Data {
    try validateShape(object, depth: 1)
    guard JSONSerialization.isValidJSONObject(object) else {
      throw AuthorityV1ValidationError.invalidType
    }
    let data: Data
    do {
      data = try JSONSerialization.data(
        withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    } catch { throw AuthorityV1ValidationError.invalidType }
    guard data.count <= AuthorityV1Limits.maximumEnvelopeBytes else {
      throw AuthorityV1ValidationError.messageTooLarge(
        actual: data.count, maximum: AuthorityV1Limits.maximumEnvelopeBytes)
    }
    return data
  }

  static func encodedObject<T: AuthorityV1WireModel>(_ value: T) throws -> Any {
    try value.validateAuthorityV1()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(value)
    do { return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) } catch {
      throw AuthorityV1ValidationError.invalidType
    }
  }

  static func decodeObject<T: AuthorityV1WireModel>(_ type: T.Type, _ object: Any)
    throws -> T
  {
    let decoded: T
    do { decoded = try JSONDecoder().decode(type, from: canonicalData(object)) } catch let error
      as AuthorityV1ValidationError
    { throw error } catch { throw AuthorityV1ValidationError.invalidType }
    try decoded.validateAuthorityV1()
    return decoded
  }

  fileprivate static func validateShape(_ value: Any, depth: Int) throws {
    guard depth <= maximumNestingDepth else { throw AuthorityV1ValidationError.boundViolation }
    switch value {
    case let object as [String: Any]:
      for child in object.values { try validateShape(child, depth: depth + 1) }
    case let values as [Any]:
      for child in values { try validateShape(child, depth: depth + 1) }
    case is String, is NSNull:
      return
    case let number as NSNumber:
      if CFGetTypeID(number) == CFBooleanGetTypeID() { return }
      let text = number.stringValue
      guard !text.contains("."), !text.contains("e"), !text.contains("E") else {
        throw AuthorityV1ValidationError.invalidType
      }
    default:
      throw AuthorityV1ValidationError.invalidType
    }
  }

  static func dictionary(_ value: Any?) throws -> [String: Any] {
    guard let object = value as? [String: Any] else {
      throw AuthorityV1ValidationError.invalidType
    }
    return object
  }

  static func exactKeys(_ object: [String: Any], _ expected: Set<String>) throws {
    guard Set(object.keys) == expected else { throw AuthorityV1ValidationError.malformedEnvelope }
  }

  static func identifier(_ value: Any?) throws -> AuthorityIdentifier {
    guard let text = value as? String, text == text.lowercased(),
      let uuid = UUID(uuidString: text), uuid.uuidString.lowercased() == text
    else { throw AuthorityV1ValidationError.invalidIdentifier }
    return AuthorityIdentifier(uuid)
  }

  static func unsigned<T: FixedWidthInteger & UnsignedInteger>(
    _ value: Any?, as: T.Type
  ) throws -> T {
    guard let number = value as? NSNumber,
      CFGetTypeID(number) != CFBooleanGetTypeID()
    else { throw AuthorityV1ValidationError.invalidType }
    let text = number.stringValue
    guard !text.contains("."), !text.contains("e"), !text.contains("E"), let parsed = T(text)
    else { throw AuthorityV1ValidationError.invalidType }
    return parsed
  }

  static func bytes(_ value: Any?, exactCount: Int) throws -> Data {
    guard let values = value as? [Any], values.count == exactCount else {
      throw AuthorityV1ValidationError.boundViolation
    }
    return Data(try values.map { try unsigned($0, as: UInt8.self) })
  }

  static func byteArray(_ data: Data) -> [Int] { data.map(Int.init) }
}
