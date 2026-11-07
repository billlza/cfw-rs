import CFWSharedProtocol
import Foundation

private struct Installed40019ProxySnapshotRequest: Encodable, Sendable {
  let schemaVersion: UInt16 = 5
  let requestID: RequestID
  let command: NativeCommand

  init(requestID: RequestID) throws {
    self.requestID = requestID
    command = try NativeCommand(kind: .snapshot)
  }
}

private struct Installed40019ProxySnapshotResponse: Decodable, Sendable {
  let schemaVersion: UInt16
  let requestID: RequestID
  let result: CommandResult?
  let failure: EngineFailure?

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try container.decode(UInt16.self, forKey: .schemaVersion)
    guard schemaVersion == 5 else {
      throw ProtocolValidationError.unsupportedSchemaVersion(schemaVersion)
    }
    requestID = try container.decode(RequestID.self, forKey: .requestID)
    result = try container.decodeIfPresent(CommandResult.self, forKey: .result)
    failure = try container.decodeIfPresent(EngineFailure.self, forKey: .failure)
    guard (result != nil) != (failure != nil) else {
      throw ProtocolValidationError.invalidResponse
    }
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case requestID
    case result
    case failure
  }
}

enum Installed40019ProxySnapshotCodec {
  static func encodeRequest(requestID: RequestID) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(Installed40019ProxySnapshotRequest(requestID: requestID))
    guard !data.isEmpty, data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw ProtocolValidationError.messageTooLarge(
        actual: data.count, maximum: NativeProtocolConstants.maximumMessageBytes)
    }
    return data
  }

  static func decodeResponse(_ data: Data) throws -> (
    requestID: RequestID, result: CommandResult?, failure: EngineFailure?
  ) {
    guard !data.isEmpty, data.count <= NativeProtocolConstants.maximumMessageBytes else {
      throw ProtocolValidationError.messageTooLarge(
        actual: data.count, maximum: NativeProtocolConstants.maximumMessageBytes)
    }
    let response = try JSONDecoder().decode(Installed40019ProxySnapshotResponse.self, from: data)
    if let result = response.result {
      guard result.kind == .snapshot,
        let snapshot = result.snapshot,
        snapshot.mode != .tunnel
      else { throw ProtocolValidationError.invalidResponse }
    }
    return (response.requestID, response.result, response.failure)
  }
}
