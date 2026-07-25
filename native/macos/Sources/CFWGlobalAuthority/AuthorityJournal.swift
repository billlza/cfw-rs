import CFWSharedProtocol
import Foundation

import struct CryptoKit.SHA256

public enum AuthorityJournalLimits {
  public static let maximumRecordPayloadBytes = 64 * 1_024
  public static let maximumRecords = 4_096
  public static let maximumJournalBytes = 32 * 1_024 * 1_024
  public static let maximumHeadBytes = 1_024
}

public enum AuthorityJournalTransition: String, Codable, CaseIterable, Sendable {
  case enrollAndPrepare = "enroll_and_prepare"
  case prepare
  case bindOwner = "bind_owner"
  case ready
  case beginStop = "begin_stop"
  case ownerStopped = "owner_stopped"
  case abortPrepared = "abort_prepared"
  case revokeForConsoleChange = "revoke_for_console_change"
  case revokeForTimeout = "revoke_for_timeout"
  case globalOff = "global_off"
  case reconcileOff = "reconcile_off"
}

/// The complete persistent Authority state. Its schema deliberately has no
/// ticket, capability, configuration, credential, endpoint, or secret field.
public struct AuthorityCommittedState: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let installationID: AuthorityIdentifier
  public let epoch: UInt64
  public let generation: UInt64
  public let revision: UInt64
  public let transition: AuthorityJournalTransition
  public let state: AuthorityState
  public let operationID: AuthorityIdentifier?
  public let mode: AuthorityMode?
  public let configSHA256: SHA256Digest?
  public let leaseID: AuthorityIdentifier?
  public let ownerUID: UInt32?

  public init(
    installationID: AuthorityIdentifier,
    epoch: UInt64,
    generation: UInt64,
    revision: UInt64,
    transition: AuthorityJournalTransition,
    state: AuthorityState,
    operationID: AuthorityIdentifier?,
    mode: AuthorityMode?,
    configSHA256: SHA256Digest?,
    leaseID: AuthorityIdentifier?,
    ownerUID: UInt32?
  ) throws {
    guard epoch > 0, generation > 0, revision > 0 else {
      throw AuthorityJournalValidationError.invalidState
    }
    let hasOperation =
      operationID != nil && mode != nil && configSHA256 != nil
      && leaseID != nil && ownerUID != nil
    let hasNoOperation =
      operationID == nil && mode == nil && configSHA256 == nil
      && leaseID == nil && ownerUID == nil
    guard hasOperation || hasNoOperation else {
      throw AuthorityJournalValidationError.invalidState
    }
    guard state == .off ? hasNoOperation : true else {
      throw AuthorityJournalValidationError.invalidState
    }
    schemaVersion = 1
    self.installationID = installationID
    self.epoch = epoch
    self.generation = generation
    self.revision = revision
    self.transition = transition
    self.state = state
    self.operationID = operationID
    self.mode = mode
    self.configSHA256 = configSHA256
    self.leaseID = leaseID
    self.ownerUID = ownerUID
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case installationID = "installation_id"
    case epoch, generation, revision, transition, state
    case operationID = "operation_id"
    case mode
    case configSHA256 = "config_sha256"
    case leaseID = "lease_id"
    case ownerUID = "owner_uid"
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    guard try value.decode(UInt16.self, forKey: .schemaVersion) == 1 else {
      throw AuthorityJournalValidationError.unsupportedSchema
    }
    try self.init(
      installationID: value.decode(AuthorityIdentifier.self, forKey: .installationID),
      epoch: value.decode(UInt64.self, forKey: .epoch),
      generation: value.decode(UInt64.self, forKey: .generation),
      revision: value.decode(UInt64.self, forKey: .revision),
      transition: value.decode(AuthorityJournalTransition.self, forKey: .transition),
      state: value.decode(AuthorityState.self, forKey: .state),
      operationID: value.decodeIfPresent(AuthorityIdentifier.self, forKey: .operationID),
      mode: value.decodeIfPresent(AuthorityMode.self, forKey: .mode),
      configSHA256: value.decodeIfPresent(SHA256Digest.self, forKey: .configSHA256),
      leaseID: value.decodeIfPresent(AuthorityIdentifier.self, forKey: .leaseID),
      ownerUID: value.decodeIfPresent(UInt32.self, forKey: .ownerUID)
    )
  }
}

public struct AuthorityJournalHead: Codable, Equatable, Sendable {
  public let schemaVersion: UInt16
  public let sequence: UInt64
  public let committedLength: UInt64
  public let recordSHA256: SHA256Digest

  public init(sequence: UInt64, committedLength: UInt64, recordSHA256: SHA256Digest) throws {
    guard sequence > 0, committedLength > 0 else {
      throw AuthorityJournalValidationError.invalidHead
    }
    schemaVersion = 1
    self.sequence = sequence
    self.committedLength = committedLength
    self.recordSHA256 = recordSHA256
  }

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case sequence
    case committedLength = "committed_length"
    case recordSHA256 = "record_sha256"
  }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    guard try value.decode(UInt16.self, forKey: .schemaVersion) == 1 else {
      throw AuthorityJournalValidationError.unsupportedSchema
    }
    try self.init(
      sequence: value.decode(UInt64.self, forKey: .sequence),
      committedLength: value.decode(UInt64.self, forKey: .committedLength),
      recordSHA256: value.decode(SHA256Digest.self, forKey: .recordSHA256)
    )
  }
}

public enum AuthorityJournalValidationError: Error, Equatable, Sendable {
  case unsupportedSchema
  case journalTooLarge
  case tooManyRecords
  case recordTooLarge
  case malformedFrame
  case noncanonicalRecord
  case invalidHead
  case missingHead
  case unexpectedHead
  case interruptedHeadReplacement
  case truncated
  case trailingData
  case invalidCRC
  case invalidPayloadDigest
  case brokenHashChain
  case reordered
  case rollback
  case invalidState
}

public enum AuthorityRecoveryAction: Equatable, Sendable {
  case verifyOff
  case stopOwner
  case reattestOwner
}

public enum AuthorityRecoveryPosture: Equatable, Sendable {
  case recovering(AuthorityRecoveryAction)
  case quarantined(AuthorityJournalValidationError)
}

public struct AuthorityJournalRecovery: Equatable, Sendable {
  public let committedState: AuthorityCommittedState?
  public let head: AuthorityJournalHead?
  public let posture: AuthorityRecoveryPosture

  public var permitsStart: Bool { false }
}

public struct AuthorityJournalImage: Equatable, Sendable {
  public let journal: Data?
  public let head: Data?
  public let hasTemporaryHead: Bool

  public init(journal: Data?, head: Data?, hasTemporaryHead: Bool = false) {
    self.journal = journal
    self.head = head
    self.hasTemporaryHead = hasTemporaryHead
  }
}

public enum AuthorityJournalRecoveryReducer {
  public static func recover(
    _ image: AuthorityJournalImage,
    minimumHead: AuthorityJournalHead? = nil
  ) -> AuthorityJournalRecovery {
    if image.hasTemporaryHead {
      return quarantine(.interruptedHeadReplacement)
    }
    switch (image.journal, image.head) {
    case (nil, nil):
      if minimumHead != nil { return quarantine(.rollback) }
      return AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.verifyOff))
    case (.some(let data), nil) where data.isEmpty:
      if minimumHead != nil { return quarantine(.rollback) }
      return AuthorityJournalRecovery(
        committedState: nil, head: nil, posture: .recovering(.verifyOff))
    case (nil, .some):
      return quarantine(.unexpectedHead)
    case (.some, nil):
      return quarantine(.missingHead)
    case (.some(let journal), .some(let headData)):
      do {
        let head = try AuthorityJournalCodec.decodeHead(headData)
        if let minimumHead,
          head.sequence < minimumHead.sequence
            || head.committedLength < minimumHead.committedLength
            || (head.sequence == minimumHead.sequence
              && head.recordSHA256 != minimumHead.recordSHA256)
        {
          throw AuthorityJournalValidationError.rollback
        }
        guard journal.count <= AuthorityJournalLimits.maximumJournalBytes else {
          throw AuthorityJournalValidationError.journalTooLarge
        }
        guard head.committedLength <= UInt64(journal.count) else {
          throw AuthorityJournalValidationError.truncated
        }
        let committedBytes = journal.prefix(Int(head.committedLength))
        let decoded = try AuthorityJournalCodec.decodeRecords(Data(committedBytes))
        guard let last = decoded.last else {
          throw AuthorityJournalValidationError.invalidHead
        }
        guard last.sequence == head.sequence,
          last.recordSHA256 == head.recordSHA256,
          last.endOffset == committedBytes.count
        else { throw AuthorityJournalValidationError.invalidHead }
        try validateMonotonic(decoded.map(\.state))
        guard head.committedLength == UInt64(journal.count) else {
          // Preserve the exact head high-water for diagnostics/reconciliation,
          // but an append durable before head replacement is ambiguous with a
          // rolled-back head and therefore always quarantines.
          return AuthorityJournalRecovery(
            committedState: last.state, head: head,
            posture: .quarantined(.trailingData))
        }
        let action: AuthorityRecoveryAction
        switch last.state.state {
        case .active:
          action = .reattestOwner
        case .preparing, .starting, .stopping:
          action = .stopOwner
        case .off:
          action = .verifyOff
        case .recovering, .quarantined:
          return AuthorityJournalRecovery(
            committedState: last.state, head: head,
            posture: .quarantined(.invalidState))
        }
        return AuthorityJournalRecovery(
          committedState: last.state, head: head,
          posture: .recovering(action))
      } catch let error as AuthorityJournalValidationError {
        return quarantine(error)
      } catch {
        return quarantine(.malformedFrame)
      }
    }
  }

  private static func validateMonotonic(_ states: [AuthorityCommittedState]) throws {
    guard states.count <= AuthorityJournalLimits.maximumRecords else {
      throw AuthorityJournalValidationError.tooManyRecords
    }
    for (prior, next) in zip(states, states.dropFirst()) {
      guard next.installationID == prior.installationID else {
        throw AuthorityJournalValidationError.rollback
      }
      guard next.revision == prior.revision + 1 else {
        throw next.revision <= prior.revision
          ? AuthorityJournalValidationError.rollback
          : AuthorityJournalValidationError.reordered
      }
      guard (next.epoch, next.generation) >= (prior.epoch, prior.generation) else {
        throw AuthorityJournalValidationError.rollback
      }
    }
  }

  private static func quarantine(_ reason: AuthorityJournalValidationError)
    -> AuthorityJournalRecovery
  {
    AuthorityJournalRecovery(
      committedState: nil, head: nil, posture: .quarantined(reason))
  }
}

struct AuthorityJournalDecodedRecord: Equatable {
  let sequence: UInt64
  let state: AuthorityCommittedState
  let recordSHA256: SHA256Digest
  let endOffset: Int
}

/// Binary frame: magic, payload length, sequence, previous digest, payload
/// digest, CRC-32, then canonical JSON payload. The SHA-256 of the complete
/// frame is the next record's chain value and the durable head value.
enum AuthorityJournalCodec {
  static let magic = Data("CFWAJR01".utf8)
  static let headerBytes = 8 + 4 + 8 + 32 + 32 + 4
  static let zeroDigest = try! SHA256Digest(hex: String(repeating: "0", count: 64))

  static func encodeRecord(
    state: AuthorityCommittedState,
    sequence: UInt64,
    previousSHA256: SHA256Digest
  ) throws -> (frame: Data, digest: SHA256Digest) {
    let payload = try canonicalEncode(state)
    guard payload.count <= AuthorityJournalLimits.maximumRecordPayloadBytes else {
      throw AuthorityJournalValidationError.recordTooLarge
    }
    var prefix = Data()
    prefix.append(magic)
    prefix.appendBigEndian(UInt32(payload.count))
    prefix.appendBigEndian(sequence)
    prefix.append(try digestBytes(previousSHA256))
    prefix.append(Data(SHA256.hash(data: payload)))
    let crc = crc32(prefix + payload)
    var frame = prefix
    frame.appendBigEndian(crc)
    frame.append(payload)
    return (frame, try digest(frame))
  }

  static func decodeRecords(_ journal: Data) throws -> [AuthorityJournalDecodedRecord] {
    guard !journal.isEmpty else { throw AuthorityJournalValidationError.malformedFrame }
    var records: [AuthorityJournalDecodedRecord] = []
    var offset = 0
    var expectedSequence: UInt64 = 1
    var expectedPrevious = zeroDigest
    while offset < journal.count {
      guard records.count < AuthorityJournalLimits.maximumRecords else {
        throw AuthorityJournalValidationError.tooManyRecords
      }
      guard journal.count - offset >= headerBytes else {
        throw AuthorityJournalValidationError.truncated
      }
      let start = offset
      guard journal.subdata(in: offset..<(offset + magic.count)) == magic else {
        throw AuthorityJournalValidationError.malformedFrame
      }
      offset += magic.count
      let payloadLength: UInt32 = try journal.readBigEndian(at: &offset)
      guard payloadLength <= AuthorityJournalLimits.maximumRecordPayloadBytes else {
        throw AuthorityJournalValidationError.recordTooLarge
      }
      let sequence: UInt64 = try journal.readBigEndian(at: &offset)
      guard sequence == expectedSequence else {
        throw AuthorityJournalValidationError.reordered
      }
      let previous = try SHA256Digest(hex: journal.readBytes(at: &offset, count: 32).hex)
      guard previous == expectedPrevious else {
        throw AuthorityJournalValidationError.brokenHashChain
      }
      let payloadDigest = try SHA256Digest(
        hex: journal.readBytes(at: &offset, count: 32).hex)
      let storedCRC: UInt32 = try journal.readBigEndian(at: &offset)
      guard Int(payloadLength) <= journal.count - offset else {
        throw AuthorityJournalValidationError.truncated
      }
      let payload = journal.subdata(in: offset..<(offset + Int(payloadLength)))
      offset += Int(payloadLength)
      guard try digest(payload) == payloadDigest else {
        throw AuthorityJournalValidationError.invalidPayloadDigest
      }
      var crcInput = journal.subdata(in: start..<(start + headerBytes - 4))
      crcInput.append(payload)
      guard crc32(crcInput) == storedCRC else {
        throw AuthorityJournalValidationError.invalidCRC
      }
      let frame = journal.subdata(in: start..<offset)
      let recordDigest = try digest(frame)
      let state = try canonicalDecode(AuthorityCommittedState.self, payload)
      records.append(
        AuthorityJournalDecodedRecord(
          sequence: sequence, state: state,
          recordSHA256: recordDigest, endOffset: offset))
      expectedSequence += 1
      expectedPrevious = recordDigest
    }
    return records
  }

  static func encodeHead(_ head: AuthorityJournalHead) throws -> Data {
    let data = try canonicalEncode(head)
    guard data.count <= AuthorityJournalLimits.maximumHeadBytes else {
      throw AuthorityJournalValidationError.invalidHead
    }
    return data
  }

  static func decodeHead(_ data: Data) throws -> AuthorityJournalHead {
    guard !data.isEmpty, data.count <= AuthorityJournalLimits.maximumHeadBytes else {
      throw AuthorityJournalValidationError.invalidHead
    }
    return try canonicalDecode(AuthorityJournalHead.self, data)
  }

  private static func canonicalEncode<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    do { return try encoder.encode(value) } catch {
      throw AuthorityJournalValidationError.invalidState
    }
  }

  private static func canonicalDecode<T: Codable>(_ type: T.Type, _ data: Data) throws -> T {
    let decoded: T
    do { decoded = try JSONDecoder().decode(type, from: data) } catch {
      throw AuthorityJournalValidationError.malformedFrame
    }
    guard try canonicalEncode(decoded) == data else {
      throw AuthorityJournalValidationError.noncanonicalRecord
    }
    return decoded
  }

  private static func digest(_ data: Data) throws -> SHA256Digest {
    try SHA256Digest(hex: Data(SHA256.hash(data: data)).hex)
  }

  private static func digestBytes(_ digest: SHA256Digest) throws -> Data {
    guard let data = Data(hex: digest.hex), data.count == 32 else {
      throw AuthorityJournalValidationError.invalidPayloadDigest
    }
    return data
  }

  private static func crc32(_ data: Data) -> UInt32 {
    var crc: UInt32 = 0xffff_ffff
    for byte in data {
      crc ^= UInt32(byte)
      for _ in 0..<8 {
        let mask = UInt32(bitPattern: -Int32(crc & 1))
        crc = (crc >> 1) ^ (0xedb8_8320 & mask)
      }
    }
    return ~crc
  }
}

extension Data {
  fileprivate mutating func appendBigEndian<T: FixedWidthInteger>(_ value: T) {
    var bigEndian = value.bigEndian
    Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
  }

  fileprivate func readBigEndian<T: FixedWidthInteger>(at offset: inout Int) throws -> T {
    let count = MemoryLayout<T>.size
    guard offset >= 0, count <= self.count - offset else {
      throw AuthorityJournalValidationError.truncated
    }
    var value: T = 0
    Swift.withUnsafeMutableBytes(of: &value) { destination in
      _ = copyBytes(to: destination, from: offset..<(offset + count))
    }
    offset += count
    return T(bigEndian: value)
  }

  fileprivate func readBytes(at offset: inout Int, count: Int) throws -> Data {
    guard offset >= 0, count >= 0, count <= self.count - offset else {
      throw AuthorityJournalValidationError.truncated
    }
    defer { offset += count }
    return subdata(in: offset..<(offset + count))
  }

  fileprivate var hex: String { map { String(format: "%02x", $0) }.joined() }

  fileprivate init?(hex: String) {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}
