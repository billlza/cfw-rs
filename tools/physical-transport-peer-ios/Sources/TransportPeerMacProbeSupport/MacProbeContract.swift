import Darwin
import Foundation
import Security
import TransportPeerCore

public enum MacProbeContract {
  public static let planSchemaVersion = 1
  public static let resultSchemaVersion = 3
  public static let planDocument = "cfm-ios-transport-peer-mac-probe-plan-v1"
  public static let resultDocument = "cfm-ios-transport-peer-mac-probe-result-v3"
  public static let resultMode = "lab_smoke_only"
  public static let planFileName = "probe.json"
  public static let readyFileName = PeerContract.readyFileName
  public static let certificateFileName = PeerContract.certificateFileName
  public static let serverName = "cfm-transport-peer.invalid"
  public static let mismatchedALPN = "cfm-transport-peer-no-overlap/1"
  public static let attemptCount = 7
  public static let connectionDeadlineSeconds: TimeInterval = 8
}

public enum MacProbeError: Error, Equatable, LocalizedError {
  case invalidInput(String)
  case connectionFailed(String)
  case deadline(String)
  case protocolMismatch(String)

  public var errorDescription: String? {
    switch self {
    case .invalidInput(let label):
      "Invalid Mac transport probe input: \(label)"
    case .connectionFailed(let label):
      "Mac transport probe connection failed: \(label)"
    case .deadline(let label):
      "Mac transport probe deadline expired: \(label)"
    case .protocolMismatch(let label):
      "Mac transport probe protocol mismatch: \(label)"
    }
  }
}

public struct MacProbePlan: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let sessionID: String
  public let createdAt: String
  public let expiresAt: String
  public let peerIPv4: String
  public let certificateSHA256: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case sessionID = "session_id"
    case createdAt = "created_at"
    case expiresAt = "expires_at"
    case peerIPv4 = "peer_ipv4"
    case certificateSHA256 = "certificate_sha256"
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "session_id",
    "created_at",
    "expires_at",
    "peer_ipv4",
    "certificate_sha256",
  ]

  public init(
    schemaVersion: Int,
    document: String,
    sessionID: String,
    createdAt: String,
    expiresAt: String,
    peerIPv4: String,
    certificateSHA256: String
  ) {
    self.schemaVersion = schemaVersion
    self.document = document
    self.sessionID = sessionID
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.peerIPv4 = peerIPv4
    self.certificateSHA256 = certificateSHA256
  }

  public static func decodeCanonical(_ data: Data, now: Date) throws -> MacProbePlan {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw MacProbeError.invalidInput("probe plan size or terminator")
    }
    let object = try JSONSerialization.jsonObject(with: Data(data.dropLast()), options: [])
    guard let dictionary = object as? [String: Any], Set(dictionary.keys) == exactFields else {
      throw MacProbeError.invalidInput("probe plan fields")
    }
    let plan = try JSONDecoder().decode(MacProbePlan.self, from: data)
    guard try ExactJSON.encode(plan) == data else {
      throw MacProbeError.invalidInput("probe plan canonical JSON")
    }
    try plan.validate(now: now)
    return plan
  }

  public func validate(now: Date) throws {
    guard schemaVersion == MacProbeContract.planSchemaVersion,
      document == MacProbeContract.planDocument,
      PeerSession.isDigest(sessionID),
      PeerSession.isDigest(certificateSHA256),
      PeerNetworkIdentity.isControlledWiFiIPv4(interfaceName: "en0", address: peerIPv4),
      let created = PeerSession.parseTimestamp(createdAt),
      let expires = PeerSession.parseTimestamp(expiresAt),
      created <= now,
      now < expires,
      expires.timeIntervalSince(created) <= PeerContract.maximumSessionSeconds
    else {
      throw MacProbeError.invalidInput("probe plan identity or lifetime")
    }
  }
}

public struct MacProbeInputs: Sendable {
  public let plan: MacProbePlan
  public let ready: ReadyReceipt
  public let certificateDER: Data
}

public enum MacProbeRunDirectory {
  public static func load(path: String, now: Date = Date()) throws -> MacProbeInputs {
    guard path.hasPrefix("/") else {
      throw MacProbeError.invalidInput("run directory is not absolute")
    }
    let directory = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
    guard directory.path == directory.resolvingSymlinksInPath().standardizedFileURL.path else {
      throw MacProbeError.invalidInput("run directory contains a symbolic link")
    }
    try requirePrivateDirectory(directory)
    let expected = Set([
      MacProbeContract.planFileName,
      MacProbeContract.readyFileName,
      MacProbeContract.certificateFileName,
    ])
    try requireExactEntries(directory, expected: expected)

    let planData = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.planFileName),
      maximumBytes: PeerContract.maximumJSONBytes
    )
    let readyData = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.readyFileName),
      maximumBytes: PeerContract.maximumJSONBytes
    )
    let certificateDER = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.certificateFileName),
      maximumBytes: 16 * 1_024
    )
    try requireExactEntries(directory, expected: expected)

    let plan = try MacProbePlan.decodeCanonical(planData, now: now)
    let ready: ReadyReceipt
    do {
      ready = try ExactJSON.decodeReady(readyData)
    } catch {
      throw MacProbeError.invalidInput("ready canonical JSON")
    }
    try validate(ready: ready, against: plan, now: now)
    guard PeerDigest.sha256(certificateDER) == plan.certificateSHA256,
      SecCertificateCreateWithData(nil, certificateDER as CFData) != nil
    else {
      throw MacProbeError.invalidInput("certificate bytes")
    }
    return MacProbeInputs(plan: plan, ready: ready, certificateDER: certificateDER)
  }

  private static func validate(ready: ReadyReceipt, against plan: MacProbePlan, now: Date) throws {
    guard ready.schemaVersion == PeerContract.schemaVersion,
      ready.document == PeerContract.readyDocument,
      ready.sessionID == plan.sessionID,
      ready.bundleIdentifier == PeerContract.bundleIdentifier,
      ready.processID > 0,
      ready.certificateSHA256 == plan.certificateSHA256,
      ready.network.interfaceName == "en0",
      ready.network.ipv4 == plan.peerIPv4,
      ready.listeners == .fixed,
      ready.expiresAt == plan.expiresAt,
      let planCreated = PeerSession.parseTimestamp(plan.createdAt),
      let started = PeerSession.parseTimestamp(ready.startedAt),
      let expires = PeerSession.parseTimestamp(ready.expiresAt),
      started <= planCreated,
      started <= now,
      now < expires
    else {
      throw MacProbeError.invalidInput("ready receipt binding")
    }
  }

  private static func requirePrivateDirectory(_ url: URL) throws {
    var metadata = stat()
    guard url.path.withCString({ lstat($0, &metadata) }) == 0,
      metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_uid == geteuid(),
      metadata.st_mode & 0o777 == 0o700
    else {
      throw MacProbeError.invalidInput("run directory ownership or mode")
    }
  }

  private static func requireExactEntries(_ directory: URL, expected: Set<String>) throws {
    let entries: [URL]
    do {
      entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw MacProbeError.invalidInput("run directory inventory")
    }
    guard entries.count == expected.count, Set(entries.map(\.lastPathComponent)) == expected else {
      throw MacProbeError.invalidInput("run directory entries")
    }
  }

  private static func readStableFile(_ url: URL, maximumBytes: Int) throws -> Data {
    var before = stat()
    guard url.path.withCString({ lstat($0, &before) }) == 0,
      before.st_mode & S_IFMT == S_IFREG,
      before.st_uid == geteuid(),
      before.st_nlink == 1,
      before.st_mode & 0o022 == 0,
      before.st_size > 0,
      before.st_size <= maximumBytes
    else {
      throw MacProbeError.invalidInput("run input metadata")
    }
    let data: Data
    do {
      data = try Data(contentsOf: url, options: [.uncached])
    } catch {
      throw MacProbeError.invalidInput("run input read")
    }
    var after = stat()
    guard url.path.withCString({ lstat($0, &after) }) == 0,
      before.st_dev == after.st_dev,
      before.st_ino == after.st_ino,
      before.st_size == after.st_size,
      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
      data.count == Int(before.st_size)
    else {
      throw MacProbeError.invalidInput("run input changed while reading")
    }
    return data
  }
}

public struct MacProbeDidNotReachReadyReceipt: Codable, Equatable, Sendable {
  public let didNotReachReady: Bool
  public let clientBytesSent: Int

  enum CodingKeys: String, CodingKey {
    case didNotReachReady = "did_not_reach_ready"
    case clientBytesSent = "client_bytes_sent"
  }

  static let exactFields: Set<String> = ["did_not_reach_ready", "client_bytes_sent"]
}

public struct MacProbeWrongLeafPinReceipt: Codable, Equatable, Sendable {
  public let didNotReachReady: Bool
  public let clientBytesSent: Int
  public let verifyCallbackInvoked: Bool
  public let leafMatchedSessionCertificate: Bool
  public let verifyReturnedFalse: Bool

  enum CodingKeys: String, CodingKey {
    case didNotReachReady = "did_not_reach_ready"
    case clientBytesSent = "client_bytes_sent"
    case verifyCallbackInvoked = "verify_callback_invoked"
    case leafMatchedSessionCertificate = "leaf_matched_session_certificate"
    case verifyReturnedFalse = "verify_returned_false"
  }

  static let exactFields: Set<String> = [
    "did_not_reach_ready",
    "client_bytes_sent",
    "verify_callback_invoked",
    "leaf_matched_session_certificate",
    "verify_returned_false",
  ]
}

public struct MacProbeInvalidFrameReceipt: Codable, Equatable, Sendable {
  public let clientCompleted: Bool
  public let connectionEnded: Bool
  public let tlsVersion: UInt16
  public let cipherSuite: UInt16
  public let alpn: String
  public let earlyDataAccepted: Bool
  public let clientBytesSent: Int
  public let invalidZeroLengthFrameSent: Bool

  enum CodingKeys: String, CodingKey {
    case clientCompleted = "client_completed"
    case connectionEnded = "connection_ended"
    case tlsVersion = "tls_version"
    case cipherSuite = "cipher_suite"
    case alpn
    case earlyDataAccepted = "early_data_accepted"
    case clientBytesSent = "client_bytes_sent"
    case invalidZeroLengthFrameSent = "invalid_zero_length_frame_sent"
  }

  static let exactFields: Set<String> = [
    "client_completed",
    "connection_ended",
    "tls_version",
    "cipher_suite",
    "alpn",
    "early_data_accepted",
    "client_bytes_sent",
    "invalid_zero_length_frame_sent",
  ]
}

public struct MacProbeNegativeReceipts: Codable, Equatable, Sendable {
  public let tls12DidNotReachReady: MacProbeDidNotReachReadyReceipt
  public let wrongLeafPinRejected: MacProbeWrongLeafPinReceipt
  public let alpnMismatchDidNotReachReady: MacProbeDidNotReachReadyReceipt
  public let zeroLengthFrameConnectionEnded: MacProbeInvalidFrameReceipt

  enum CodingKeys: String, CodingKey {
    case tls12DidNotReachReady = "tls12_did_not_reach_ready"
    case wrongLeafPinRejected = "wrong_leaf_pin_rejected"
    case alpnMismatchDidNotReachReady = "alpn_mismatch_did_not_reach_ready"
    case zeroLengthFrameConnectionEnded = "zero_length_frame_connection_ended"
  }

  static let exactFields: Set<String> = [
    "tls12_did_not_reach_ready",
    "wrong_leaf_pin_rejected",
    "alpn_mismatch_did_not_reach_ready",
    "zero_length_frame_connection_ended",
  ]
}

public struct MacProbeTCPReceipt: Codable, Equatable, Sendable {
  public let clientCompleted: Bool
  public let transport: String
  public let payloadSHA256: String
  public let payloadBytes: Int
  public let clientBytesSent: Int
  public let clientBytesReceived: Int

  enum CodingKeys: String, CodingKey {
    case clientCompleted = "client_completed"
    case transport
    case payloadSHA256 = "payload_sha256"
    case payloadBytes = "payload_bytes"
    case clientBytesSent = "client_bytes_sent"
    case clientBytesReceived = "client_bytes_received"
  }

  static let exactFields: Set<String> = [
    "client_completed",
    "transport",
    "payload_sha256",
    "payload_bytes",
    "client_bytes_sent",
    "client_bytes_received",
  ]
}

public struct MacProbeSecureReceipt: Codable, Equatable, Sendable {
  public let clientCompleted: Bool
  public let transport: String
  public let payloadSHA256: String
  public let payloadBytes: Int
  public let clientBytesSent: Int
  public let clientBytesReceived: Int
  public let clientControlBytesSent: Int
  public let clientControlBytesReceived: Int
  public let deliveryAcknowledgementHex: String
  public let deliveryConfirmationHex: String
  public let deliveryConfirmationStreamComplete: Bool
  public let tlsVersion: UInt16
  public let cipherSuite: UInt16
  public let alpn: String
  public let earlyDataAccepted: Bool
  public let certificateSHA256: String

  enum CodingKeys: String, CodingKey {
    case clientCompleted = "client_completed"
    case transport
    case payloadSHA256 = "payload_sha256"
    case payloadBytes = "payload_bytes"
    case clientBytesSent = "client_bytes_sent"
    case clientBytesReceived = "client_bytes_received"
    case clientControlBytesSent = "client_control_bytes_sent"
    case clientControlBytesReceived = "client_control_bytes_received"
    case deliveryAcknowledgementHex = "delivery_acknowledgement_hex"
    case deliveryConfirmationHex = "delivery_confirmation_hex"
    case deliveryConfirmationStreamComplete = "delivery_confirmation_stream_complete"
    case tlsVersion = "tls_version"
    case cipherSuite = "cipher_suite"
    case alpn
    case earlyDataAccepted = "early_data_accepted"
    case certificateSHA256 = "certificate_sha256"
  }

  static let exactFields: Set<String> = [
    "client_completed",
    "transport",
    "payload_sha256",
    "payload_bytes",
    "client_bytes_sent",
    "client_bytes_received",
    "client_control_bytes_sent",
    "client_control_bytes_received",
    "delivery_acknowledgement_hex",
    "delivery_confirmation_hex",
    "delivery_confirmation_stream_complete",
    "tls_version",
    "cipher_suite",
    "alpn",
    "early_data_accepted",
    "certificate_sha256",
  ]
}

public struct MacProbePositiveReceipts: Codable, Equatable, Sendable {
  public let tcpSink: MacProbeTCPReceipt
  public let tls13Echo: MacProbeSecureReceipt
  public let quicEcho: MacProbeSecureReceipt

  enum CodingKeys: String, CodingKey {
    case tcpSink = "tcp_sink"
    case tls13Echo = "tls13_echo"
    case quicEcho = "quic_echo"
  }

  static let exactFields: Set<String> = ["tcp_sink", "tls13_echo", "quic_echo"]
}

public struct MacProbeResult: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let mode: String
  public let claimEligible: Bool
  public let sessionID: String
  public let certificateSHA256: String
  public let processID: Int32
  public let peerIPv4: String
  public let attemptCount: Int
  public let startedAt: String
  public let completedAt: String
  public let negativeChecks: MacProbeNegativeReceipts
  public let positiveChecks: MacProbePositiveReceipts

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case mode
    case claimEligible = "claim_eligible"
    case sessionID = "session_id"
    case certificateSHA256 = "certificate_sha256"
    case processID = "process_id"
    case peerIPv4 = "peer_ipv4"
    case attemptCount = "attempt_count"
    case startedAt = "started_at"
    case completedAt = "completed_at"
    case negativeChecks = "negative_checks"
    case positiveChecks = "positive_checks"
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "mode",
    "claim_eligible",
    "session_id",
    "certificate_sha256",
    "process_id",
    "peer_ipv4",
    "attempt_count",
    "started_at",
    "completed_at",
    "negative_checks",
    "positive_checks",
  ]

  public static func decodeCanonical(_ data: Data, now: Date = Date()) throws -> MacProbeResult {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw MacProbeError.invalidInput("probe result size or terminator")
    }
    let object = try JSONSerialization.jsonObject(with: Data(data.dropLast()), options: [])
    guard let dictionary = object as? [String: Any], hasExactShape(dictionary) else {
      throw MacProbeError.invalidInput("probe result fields")
    }
    let result: MacProbeResult
    do {
      result = try JSONDecoder().decode(MacProbeResult.self, from: data)
    } catch {
      throw MacProbeError.invalidInput("probe result values")
    }
    guard try ExactJSON.encode(result) == data else {
      throw MacProbeError.invalidInput("probe result canonical JSON")
    }
    try result.validate(now: now)
    return result
  }

  public func validate(now: Date) throws {
    guard schemaVersion == MacProbeContract.resultSchemaVersion,
      document == MacProbeContract.resultDocument,
      mode == MacProbeContract.resultMode,
      claimEligible == false,
      PeerSession.isDigest(sessionID),
      PeerSession.isDigest(certificateSHA256),
      processID > 0,
      PeerNetworkIdentity.isControlledWiFiIPv4(interfaceName: "en0", address: peerIPv4),
      attemptCount == MacProbeContract.attemptCount,
      let started = PeerSession.parseTimestamp(startedAt),
      let completed = PeerSession.parseTimestamp(completedAt),
      started <= completed,
      completed <= now,
      completed.timeIntervalSince(started) <= PeerContract.maximumSessionSeconds,
      negativeChecks.tls12DidNotReachReady.didNotReachReady,
      negativeChecks.tls12DidNotReachReady.clientBytesSent == 0,
      negativeChecks.alpnMismatchDidNotReachReady.didNotReachReady,
      negativeChecks.alpnMismatchDidNotReachReady.clientBytesSent == 0,
      negativeChecks.wrongLeafPinRejected.didNotReachReady,
      negativeChecks.wrongLeafPinRejected.clientBytesSent == 0,
      negativeChecks.wrongLeafPinRejected.verifyCallbackInvoked,
      negativeChecks.wrongLeafPinRejected.leafMatchedSessionCertificate,
      negativeChecks.wrongLeafPinRejected.verifyReturnedFalse,
      negativeChecks.zeroLengthFrameConnectionEnded.clientCompleted,
      negativeChecks.zeroLengthFrameConnectionEnded.connectionEnded,
      negativeChecks.zeroLengthFrameConnectionEnded.tlsVersion == 0x0304,
      (0x1301...0x1305).contains(
        negativeChecks.zeroLengthFrameConnectionEnded.cipherSuite),
      negativeChecks.zeroLengthFrameConnectionEnded.alpn == PeerContract.tlsALPN,
      negativeChecks.zeroLengthFrameConnectionEnded.earlyDataAccepted == false,
      negativeChecks.zeroLengthFrameConnectionEnded.clientBytesSent == 2,
      negativeChecks.zeroLengthFrameConnectionEnded.invalidZeroLengthFrameSent
    else {
      throw MacProbeError.invalidInput("probe result semantics")
    }

    let tcpPayload = try PeerProbePayload.payload(for: .tcpSink, sessionID: sessionID)
    let tlsPayload = try PeerProbePayload.payload(for: .tls13Echo, sessionID: sessionID)
    let quicPayload = try PeerProbePayload.payload(for: .quicEcho, sessionID: sessionID)
    guard positiveChecks.tcpSink.clientCompleted,
      positiveChecks.tcpSink.transport == "tcp4",
      positiveChecks.tcpSink.payloadSHA256 == PeerDigest.sha256(tcpPayload),
      positiveChecks.tcpSink.payloadBytes == tcpPayload.count,
      positiveChecks.tcpSink.clientBytesSent == tcpPayload.count,
      positiveChecks.tcpSink.clientBytesReceived == 0,
      secureReceiptIsValid(
        positiveChecks.tls13Echo,
        transport: "tls13-tcp4",
        alpn: PeerContract.tlsALPN,
        payload: tlsPayload
      ),
      secureReceiptIsValid(
        positiveChecks.quicEcho,
        transport: "quic-tls13",
        alpn: PeerContract.quicALPN,
        payload: quicPayload
      )
    else {
      throw MacProbeError.invalidInput("probe result client observations")
    }
  }

  private static func hasExactShape(_ dictionary: [String: Any]) -> Bool {
    guard Set(dictionary.keys) == exactFields,
      let negative = dictionary["negative_checks"] as? [String: Any],
      Set(negative.keys) == MacProbeNegativeReceipts.exactFields,
      hasExactFields(
        negative["tls12_did_not_reach_ready"],
        MacProbeDidNotReachReadyReceipt.exactFields
      ),
      hasExactFields(
        negative["wrong_leaf_pin_rejected"],
        MacProbeWrongLeafPinReceipt.exactFields
      ),
      hasExactFields(
        negative["alpn_mismatch_did_not_reach_ready"],
        MacProbeDidNotReachReadyReceipt.exactFields
      ),
      hasExactFields(
        negative["zero_length_frame_connection_ended"],
        MacProbeInvalidFrameReceipt.exactFields
      ),
      let positive = dictionary["positive_checks"] as? [String: Any],
      Set(positive.keys) == MacProbePositiveReceipts.exactFields,
      hasExactFields(positive["tcp_sink"], MacProbeTCPReceipt.exactFields),
      hasExactFields(positive["tls13_echo"], MacProbeSecureReceipt.exactFields),
      hasExactFields(positive["quic_echo"], MacProbeSecureReceipt.exactFields)
    else {
      return false
    }
    return true
  }

  private static func hasExactFields(_ value: Any?, _ expected: Set<String>) -> Bool {
    guard let dictionary = value as? [String: Any] else { return false }
    return Set(dictionary.keys) == expected
  }

  private func secureReceiptIsValid(
    _ receipt: MacProbeSecureReceipt,
    transport: String,
    alpn: String,
    payload: Data
  ) -> Bool {
    receipt.clientCompleted
      && receipt.transport == transport
      && receipt.payloadSHA256 == PeerDigest.sha256(payload)
      && receipt.payloadBytes == payload.count
      && receipt.clientBytesSent == payload.count + 2
      && receipt.clientBytesReceived == payload.count + 2
      && receipt.clientControlBytesSent == PeerContract.deliveryAcknowledgement.count
      && receipt.clientControlBytesReceived == PeerContract.deliveryConfirmation.count
      && receipt.deliveryAcknowledgementHex == PeerContract.deliveryAcknowledgementHex
      && receipt.deliveryConfirmationHex == PeerContract.deliveryConfirmationHex
      && receipt.deliveryConfirmationStreamComplete
      && receipt.tlsVersion == 0x0304
      && (0x1301...0x1305).contains(receipt.cipherSuite)
      && receipt.alpn == alpn
      && receipt.earlyDataAccepted == false
      && receipt.certificateSHA256 == certificateSHA256
  }
}
