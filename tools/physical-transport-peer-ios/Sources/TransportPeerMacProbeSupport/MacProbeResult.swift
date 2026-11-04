import Foundation
import TransportPeerCore

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
