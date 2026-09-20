import CryptoKit
import Foundation

public enum PeerContract {
  public static let schemaVersion = 1
  public static let resultSchemaVersion = 5
  public static let sessionDocument = "cfm-ios-transport-peer-session-v1"
  public static let readyDocument = "cfm-ios-transport-peer-ready-v1"
  public static let resultDocument = "cfm-ios-transport-peer-result-v5"
  public static let primerResultDocument = "cfm-ios-transport-peer-primer-result-v1"
  public static let resultEvidenceRole = "server_observation_only"
  public static let bundleIdentifier = "com.bill.cfm.physical-transport-peer"
  public static let primerLaunchArgument = "--cfm-local-network-primer-v1"
  public static let transportRunLaunchArgument = "--cfm-transport-run-v1"
  public static let primerMode = "local_network_permission_primer"
  public static let sessionDirectoryName = "CFMTransportPeer"
  public static let primerDirectoryName = "CFMTransportPrimer"
  public static let sessionFileName = "session.json"
  public static let certificateFileName = "certificate.der"
  public static let privateKeyFileName = "private-key.x963"
  public static let readyFileName = "ready.json"
  public static let resultFileName = "result.json"
  public static let primerResultFileName = "primer-result.json"
  public static let primerPort: UInt16 = 44_332
  public static let tcpSinkPort: UInt16 = 44_333
  public static let tlsEchoPort: UInt16 = 44_334
  public static let quicEchoPort: UInt16 = 44_335
  public static let tlsALPN = "cfm-transport-peer-tls/1"
  public static let quicALPN = "cfm-transport-peer-quic/1"
  public static let deliveryAcknowledgement = Data([0xA5])
  public static let deliveryConfirmation = Data([0x5A])
  public static let deliveryAcknowledgementHex = "a5"
  public static let deliveryConfirmationHex = "5a"
  public static let primerBonjourName = "CFM Transport Primer"
  public static let primerBonjourType = "_cfm-primer._tcp"
  public static let primerBonjourDomain = "local."
  public static let maximumConnections = 8
  public static let observableQUICConnectionGroupLimit = 2
  public static let maximumClientInitiatedBidirectionalQUICStreams = 1
  public static let maximumServerInitiatedBidirectionalQUICStreams = 0
  public static let clientInitiatedBidirectionalQUICStreamIdentifier: UInt64 = 0
  public static let maximumPayloadBytes = 64
  public static let preSecurityHandshakeDeadlineSeconds: TimeInterval = 4
  public static let quicEstablishmentDeadlineSeconds: TimeInterval = 7
  public static let connectionProgressDeadlineSeconds: TimeInterval = 7
  public static let maximumSessionSeconds: TimeInterval = 15 * 60
  public static let maximumJSONBytes = 64 * 1_024
}

public enum PeerLaunchMode: Equatable, Sendable {
  case primer
  case session
  case packetLan

  public static func parse(arguments: [String]) throws -> PeerLaunchMode {
    switch arguments {
    case [PeerContract.primerLaunchArgument]:
      return .primer
    case [PeerContract.transportRunLaunchArgument]:
      return .session
    case [PacketLanPeerContract.launchArgument]:
      return .packetLan
    default:
      throw PeerContractError.malformed("application launch arguments")
    }
  }
}

public enum PeerContractError: Error, Equatable, LocalizedError {
  case malformed(String)
  case unsafeFile(String)
  case stalePrimer
  case staleSession
  case identityMismatch(String)
  case writeFailed(String)

  public var errorDescription: String? {
    switch self {
    case .malformed(let label):
      "Malformed peer contract: \(label)"
    case .unsafeFile(let label):
      "Unsafe peer file: \(label)"
    case .stalePrimer:
      "The local-network primer receipt is stale"
    case .staleSession:
      "The peer session is stale"
    case .identityMismatch(let label):
      "Peer identity differs: \(label)"
    case .writeFailed(let label):
      "Peer receipt write failed: \(label)"
    }
  }
}

public struct PeerSession: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let sessionID: String
  public let createdAt: String
  public let expiresAt: String
  public let certificateSHA256: String
  public let privateKeySHA256: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case sessionID = "session_id"
    case createdAt = "created_at"
    case expiresAt = "expires_at"
    case certificateSHA256 = "certificate_sha256"
    case privateKeySHA256 = "private_key_sha256"
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "session_id",
    "created_at",
    "expires_at",
    "certificate_sha256",
    "private_key_sha256",
  ]

  public func validate(now: Date) throws -> (createdAt: Date, expiresAt: Date) {
    guard schemaVersion == PeerContract.schemaVersion,
      document == PeerContract.sessionDocument,
      Self.isDigest(sessionID),
      Self.isDigest(certificateSHA256),
      Self.isDigest(privateKeySHA256),
      let created = Self.parseTimestamp(createdAt),
      let expires = Self.parseTimestamp(expiresAt),
      created <= now,
      now < expires,
      expires.timeIntervalSince(created) <= PeerContract.maximumSessionSeconds
    else {
      throw PeerContractError.staleSession
    }
    return (created, expires)
  }

  public static func isDigest(_ value: String) -> Bool {
    value.count == 64
      && value.utf8.allSatisfy { byte in
        (48...57).contains(byte) || (97...102).contains(byte)
      }
  }

  public static func parseTimestamp(_ value: String) -> Date? {
    guard value.count == 27, value.hasSuffix("Z") else { return nil }
    let formatter = DateFormatter()
    formatter.calendar = Calendar(identifier: .iso8601)
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'"
    return formatter.date(from: value)
  }

  public static func timestamp(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.calendar = Calendar(identifier: .iso8601)
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'"
    return formatter.string(from: date)
  }
}

public struct ListenerReceipt: Codable, Equatable, Sendable {
  public let port: UInt16
  public let transport: String
  public let alpn: String?

  public init(port: UInt16, transport: String, alpn: String?) {
    self.port = port
    self.transport = transport
    self.alpn = alpn
  }

  enum CodingKeys: String, CodingKey {
    case port
    case transport
    case alpn
  }

  static let exactFields: Set<String> = ["port", "transport", "alpn"]

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(port, forKey: .port)
    try container.encode(transport, forKey: .transport)
    if let alpn {
      try container.encode(alpn, forKey: .alpn)
    } else {
      try container.encodeNil(forKey: .alpn)
    }
  }
}

public struct ListenerReceipts: Codable, Equatable, Sendable {
  public let tcpSink: ListenerReceipt
  public let tls13Echo: ListenerReceipt
  public let quicEcho: ListenerReceipt

  enum CodingKeys: String, CodingKey {
    case tcpSink = "tcp_sink"
    case tls13Echo = "tls13_echo"
    case quicEcho = "quic_echo"
  }

  static let exactFields: Set<String> = ["tcp_sink", "tls13_echo", "quic_echo"]

  public static let fixed = ListenerReceipts(
    tcpSink: ListenerReceipt(port: PeerContract.tcpSinkPort, transport: "tcp4", alpn: nil),
    tls13Echo: ListenerReceipt(
      port: PeerContract.tlsEchoPort,
      transport: "tls13-tcp4",
      alpn: PeerContract.tlsALPN
    ),
    quicEcho: ListenerReceipt(
      port: PeerContract.quicEchoPort,
      transport: "quic-tls13",
      alpn: PeerContract.quicALPN
    )
  )
}

public struct ReadyReceipt: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let sessionID: String
  public let bundleIdentifier: String
  public let processID: Int32
  public let startedAt: String
  public let expiresAt: String
  public let certificateSHA256: String
  public let network: PeerNetworkReceipt
  public let listeners: ListenerReceipts

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case sessionID = "session_id"
    case bundleIdentifier = "bundle_identifier"
    case processID = "process_id"
    case startedAt = "started_at"
    case expiresAt = "expires_at"
    case certificateSHA256 = "certificate_sha256"
    case network
    case listeners
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "session_id",
    "bundle_identifier",
    "process_id",
    "started_at",
    "expires_at",
    "certificate_sha256",
    "network",
    "listeners",
  ]
}

public struct PrimerListenerReceipt: Codable, Equatable, Sendable {
  public let port: UInt16
  public let transport: String
  public let bonjourName: String
  public let bonjourType: String
  public let bonjourDomain: String

  enum CodingKeys: String, CodingKey {
    case port
    case transport
    case bonjourName = "bonjour_name"
    case bonjourType = "bonjour_type"
    case bonjourDomain = "bonjour_domain"
  }

  static let exactFields: Set<String> = [
    "port",
    "transport",
    "bonjour_name",
    "bonjour_type",
    "bonjour_domain",
  ]

  public static let fixed = PrimerListenerReceipt(
    port: PeerContract.primerPort,
    transport: "tcp4",
    bonjourName: PeerContract.primerBonjourName,
    bonjourType: PeerContract.primerBonjourType,
    bonjourDomain: PeerContract.primerBonjourDomain
  )
}

public struct LocalNetworkPrimerReceipt: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let mode: String
  public let claimEligible: Bool
  public let bundleIdentifier: String
  public let processID: Int32
  public let startedAt: String
  public let serviceRegisteredAt: String
  public let listenerReadyAt: String
  public let listenerCancelledAt: String
  public let serviceRegistered: Bool
  public let listenerReady: Bool
  public let listenerCancelled: Bool
  public let network: PeerNetworkReceipt
  public let listener: PrimerListenerReceipt

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case mode
    case claimEligible = "claim_eligible"
    case bundleIdentifier = "bundle_identifier"
    case processID = "process_id"
    case startedAt = "started_at"
    case serviceRegisteredAt = "service_registered_at"
    case listenerReadyAt = "listener_ready_at"
    case listenerCancelledAt = "listener_cancelled_at"
    case serviceRegistered = "service_registered"
    case listenerReady = "listener_ready"
    case listenerCancelled = "listener_cancelled"
    case network
    case listener
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "mode",
    "claim_eligible",
    "bundle_identifier",
    "process_id",
    "started_at",
    "service_registered_at",
    "listener_ready_at",
    "listener_cancelled_at",
    "service_registered",
    "listener_ready",
    "listener_cancelled",
    "network",
    "listener",
  ]

  public func validate() throws {
    guard schemaVersion == PeerContract.schemaVersion,
      document == PeerContract.primerResultDocument,
      mode == PeerContract.primerMode,
      claimEligible == false,
      bundleIdentifier == PeerContract.bundleIdentifier,
      processID > 0,
      let started = PeerSession.parseTimestamp(startedAt),
      let registered = PeerSession.parseTimestamp(serviceRegisteredAt),
      let ready = PeerSession.parseTimestamp(listenerReadyAt),
      let cancelled = PeerSession.parseTimestamp(listenerCancelledAt),
      started <= registered,
      started <= ready,
      registered <= cancelled,
      ready <= cancelled,
      cancelled.timeIntervalSince(started) <= PeerContract.maximumSessionSeconds,
      serviceRegistered,
      listenerReady,
      listenerCancelled,
      PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: network.interfaceName,
        address: network.ipv4
      ),
      listener == .fixed
    else {
      throw PeerContractError.malformed("local-network primer receipt")
    }
  }

  public func validateFresh(now: Date) throws {
    guard let cancelled = PeerSession.parseTimestamp(listenerCancelledAt),
      cancelled <= now,
      now.timeIntervalSince(cancelled) <= PeerContract.maximumSessionSeconds
    else {
      throw PeerContractError.stalePrimer
    }
  }
}

public enum PeerEvidenceDisposition: String, Codable, Equatable, Sendable {
  case accepted
  case pairRequired = "pair_required"
  case unobserved
}

public enum PeerDeliveryConfirmationCompletion: String, Codable, Equatable, Sendable {
  case processed
  case failed
  case unobserved
}

public enum PeerResultStatus: String, Codable, Equatable, Sendable {
  case closed
  case pairRequired = "pair_required"
  case failed
}

public enum PeerFailurePhase: String, Codable, Equatable, Sendable {
  case none
  case applicationLifecycle = "application_lifecycle"
  case listenerSetup = "listener_setup"
  case listenerRuntime = "listener_runtime"
  case readyPublication = "ready_publication"
  case sessionDeadline = "session_deadline"
  case connectionAdmission = "connection_admission"
  case deliveryEvidence = "delivery_evidence"
  case completionValidation = "completion_validation"
  case listenerShutdown = "listener_shutdown"
  case identityCleanup = "identity_cleanup"
}

public enum PeerFailedService: String, Codable, Equatable, Sendable {
  case none
  case runtime
  case tcpSink = "tcp_sink"
  case tls13Echo = "tls13_echo"
  case quicEcho = "quic_echo"
}

public enum PeerFailureReason: String, Codable, Equatable, Sendable {
  case none
  case applicationLifecycleRequested = "application_lifecycle_requested"
  case listenerSetupFailed = "listener_setup_failed"
  case listenerRuntimeFailed = "listener_runtime_failed"
  case unexpectedListenerCancellation = "unexpected_listener_cancellation"
  case readyPublicationFailed = "ready_publication_failed"
  case sessionDeadlineExpired = "session_deadline_expired"
  case connectionDeadlineExpired = "connection_deadline_expired"
  case connectionAdmissionOverlap = "connection_admission_overlap"
  case echoRuntimeStateConflict = "echo_runtime_state_conflict"
  case echoSendFailed = "echo_send_failed"
  case acknowledgementReceiveFailed = "acknowledgement_receive_failed"
  case acknowledgementInvalid = "acknowledgement_invalid"
  case acknowledgementNotFinal = "acknowledgement_not_final"
  case deliveryCallbackOutOfOrder = "delivery_callback_out_of_order"
  case deliveryCallbackConflict = "delivery_callback_conflict"
  case unexpectedTrailingBytes = "unexpected_trailing_bytes"
  case connectionOverlap = "connection_overlap"
  case completionEvidenceInvalid = "completion_evidence_invalid"
  case completionOverlap = "completion_overlap"
  case completionPayloadInvalid = "completion_payload_invalid"
  case listenerShutdownDeadline = "listener_shutdown_deadline"
  case identityCleanupFailed = "identity_cleanup_failed"
}

public enum PeerPhaseReached: String, Codable, Equatable, Sendable {
  case applicationStarted = "application_started"
  case listenerSetup = "listener_setup"
  case listenersReady = "listeners_ready"
  case connectionAccepted = "connection_accepted"
  case securityReady = "security_ready"
  case payloadReceived = "payload_received"
  case echoCompleted = "echo_completed"
  case acknowledgementReceived = "acknowledgement_received"
  case deliveryConfirmationSubmitted = "delivery_confirmation_submitted"
  case deliveryEvidenceObserved = "delivery_evidence_observed"
  case completionResolved = "completion_resolved"
  case listenerShutdown = "listener_shutdown"
  case identityCleanup = "identity_cleanup"
  case completed

  var rank: Int {
    switch self {
    case .applicationStarted: 0
    case .listenerSetup: 1
    case .listenersReady: 2
    case .connectionAccepted: 3
    case .securityReady: 4
    case .payloadReceived: 5
    case .echoCompleted: 6
    case .acknowledgementReceived: 7
    case .deliveryConfirmationSubmitted: 8
    case .deliveryEvidenceObserved: 9
    case .completionResolved: 10
    case .listenerShutdown: 11
    case .identityCleanup: 12
    case .completed: 13
    }
  }
}

extension PeerService {
  var failedService: PeerFailedService {
    switch self {
    case .tcpSink: .tcpSink
    case .tls13Echo: .tls13Echo
    case .quicEcho: .quicEcho
    }
  }
}

public struct ConnectionOutcome: Codable, Equatable, Sendable {
  public var accepted: Int
  public var evidenceDisposition: PeerEvidenceDisposition
  public var bytesReceived: Int
  public var bytesSent: Int
  public var controlBytesReceived: Int
  public var controlBytesSubmitted: Int
  public var deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion?
  public var peerTerminalObserved: Bool
  public var deliveryAcknowledgementFinalContextObserved: Bool
  public var transport: String?
  public var tlsVersion: UInt16?
  public var cipherSuite: UInt16?
  public var alpn: String?
  public var earlyDataAccepted: Bool?
  public var payloadSHA256: String?

  enum CodingKeys: String, CodingKey {
    case accepted
    case evidenceDisposition = "evidence_disposition"
    case bytesReceived = "bytes_received"
    case bytesSent = "bytes_sent"
    case controlBytesReceived = "control_bytes_received"
    case controlBytesSubmitted = "control_bytes_submitted"
    case deliveryConfirmationCompletion = "delivery_confirmation_completion"
    case peerTerminalObserved = "peer_terminal_observed"
    case deliveryAcknowledgementFinalContextObserved =
      "delivery_acknowledgement_final_context_observed"
    case transport
    case tlsVersion = "tls_version"
    case cipherSuite = "cipher_suite"
    case alpn
    case earlyDataAccepted = "early_data_accepted"
    case payloadSHA256 = "payload_sha256"
  }

  public init(
    accepted: Int = 0,
    evidenceDisposition: PeerEvidenceDisposition = .unobserved,
    bytesReceived: Int = 0,
    bytesSent: Int = 0,
    controlBytesReceived: Int = 0,
    controlBytesSubmitted: Int = 0,
    deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion? = nil,
    peerTerminalObserved: Bool = false,
    deliveryAcknowledgementFinalContextObserved: Bool = false,
    transport: String? = nil,
    tlsVersion: UInt16? = nil,
    cipherSuite: UInt16? = nil,
    alpn: String? = nil,
    earlyDataAccepted: Bool? = nil,
    payloadSHA256: String? = nil
  ) {
    self.accepted = accepted
    self.evidenceDisposition = evidenceDisposition
    self.bytesReceived = bytesReceived
    self.bytesSent = bytesSent
    self.controlBytesReceived = controlBytesReceived
    self.controlBytesSubmitted = controlBytesSubmitted
    self.deliveryConfirmationCompletion = deliveryConfirmationCompletion
    self.peerTerminalObserved = peerTerminalObserved
    self.deliveryAcknowledgementFinalContextObserved =
      deliveryAcknowledgementFinalContextObserved
    self.transport = transport
    self.tlsVersion = tlsVersion
    self.cipherSuite = cipherSuite
    self.alpn = alpn
    self.earlyDataAccepted = earlyDataAccepted
    self.payloadSHA256 = payloadSHA256
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(accepted, forKey: .accepted)
    try container.encode(evidenceDisposition, forKey: .evidenceDisposition)
    try container.encode(bytesReceived, forKey: .bytesReceived)
    try container.encode(bytesSent, forKey: .bytesSent)
    try container.encode(controlBytesReceived, forKey: .controlBytesReceived)
    try container.encode(controlBytesSubmitted, forKey: .controlBytesSubmitted)
    if let deliveryConfirmationCompletion {
      try container.encode(
        deliveryConfirmationCompletion,
        forKey: .deliveryConfirmationCompletion
      )
    } else {
      try container.encodeNil(forKey: .deliveryConfirmationCompletion)
    }
    try container.encode(peerTerminalObserved, forKey: .peerTerminalObserved)
    try container.encode(
      deliveryAcknowledgementFinalContextObserved,
      forKey: .deliveryAcknowledgementFinalContextObserved
    )
    if let transport {
      try container.encode(transport, forKey: .transport)
    } else {
      try container.encodeNil(forKey: .transport)
    }
    if let tlsVersion {
      try container.encode(tlsVersion, forKey: .tlsVersion)
    } else {
      try container.encodeNil(forKey: .tlsVersion)
    }
    if let cipherSuite {
      try container.encode(cipherSuite, forKey: .cipherSuite)
    } else {
      try container.encodeNil(forKey: .cipherSuite)
    }
    if let alpn {
      try container.encode(alpn, forKey: .alpn)
    } else {
      try container.encodeNil(forKey: .alpn)
    }
    if let earlyDataAccepted {
      try container.encode(earlyDataAccepted, forKey: .earlyDataAccepted)
    } else {
      try container.encodeNil(forKey: .earlyDataAccepted)
    }
    if let payloadSHA256 {
      try container.encode(payloadSHA256, forKey: .payloadSHA256)
    } else {
      try container.encodeNil(forKey: .payloadSHA256)
    }
  }
}

public struct ConnectionOutcomes: Codable, Equatable, Sendable {
  public var tcpSink: ConnectionOutcome
  public var tls13Echo: ConnectionOutcome
  public var quicEcho: ConnectionOutcome

  enum CodingKeys: String, CodingKey {
    case tcpSink = "tcp_sink"
    case tls13Echo = "tls13_echo"
    case quicEcho = "quic_echo"
  }

  public init(
    tcpSink: ConnectionOutcome = ConnectionOutcome(),
    tls13Echo: ConnectionOutcome = ConnectionOutcome(),
    quicEcho: ConnectionOutcome = ConnectionOutcome()
  ) {
    self.tcpSink = tcpSink
    self.tls13Echo = tls13Echo
    self.quicEcho = quicEcho
  }
}

extension KeyedEncodingContainer {
  fileprivate mutating func encodeOptional<Value: Encodable>(
    _ value: Value?,
    forKey key: Key
  ) throws {
    if let value {
      try encode(value, forKey: key)
    } else {
      try encodeNil(forKey: key)
    }
  }
}

public struct ResultReceipt: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let evidenceRole: String
  public let claimEligible: Bool
  public let sessionID: String
  public let certificateSHA256: String
  public let bundleIdentifier: String
  public let processID: Int32
  public let completedAt: String
  public let status: PeerResultStatus
  public let failurePhase: PeerFailurePhase
  public let failedService: PeerFailedService
  public let failureReason: PeerFailureReason
  public let phaseReached: PeerPhaseReached
  public let blockingService: PeerFailedService?
  public let blockingPhase: PeerPhaseReached?
  public let blockingAdmissionSequence: Int?
  public let incomingAdmissionSequence: Int?
  public let incomingMatchesBlockerObject: Bool?
  public let blockingQUICStreamIdentifier: UInt64?
  public let listenersClosed: Bool
  public let identityFilesRemoved: Bool
  public let connections: ConnectionOutcomes

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case evidenceRole = "evidence_role"
    case claimEligible = "claim_eligible"
    case sessionID = "session_id"
    case certificateSHA256 = "certificate_sha256"
    case bundleIdentifier = "bundle_identifier"
    case processID = "process_id"
    case completedAt = "completed_at"
    case status
    case failurePhase = "failure_phase"
    case failedService = "failed_service"
    case failureReason = "failure_reason"
    case phaseReached = "phase_reached"
    case blockingService = "blocking_service"
    case blockingPhase = "blocking_phase"
    case blockingAdmissionSequence = "blocking_admission_sequence"
    case incomingAdmissionSequence = "incoming_admission_sequence"
    case incomingMatchesBlockerObject = "incoming_matches_blocker_object"
    case blockingQUICStreamIdentifier = "blocking_quic_stream_identifier"
    case listenersClosed = "listeners_closed"
    case identityFilesRemoved = "identity_files_removed"
    case connections
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(schemaVersion, forKey: .schemaVersion)
    try container.encode(document, forKey: .document)
    try container.encode(evidenceRole, forKey: .evidenceRole)
    try container.encode(claimEligible, forKey: .claimEligible)
    try container.encode(sessionID, forKey: .sessionID)
    try container.encode(certificateSHA256, forKey: .certificateSHA256)
    try container.encode(bundleIdentifier, forKey: .bundleIdentifier)
    try container.encode(processID, forKey: .processID)
    try container.encode(completedAt, forKey: .completedAt)
    try container.encode(status, forKey: .status)
    try container.encode(failurePhase, forKey: .failurePhase)
    try container.encode(failedService, forKey: .failedService)
    try container.encode(failureReason, forKey: .failureReason)
    try container.encode(phaseReached, forKey: .phaseReached)
    try container.encodeOptional(blockingService, forKey: .blockingService)
    try container.encodeOptional(blockingPhase, forKey: .blockingPhase)
    try container.encodeOptional(
      blockingAdmissionSequence,
      forKey: .blockingAdmissionSequence
    )
    try container.encodeOptional(
      incomingAdmissionSequence,
      forKey: .incomingAdmissionSequence
    )
    try container.encodeOptional(
      incomingMatchesBlockerObject,
      forKey: .incomingMatchesBlockerObject
    )
    try container.encodeOptional(
      blockingQUICStreamIdentifier,
      forKey: .blockingQUICStreamIdentifier
    )
    try container.encode(listenersClosed, forKey: .listenersClosed)
    try container.encode(identityFilesRemoved, forKey: .identityFilesRemoved)
    try container.encode(connections, forKey: .connections)
  }

  public func validate() throws {
    guard schemaVersion == PeerContract.resultSchemaVersion,
      document == PeerContract.resultDocument,
      evidenceRole == PeerContract.resultEvidenceRole,
      claimEligible == false,
      PeerSession.isDigest(sessionID),
      PeerSession.isDigest(certificateSHA256),
      bundleIdentifier == PeerContract.bundleIdentifier,
      processID > 0,
      PeerSession.parseTimestamp(completedAt) != nil
    else {
      throw PeerContractError.malformed("result receipt identity")
    }

    try validateOutcome(connections.tcpSink, service: .tcpSink)
    try validateOutcome(connections.tls13Echo, service: .tls13Echo)
    try validateOutcome(connections.quicEcho, service: .quicEcho)
    try validateAdmissionObservation()

    let dispositions = [
      connections.tcpSink.evidenceDisposition,
      connections.tls13Echo.evidenceDisposition,
      connections.quicEcho.evidenceDisposition,
    ]
    switch status {
    case .closed:
      guard failurePhase == .none,
        failedService == .none,
        failureReason == .none,
        phaseReached == .completed,
        listenersClosed,
        identityFilesRemoved,
        dispositions.allSatisfy({ $0 == .accepted })
      else {
        throw PeerContractError.malformed("closed result receipt")
      }
    case .pairRequired:
      guard failurePhase == .none,
        failedService == .none,
        failureReason == .none,
        phaseReached == .completed,
        listenersClosed,
        identityFilesRemoved,
        connections.tcpSink.evidenceDisposition == .accepted,
        [connections.tls13Echo, connections.quicEcho].allSatisfy({ outcome in
          outcome.evidenceDisposition == .accepted
            || outcome.evidenceDisposition == .pairRequired
        }),
        dispositions.contains(.pairRequired)
      else {
        throw PeerContractError.malformed("pair-required result receipt")
      }
    case .failed:
      guard failurePhase != .none,
        failedService != .none,
        failureReason != .none,
        phaseReached != .completed
      else {
        throw PeerContractError.malformed("failed result receipt")
      }
      try validateFailureMetadata()
    }
  }

  private func validateFailureMetadata() throws {
    let isAdmissionOverlap = failureReason == .connectionAdmissionOverlap
    guard isAdmissionOverlap == (failurePhase == .connectionAdmission) else {
      throw PeerContractError.malformed("connection admission failure phase")
    }
    let runtimeReasons: Set<PeerFailureReason> = [
      .applicationLifecycleRequested,
      .listenerSetupFailed,
      .readyPublicationFailed,
      .sessionDeadlineExpired,
      .listenerShutdownDeadline,
      .identityCleanupFailed,
    ]
    let secureDeliveryReasons: Set<PeerFailureReason> = [
      .echoRuntimeStateConflict,
      .echoSendFailed,
      .acknowledgementReceiveFailed,
      .acknowledgementInvalid,
      .acknowledgementNotFinal,
      .deliveryCallbackOutOfOrder,
      .deliveryCallbackConflict,
      .unexpectedTrailingBytes,
      .connectionOverlap,
    ]
    if runtimeReasons.contains(failureReason) {
      guard failedService == .runtime else {
        throw PeerContractError.malformed("runtime failure service")
      }
      return
    }
    if secureDeliveryReasons.contains(failureReason) {
      guard failedService == .tls13Echo || failedService == .quicEcho else {
        throw PeerContractError.malformed("secure delivery failure service")
      }
      return
    }
    switch failureReason {
    case .listenerRuntimeFailed, .unexpectedListenerCancellation,
      .connectionDeadlineExpired, .connectionAdmissionOverlap, .completionOverlap,
      .completionPayloadInvalid:
      guard failedService != .none, failedService != .runtime else {
        throw PeerContractError.malformed("service failure identity")
      }
    case .completionEvidenceInvalid:
      guard failedService != .none else {
        throw PeerContractError.malformed("completion failure identity")
      }
    case .none:
      throw PeerContractError.malformed("failure reason")
    default:
      throw PeerContractError.malformed("failure reason classification")
    }
  }

  private func validateAdmissionObservation() throws {
    let requiredPresence = [
      blockingService != nil,
      blockingPhase != nil,
      blockingAdmissionSequence != nil,
      incomingAdmissionSequence != nil,
      incomingMatchesBlockerObject != nil,
    ]
    let observationPresent = requiredPresence.allSatisfy({ $0 })
    guard observationPresent || requiredPresence.allSatisfy({ !$0 }) else {
      throw PeerContractError.malformed("partial admission overlap observation")
    }
    let isAdmissionOverlap = failureReason == .connectionAdmissionOverlap
    guard observationPresent == isAdmissionOverlap else {
      throw PeerContractError.malformed("admission overlap observation presence")
    }
    guard observationPresent else {
      guard blockingQUICStreamIdentifier == nil else {
        throw PeerContractError.malformed("orphan QUIC stream observation")
      }
      return
    }
    guard let blockingService, let blockingPhase, let blockingAdmissionSequence,
      let incomingAdmissionSequence, let incomingMatchesBlockerObject,
      blockingService != .none,
      blockingService != .runtime,
      blockingPhase.rank >= PeerPhaseReached.connectionAccepted.rank,
      blockingPhase.rank <= PeerPhaseReached.deliveryEvidenceObserved.rank,
      blockingAdmissionSequence > 0,
      blockingAdmissionSequence < incomingAdmissionSequence,
      incomingAdmissionSequence <= PeerContract.maximumConnections,
      !incomingMatchesBlockerObject || blockingService == failedService
    else {
      throw PeerContractError.malformed("admission overlap observation")
    }
    if blockingQUICStreamIdentifier != nil {
      guard blockingService == .quicEcho,
        blockingPhase.rank >= PeerPhaseReached.securityReady.rank
      else {
        throw PeerContractError.malformed("QUIC stream observation binding")
      }
    }
  }

  private func validateOutcome(
    _ outcome: ConnectionOutcome,
    service: PeerService
  ) throws {
    switch outcome.evidenceDisposition {
    case .unobserved:
      guard outcome == ConnectionOutcome() else {
        throw PeerContractError.malformed("unobserved connection outcome")
      }
    case .accepted, .pairRequired:
      let expectedPayload = try PeerProbePayload.payload(for: service, sessionID: sessionID)
      let isSecure = service != .tcpSink
      let expectedTransport =
        switch service {
        case .tcpSink: "tcp4"
        case .tls13Echo: "tls13-tcp4"
        case .quicEcho: "quic-tls13"
        }
      let expectedALPN =
        switch service {
        case .tcpSink: Optional<String>.none
        case .tls13Echo: PeerContract.tlsALPN
        case .quicEcho: PeerContract.quicALPN
        }
      guard outcome.accepted == (outcome.evidenceDisposition == .accepted ? 1 : 0),
        outcome.bytesReceived == expectedPayload.count,
        outcome.bytesSent == (isSecure ? expectedPayload.count + 2 : 0),
        outcome.controlBytesReceived == (isSecure ? 1 : 0),
        outcome.controlBytesSubmitted == (isSecure ? 1 : 0),
        outcome.transport == expectedTransport,
        outcome.payloadSHA256 == PeerDigest.sha256(expectedPayload)
      else {
        throw PeerContractError.malformed("resolved connection outcome")
      }

      if isSecure {
        guard !outcome.peerTerminalObserved,
          outcome.deliveryAcknowledgementFinalContextObserved,
          outcome.tlsVersion == 0x0304,
          outcome.cipherSuite.map({ (0x1301...0x1305).contains($0) }) == true,
          outcome.alpn == expectedALPN,
          outcome.earlyDataAccepted == false
        else {
          throw PeerContractError.malformed("secure connection outcome")
        }
        switch outcome.evidenceDisposition {
        case .accepted:
          throw PeerContractError.malformed("secure outcome cannot be locally accepted")
        case .pairRequired:
          guard
            outcome.deliveryConfirmationCompletion == .processed
              || outcome.deliveryConfirmationCompletion == .failed
              || outcome.deliveryConfirmationCompletion == .unobserved
          else {
            throw PeerContractError.malformed("pair-required delivery confirmation")
          }
        case .unobserved:
          throw PeerContractError.malformed("secure connection disposition")
        }
      } else {
        guard outcome.evidenceDisposition == .accepted,
          outcome.peerTerminalObserved,
          !outcome.deliveryAcknowledgementFinalContextObserved,
          outcome.deliveryConfirmationCompletion == nil,
          outcome.tlsVersion == nil,
          outcome.cipherSuite == nil,
          outcome.alpn == nil,
          outcome.earlyDataAccepted == nil
        else {
          throw PeerContractError.malformed("TCP connection outcome")
        }
      }
    }
  }
}

public enum ExactJSON {
  public static func decodeSession(_ data: Data) throws -> PeerSession {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw PeerContractError.malformed("session size or terminator")
    }
    let body = data.dropLast()
    let value = try JSONSerialization.jsonObject(with: Data(body), options: [])
    guard let dictionary = value as? [String: Any],
      Set(dictionary.keys) == PeerSession.exactFields
    else {
      throw PeerContractError.malformed("session fields")
    }
    let canonical = try canonicalData(fromJSONObject: dictionary)
    guard canonical == data else {
      throw PeerContractError.malformed("session canonical JSON")
    }
    return try JSONDecoder().decode(PeerSession.self, from: Data(body))
  }

  public static func decodeReady(_ data: Data) throws -> ReadyReceipt {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw PeerContractError.malformed("ready size or terminator")
    }
    let body = data.dropLast()
    let value = try JSONSerialization.jsonObject(with: Data(body), options: [])
    guard let dictionary = value as? [String: Any],
      Set(dictionary.keys) == ReadyReceipt.exactFields,
      let network = dictionary["network"] as? [String: Any],
      Set(network.keys) == PeerNetworkReceipt.exactFields,
      let listeners = dictionary["listeners"] as? [String: Any],
      Set(listeners.keys) == ListenerReceipts.exactFields,
      listeners.values.allSatisfy({ value in
        guard let listener = value as? [String: Any] else { return false }
        return Set(listener.keys) == ListenerReceipt.exactFields
      })
    else {
      throw PeerContractError.malformed("ready fields")
    }
    let canonical = try canonicalData(fromJSONObject: dictionary)
    guard canonical == data else {
      throw PeerContractError.malformed("ready canonical JSON")
    }
    return try JSONDecoder().decode(ReadyReceipt.self, from: Data(body))
  }

  public static func decodePrimerResult(_ data: Data) throws -> LocalNetworkPrimerReceipt {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw PeerContractError.malformed("primer result size or terminator")
    }
    let body = data.dropLast()
    let value = try JSONSerialization.jsonObject(with: Data(body), options: [])
    guard let dictionary = value as? [String: Any],
      Set(dictionary.keys) == LocalNetworkPrimerReceipt.exactFields,
      let network = dictionary["network"] as? [String: Any],
      Set(network.keys) == PeerNetworkReceipt.exactFields,
      let listener = dictionary["listener"] as? [String: Any],
      Set(listener.keys) == PrimerListenerReceipt.exactFields
    else {
      throw PeerContractError.malformed("primer result fields")
    }
    let canonical = try canonicalData(fromJSONObject: dictionary)
    guard canonical == data else {
      throw PeerContractError.malformed("primer result canonical JSON")
    }
    let receipt = try JSONDecoder().decode(LocalNetworkPrimerReceipt.self, from: Data(body))
    try receipt.validate()
    return receipt
  }

  public static func encode<T: Encodable>(_ value: T) throws -> Data {
    let encoded = try JSONEncoder().encode(value)
    let object = try JSONSerialization.jsonObject(with: encoded, options: [])
    return try canonicalData(fromJSONObject: object)
  }

  static func canonicalData(fromJSONObject object: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else {
      throw PeerContractError.malformed("canonical JSON value")
    }
    var data = try JSONSerialization.data(
      withJSONObject: object,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    data.append(0x0A)
    return data
  }
}

public enum PeerDigest {
  public static func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
}

public enum PeerProbePayload {
  public static func payload(for service: PeerService, sessionID: String) throws -> Data {
    guard PeerSession.isDigest(sessionID), let sessionBytes = Data(hexadecimal: sessionID) else {
      throw PeerContractError.malformed("probe session ID")
    }
    let domain: String
    switch service {
    case .tcpSink:
      domain = "cfm-ios-transport-peer-tcp-payload-v1\0"
    case .tls13Echo:
      domain = "cfm-ios-transport-peer-tls-payload-v1\0"
    case .quicEcho:
      domain = "cfm-ios-transport-peer-quic-payload-v1\0"
    }
    var digest = SHA256()
    digest.update(data: Data(domain.utf8))
    digest.update(data: sessionBytes)
    return Data(digest.finalize())
  }
}

extension Data {
  fileprivate init?(hexadecimal: String) {
    guard hexadecimal.count.isMultiple(of: 2) else { return nil }
    var bytes = Data(capacity: hexadecimal.count / 2)
    var index = hexadecimal.startIndex
    while index < hexadecimal.endIndex {
      let end = hexadecimal.index(index, offsetBy: 2)
      guard let byte = UInt8(hexadecimal[index..<end], radix: 16) else { return nil }
      bytes.append(byte)
      index = end
    }
    self = bytes
  }
}
