import Foundation

public enum PacketLanPeerContract {
  public static let schemaVersion = 1
  public static let sessionDocument = "cfm-ios-packet-lan-peer-session-v1"
  public static let readyDocument = "cfm-ios-packet-lan-peer-ready-v1"
  public static let resultDocument = "cfm-ios-packet-lan-peer-result-v1"
  public static let evidenceRole = "server_observation_only"
  public static let launchArgument = "--cfm-packet-lan-run-v1"
  public static let directoryName = "CFMPacketLanPeer"
  public static let sessionFileName = "session.json"
  public static let readyFileName = "ready.json"
  public static let resultFileName = "result.json"
  public static let caseID = "lan-bypass"
  public static let listenerPort: UInt16 = PeerContract.tcpSinkPort
  public static let transport = "tcp4"
  public static let tokenBytes = 20
  public static let connectionDeadlineSeconds: TimeInterval = 5
  public static let failureFinalizationGraceSeconds: TimeInterval = 10
  public static let maximumSessionSeconds: TimeInterval = 15 * 60
}

public enum PacketLanStage: String, Codable, CaseIterable, Sendable {
  case start
  case target
  case end

  var expectedPrefix: UInt8 {
    switch self {
    case .start: Character("s").asciiValue!
    case .target: Character("t").asciiValue!
    case .end: Character("e").asciiValue!
    }
  }
}

public struct PacketLanTokenDigests: Codable, Equatable, Sendable {
  public let start: String
  public let target: String
  public let end: String

  enum CodingKeys: String, CodingKey, CaseIterable {
    case start
    case target
    case end
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public init(start: String, target: String, end: String) {
    self.start = start
    self.target = target
    self.end = end
  }

  public func validate() throws {
    let values = [start, target, end]
    guard values.allSatisfy(PeerSession.isDigest), Set(values).count == values.count else {
      throw PeerContractError.malformed("packet LAN token digests")
    }
  }

  public func digest(for stage: PacketLanStage) -> String {
    switch stage {
    case .start: start
    case .target: target
    case .end: end
    }
  }
}

public struct PacketLanPeerSession: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let sessionID: String
  public let caseID: String
  public let createdAt: String
  public let expiresAt: String
  public let listenerPort: UInt16
  public let stageTokenSHA256: PacketLanTokenDigests

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion = "schema_version"
    case document
    case sessionID = "session_id"
    case caseID = "case_id"
    case createdAt = "created_at"
    case expiresAt = "expires_at"
    case listenerPort = "listener_port"
    case stageTokenSHA256 = "stage_token_sha256"
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public init(
    schemaVersion: Int,
    document: String,
    sessionID: String,
    caseID: String,
    createdAt: String,
    expiresAt: String,
    listenerPort: UInt16,
    stageTokenSHA256: PacketLanTokenDigests
  ) {
    self.schemaVersion = schemaVersion
    self.document = document
    self.sessionID = sessionID
    self.caseID = caseID
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.listenerPort = listenerPort
    self.stageTokenSHA256 = stageTokenSHA256
  }

  @discardableResult
  public func validate(now: Date) throws -> (createdAt: Date, expiresAt: Date) {
    guard schemaVersion == PacketLanPeerContract.schemaVersion,
      document == PacketLanPeerContract.sessionDocument,
      PeerSession.isDigest(sessionID),
      caseID == PacketLanPeerContract.caseID,
      listenerPort == PacketLanPeerContract.listenerPort,
      let created = PeerSession.parseTimestamp(createdAt),
      let expires = PeerSession.parseTimestamp(expiresAt),
      created <= now,
      now < expires,
      expires.timeIntervalSince(created) <= PacketLanPeerContract.maximumSessionSeconds
    else {
      throw PeerContractError.malformed("packet LAN session identity")
    }
    try stageTokenSHA256.validate()
    return (created, expires)
  }
}

public struct PacketLanListenerReceipt: Codable, Equatable, Sendable {
  public let port: UInt16
  public let transport: String

  enum CodingKeys: String, CodingKey, CaseIterable {
    case port
    case transport
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public static let fixed = PacketLanListenerReceipt(
    port: PacketLanPeerContract.listenerPort,
    transport: PacketLanPeerContract.transport
  )
}

public struct PacketLanReadyReceipt: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let evidenceRole: String
  public let claimEligible: Bool
  public let sessionID: String
  public let bundleIdentifier: String
  public let processID: Int32
  public let startedAt: String
  public let expiresAt: String
  public let network: PeerNetworkReceipt
  public let listener: PacketLanListenerReceipt
  public let sessionFileRemoved: Bool

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion = "schema_version"
    case document
    case evidenceRole = "evidence_role"
    case claimEligible = "claim_eligible"
    case sessionID = "session_id"
    case bundleIdentifier = "bundle_identifier"
    case processID = "process_id"
    case startedAt = "started_at"
    case expiresAt = "expires_at"
    case network
    case listener
    case sessionFileRemoved = "session_file_removed"
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public func validate(session: PacketLanPeerSession) throws {
    let created = PeerSession.parseTimestamp(session.createdAt)
    let started = PeerSession.parseTimestamp(startedAt)
    let expires = PeerSession.parseTimestamp(session.expiresAt)
    guard schemaVersion == PacketLanPeerContract.schemaVersion,
      document == PacketLanPeerContract.readyDocument,
      evidenceRole == PacketLanPeerContract.evidenceRole,
      claimEligible == false,
      sessionID == session.sessionID,
      bundleIdentifier == PeerContract.bundleIdentifier,
      processID > 0,
      let created,
      let started,
      let expires,
      created <= started,
      started < expires,
      expiresAt == session.expiresAt,
      listener == .fixed,
      sessionFileRemoved
    else {
      throw PeerContractError.malformed("packet LAN ready receipt")
    }
  }
}

public struct PacketLanConnectionReceipt: Codable, Equatable, Sendable {
  public let stage: PacketLanStage
  public let admissionSequence: Int
  public let tokenSHA256: String
  public let bytesReceived: Int
  public let eofObserved: Bool
  public let peerIPv4: String
  public let peerPort: UInt16

  enum CodingKeys: String, CodingKey, CaseIterable {
    case stage
    case admissionSequence = "admission_sequence"
    case tokenSHA256 = "token_sha256"
    case bytesReceived = "bytes_received"
    case eofObserved = "eof_observed"
    case peerIPv4 = "peer_ipv4"
    case peerPort = "peer_port"
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public func validate(
    session: PacketLanPeerSession,
    expectedSequence: Int,
    localIPv4: String
  ) throws {
    guard (1...PacketLanStage.allCases.count).contains(expectedSequence),
      admissionSequence == expectedSequence,
      PacketLanStage.allCases[expectedSequence - 1] == stage,
      tokenSHA256 == session.stageTokenSHA256.digest(for: stage),
      bytesReceived == PacketLanPeerContract.tokenBytes,
      eofObserved,
      PeerNetworkIdentity.isControlledLANIPv4(peerIPv4),
      peerIPv4 != localIPv4,
      (49_152...65_535).contains(Int(peerPort))
    else {
      throw PeerContractError.malformed("packet LAN connection receipt")
    }
  }
}

public enum PacketLanResultStatus: String, Codable, Sendable {
  case closed
  case failed
}

public enum PacketLanFailurePhase: String, Codable, Sendable {
  case none
  case applicationLifecycle = "application_lifecycle"
  case connectionAdmission = "connection_admission"
  case payloadDelivery = "payload_delivery"
  case sessionDeadline = "session_deadline"
  case listenerRuntime = "listener_runtime"
  case listenerShutdown = "listener_shutdown"
}

public enum PacketLanFailureReason: String, Codable, Sendable {
  case none
  case applicationLifecycleRequested = "application_lifecycle_requested"
  case connectionOverlap = "connection_overlap"
  case extraConnection = "extra_connection"
  case connectionDeadlineExpired = "connection_deadline_expired"
  case connectionTerminated = "connection_terminated"
  case payloadInvalid = "payload_invalid"
  case clientEndpointInvalid = "client_endpoint_invalid"
  case sessionDeadlineExpired = "session_deadline_expired"
  case listenerRuntimeFailed = "listener_runtime_failed"
  case networkIdentityChanged = "network_identity_changed"
  case listenerShutdownFailed = "listener_shutdown_failed"

  var expectedPhase: PacketLanFailurePhase? {
    switch self {
    case .none:
      nil
    case .applicationLifecycleRequested:
      .applicationLifecycle
    case .connectionOverlap, .extraConnection:
      .connectionAdmission
    case .connectionDeadlineExpired, .connectionTerminated, .payloadInvalid,
      .clientEndpointInvalid:
      .payloadDelivery
    case .sessionDeadlineExpired:
      .sessionDeadline
    case .listenerRuntimeFailed, .networkIdentityChanged:
      .listenerRuntime
    case .listenerShutdownFailed:
      .listenerShutdown
    }
  }
}

public struct PacketLanResultReceipt: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let evidenceRole: String
  public let claimEligible: Bool
  public let sessionID: String
  public let readySHA256: String
  public let bundleIdentifier: String
  public let processID: Int32
  public let completedAt: String
  public let status: PacketLanResultStatus
  public let failurePhase: PacketLanFailurePhase
  public let failureReason: PacketLanFailureReason
  public let network: PeerNetworkReceipt
  public let listener: PacketLanListenerReceipt
  public let listenerClosed: Bool
  public let sessionFileRemoved: Bool
  public let connections: [PacketLanConnectionReceipt]

  enum CodingKeys: String, CodingKey, CaseIterable {
    case schemaVersion = "schema_version"
    case document
    case evidenceRole = "evidence_role"
    case claimEligible = "claim_eligible"
    case sessionID = "session_id"
    case readySHA256 = "ready_sha256"
    case bundleIdentifier = "bundle_identifier"
    case processID = "process_id"
    case completedAt = "completed_at"
    case status
    case failurePhase = "failure_phase"
    case failureReason = "failure_reason"
    case network
    case listener
    case listenerClosed = "listener_closed"
    case sessionFileRemoved = "session_file_removed"
    case connections
  }

  static let exactFields = Set(CodingKeys.allCases.map(\.rawValue))

  public func validate(
    session: PacketLanPeerSession,
    ready: PacketLanReadyReceipt
  ) throws {
    let readyData = try ExactJSON.encode(ready)
    let started = PeerSession.parseTimestamp(ready.startedAt)
    let completed = PeerSession.parseTimestamp(completedAt)
    let expires = PeerSession.parseTimestamp(ready.expiresAt)
    guard schemaVersion == PacketLanPeerContract.schemaVersion,
      document == PacketLanPeerContract.resultDocument,
      evidenceRole == PacketLanPeerContract.evidenceRole,
      claimEligible == false,
      sessionID == session.sessionID,
      readySHA256 == PeerDigest.sha256(readyData),
      bundleIdentifier == PeerContract.bundleIdentifier,
      processID == ready.processID,
      let started,
      let completed,
      let expires,
      started <= completed,
      network == ready.network,
      listener == .fixed,
      listenerClosed,
      sessionFileRemoved,
      connections.count <= PacketLanStage.allCases.count
    else {
      throw PeerContractError.malformed("packet LAN result identity")
    }
    for (index, connection) in connections.enumerated() {
      try connection.validate(
        session: session,
        expectedSequence: index + 1,
        localIPv4: network.ipv4
      )
    }
    guard Set(connections.map(\.peerPort)).count == connections.count,
      Set(connections.map(\.peerIPv4)).count <= 1
    else {
      throw PeerContractError.malformed("packet LAN client identity")
    }
    switch status {
    case .closed:
      guard failurePhase == .none,
        failureReason == .none,
        completed <= expires,
        connections.count == PacketLanStage.allCases.count
      else {
        throw PeerContractError.malformed("closed packet LAN result")
      }
    case .failed:
      guard failurePhase != .none,
        failureReason != .none,
        failureReason.expectedPhase == failurePhase,
        completed
          <= expires.addingTimeInterval(
            PacketLanPeerContract.failureFinalizationGraceSeconds
          )
      else {
        throw PeerContractError.malformed("failed packet LAN result")
      }
    }
  }
}

public enum PacketLanTrackerDecision: Equatable, Sendable {
  case continueRunning
  case close
  case fail(PacketLanFailureReason)
}

public struct PacketLanCompletionTracker: Equatable, Sendable {
  public private(set) var connections: [PacketLanConnectionReceipt] = []
  private let session: PacketLanPeerSession
  private let localIPv4: String

  public init(session: PacketLanPeerSession, localIPv4: String) throws {
    guard PeerNetworkIdentity.isControlledLANIPv4(localIPv4) else {
      throw PeerContractError.malformed("packet LAN local IPv4")
    }
    self.session = session
    self.localIPv4 = localIPv4
  }

  public mutating func record(
    payload: Data,
    eofObserved: Bool,
    peerIPv4: String,
    peerPort: UInt16
  ) -> PacketLanTrackerDecision {
    guard connections.count < PacketLanStage.allCases.count else {
      return .fail(.extraConnection)
    }
    let stage = PacketLanStage.allCases[connections.count]
    guard payload.count == PacketLanPeerContract.tokenBytes,
      payload.first == stage.expectedPrefix,
      payload.allSatisfy(Self.isCanonicalTokenByte),
      eofObserved,
      PeerDigest.sha256(payload) == session.stageTokenSHA256.digest(for: stage)
    else {
      return .fail(.payloadInvalid)
    }
    guard PeerNetworkIdentity.isControlledLANIPv4(peerIPv4),
      peerIPv4 != localIPv4,
      (49_152...65_535).contains(Int(peerPort)),
      connections.allSatisfy({ $0.peerIPv4 == peerIPv4 && $0.peerPort != peerPort })
    else {
      return .fail(.clientEndpointInvalid)
    }
    connections.append(
      PacketLanConnectionReceipt(
        stage: stage,
        admissionSequence: connections.count + 1,
        tokenSHA256: PeerDigest.sha256(payload),
        bytesReceived: payload.count,
        eofObserved: true,
        peerIPv4: peerIPv4,
        peerPort: peerPort
      )
    )
    return connections.count == PacketLanStage.allCases.count ? .close : .continueRunning
  }

  private static func isCanonicalTokenByte(_ byte: UInt8) -> Bool {
    (48...57).contains(byte)
      || (65...90).contains(byte)
      || (97...122).contains(byte)
      || byte == 0x2E
      || byte == 0x5F
      || byte == 0x3A
      || byte == 0x2D
  }
}

extension ExactJSON {
  public static func decodePacketLanSession(_ data: Data) throws -> PacketLanPeerSession {
    let dictionary = try packetLanDictionary(
      data,
      exactFields: PacketLanPeerSession.exactFields,
      label: "packet LAN session"
    )
    guard let digests = dictionary["stage_token_sha256"] as? [String: Any],
      Set(digests.keys) == PacketLanTokenDigests.exactFields
    else {
      throw PeerContractError.malformed("packet LAN session token fields")
    }
    return try JSONDecoder().decode(
      PacketLanPeerSession.self,
      from: Data(data.dropLast())
    )
  }

  public static func decodePacketLanReady(_ data: Data) throws -> PacketLanReadyReceipt {
    let dictionary = try packetLanDictionary(
      data,
      exactFields: PacketLanReadyReceipt.exactFields,
      label: "packet LAN ready"
    )
    guard let network = dictionary["network"] as? [String: Any],
      Set(network.keys) == PeerNetworkReceipt.exactFields,
      let listener = dictionary["listener"] as? [String: Any],
      Set(listener.keys) == PacketLanListenerReceipt.exactFields
    else {
      throw PeerContractError.malformed("packet LAN ready nested fields")
    }
    return try JSONDecoder().decode(
      PacketLanReadyReceipt.self,
      from: Data(data.dropLast())
    )
  }

  public static func decodePacketLanResult(_ data: Data) throws -> PacketLanResultReceipt {
    let dictionary = try packetLanDictionary(
      data,
      exactFields: PacketLanResultReceipt.exactFields,
      label: "packet LAN result"
    )
    guard let network = dictionary["network"] as? [String: Any],
      Set(network.keys) == PeerNetworkReceipt.exactFields,
      let listener = dictionary["listener"] as? [String: Any],
      Set(listener.keys) == PacketLanListenerReceipt.exactFields,
      let connections = dictionary["connections"] as? [[String: Any]],
      connections.allSatisfy({ Set($0.keys) == PacketLanConnectionReceipt.exactFields })
    else {
      throw PeerContractError.malformed("packet LAN result nested fields")
    }
    return try JSONDecoder().decode(
      PacketLanResultReceipt.self,
      from: Data(data.dropLast())
    )
  }

  private static func packetLanDictionary(
    _ data: Data,
    exactFields: Set<String>,
    label: String
  ) throws -> [String: Any] {
    guard data.count > 1,
      data.count <= PeerContract.maximumJSONBytes,
      data.last == 0x0A
    else {
      throw PeerContractError.malformed("\(label) size or terminator")
    }
    let body = data.dropLast()
    let value = try JSONSerialization.jsonObject(with: Data(body), options: [])
    guard let dictionary = value as? [String: Any],
      Set(dictionary.keys) == exactFields,
      try canonicalData(fromJSONObject: dictionary) == data
    else {
      throw PeerContractError.malformed("\(label) fields or canonical JSON")
    }
    return dictionary
  }
}
