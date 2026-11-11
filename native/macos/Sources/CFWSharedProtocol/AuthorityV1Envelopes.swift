import Foundation

public enum AuthorityCommand: Sendable {
  case handshake(HandshakeRequest)
  case prepareStart(PrepareStartRequest)
  case bindProxyOwner(BindProxyOwnerRequest)
  case redeemTunnelTicket(RedeemTunnelTicketRequest)
  case attestReady(ReadyAttestation)
  case beginStop(BeginStopRequest)
  case completeStop(CompleteStopRequest)
  case reconcileOff(ReconcileOffRequest)
  case attestStopped(StoppedAttestation)
  case cancelPrepared(CancelPreparedRequest)
  case snapshot(SnapshotRequest)
  case installationRecoveryIdentity(SnapshotRequest)
  case ownerLeaseStatus(OwnerLeaseStatusRequest)

  public var isReadOnly: Bool {
    switch self {
    case .handshake, .snapshot, .ownerLeaseStatus, .installationRecoveryIdentity: true
    default: false
    }
  }
}

public struct AuthorityRequestEnvelope: Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let requiredFeatureBits: UInt64
  public let requestID: AuthorityIdentifier
  public let command: AuthorityCommand

  public init(
    requestID: AuthorityIdentifier, requiredFeatureBits: UInt64 = 0,
    command: AuthorityCommand
  ) throws {
    let unsupported = requiredFeatureBits & ~AuthorityV1Limits.supportedFeatureBits
    guard unsupported == 0 else {
      throw AuthorityV1ValidationError.unsupportedRequiredFeatures(unsupported)
    }
    major = AuthorityV1Limits.major
    minor = AuthorityV1Limits.minor
    self.requiredFeatureBits = requiredFeatureBits
    self.requestID = requestID
    self.command = command
  }
}

public enum AuthorityEvent: Codable, Equatable, Sendable {
  case snapshot(AuthoritySnapshot)
  case revoke(StopDirective)
  case stop(StopDirective)

  enum CodingKeys: String, CodingKey { case kind, payload }
  enum Kind: String, Codable { case snapshot, revoke, stop }

  public init(from decoder: Decoder) throws {
    let value = try decoder.container(keyedBy: CodingKeys.self)
    switch try value.decode(Kind.self, forKey: .kind) {
    case .snapshot: self = .snapshot(try value.decode(AuthoritySnapshot.self, forKey: .payload))
    case .revoke: self = .revoke(try value.decode(StopDirective.self, forKey: .payload))
    case .stop: self = .stop(try value.decode(StopDirective.self, forKey: .payload))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var value = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .snapshot(let payload):
      try value.encode(Kind.snapshot, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    case .revoke(let payload):
      try value.encode(Kind.revoke, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    case .stop(let payload):
      try value.encode(Kind.stop, forKey: .kind)
      try value.encode(payload, forKey: .payload)
    }
  }
}

public struct AuthorityConcurrencyLimits: Equatable, Sendable {
  public let maximumReadOnlyRequests = AuthorityV1Limits.maximumReadOnlyRequests
  public let maximumMutatingTransactions = AuthorityV1Limits.maximumMutatingTransactions
  public let maximumQueuedEventsPerPeer = AuthorityV1Limits.maximumQueuedEventsPerPeer
  public init() {}
}

public struct AuthorityResponseEnvelope<Payload: Codable & Sendable>: Codable, Sendable {
  public let major: UInt16
  public let minor: UInt16
  public let requestID: AuthorityIdentifier
  public let operationID: AuthorityIdentifier?
  public let result: Payload

  public init(
    requestID: AuthorityIdentifier, operationID: AuthorityIdentifier?, result: Payload
  ) {
    major = AuthorityV1Limits.major
    minor = AuthorityV1Limits.minor
    self.requestID = requestID
    self.operationID = operationID
    self.result = result
  }

  enum CodingKeys: String, CodingKey {
    case major, minor
    case requestID = "request_id"
    case operationID = "operation_id"
    case result
  }
}
