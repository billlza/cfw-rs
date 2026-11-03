import CFWSharedProtocol

public struct AuthorityOwnerBinding: Equatable, Sendable {
  public let operation: OperationContext
  public let leaseID: AuthorityIdentifier
  public let leaseOwnerUID: UInt32
  public let connectionNonce: SHA256Digest
  public let role: AuthorityRole
  public let mode: AuthorityMode

  public init(
    operation: OperationContext, leaseID: AuthorityIdentifier,
    leaseOwnerUID: UInt32, connectionNonce: SHA256Digest,
    role: AuthorityRole, mode: AuthorityMode
  ) {
    self.operation = operation
    self.leaseID = leaseID
    self.leaseOwnerUID = leaseOwnerUID
    self.connectionNonce = connectionNonce
    self.role = role
    self.mode = mode
  }
}

public struct AuthorityPrepareInput: Sendable {
  public let request: PrepareStartRequest
  public let leaseID: AuthorityIdentifier
  public let ownerConnectionNonce: SHA256Digest
  public let issuedMonotonic: UInt64
  public let expiryMonotonic: UInt64
  public let retainsSecretBuffer: Bool

  public init(
    request: PrepareStartRequest, leaseID: AuthorityIdentifier,
    ownerConnectionNonce: SHA256Digest, issuedMonotonic: UInt64,
    expiryMonotonic: UInt64, retainsSecretBuffer: Bool
  ) {
    self.request = request
    self.leaseID = leaseID
    self.ownerConnectionNonce = ownerConnectionNonce
    self.issuedMonotonic = issuedMonotonic
    self.expiryMonotonic = expiryMonotonic
    self.retainsSecretBuffer = retainsSecretBuffer
  }
}

public enum AuthorityCapabilityCommand: Equatable, Sendable {
  case issueProxyCapability
  case issueTunnelTicket
}

public struct AuthorityPrepareAuthorization: Equatable, Sendable {
  public let leaseID: AuthorityIdentifier
  public let operation: OperationContext
  public let command: AuthorityCapabilityCommand
  public let committedRevision: UInt64
}

public enum AuthorityPendingMutation: Equatable, Sendable {
  case prepare(AuthorityIdentifier)
  case transition(AuthorityIdentifier)
  case globalOff(AuthorityIdentifier?)
}

public enum AuthorityDurableMutationKind: String, Equatable, Sendable {
  case enrollOff = "enroll_off"
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
