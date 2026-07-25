import CFWSharedProtocol
import Darwin
import Foundation

import struct CryptoKit.SHA256

public protocol AuthorityJournalCommitting: Sendable {
  @discardableResult
  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead
}

extension DescriptorRelativeAuthorityJournalStore: AuthorityJournalCommitting {}

public protocol AuthorityReadyObservationProviding: Sendable {
  func observation(for attestation: ReadyAttestation) -> AuthorityOSReadyObservation
}

public struct FailClosedAuthorityReadyObservationProvider:
  AuthorityReadyObservationProviding
{
  public init() {}
  public func observation(
    for attestation: ReadyAttestation
  ) -> AuthorityOSReadyObservation {
    AuthorityOSReadyObservation(
      operation: attestation.operation,
      configSHA256: attestation.operation.configSHA256,
      state: .notReady)
  }
}

public final class AuthorityConcurrencyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var reads = 0
  private var mutation = false

  public init() {}

  public func withRead<Result>(_ body: () throws -> Result) throws -> Result {
    try lock.withLock {
      guard reads < AuthorityV1Limits.maximumReadOnlyRequests else {
        throw AuthorityDomainError(code: .resourceExhausted)
      }
      reads += 1
    }
    defer { lock.withLock { reads -= 1 } }
    return try body()
  }

  public func withMutation<Result>(_ body: () throws -> Result) throws -> Result {
    try lock.withLock {
      guard !mutation else { throw AuthorityDomainError(code: .busy) }
      mutation = true
    }
    defer { lock.withLock { mutation = false } }
    return try body()
  }
}
private struct PendingProxyCapability {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
  let digest: SHA256Digest
}

/// The reasons the Authority forcibly revokes and stops the current owner outside a
/// cooperative `beginStop`. Every reason fails closed: the owner is ordered to stop
/// within the bounded deadline and the lease is never transferred to another user.
public enum AuthorityLivenessTrigger: Equatable, Sendable {
  case logout
  case consoleUserChange
  case connectionLoss
  case missedHeartbeat
  case ownerIdentityDrift
  case ownerStopTimeout
  case reattestTimeout
}

/// Result of a forced revocation. `directive` (when present) must be delivered to the
/// owner peer as a revocation event so the owner stops within the deadline; the queue
/// preserves revocation/stop events under saturation.
public struct AuthorityForcedStopOutcome: Sendable {
  public let directive: StopDirective?
  public let ownerPeerID: UUID?
  public let revision: UInt64
  public let quarantined: Bool

  public init(
    directive: StopDirective?, ownerPeerID: UUID?,
    revision: UInt64, quarantined: Bool
  ) {
    self.directive = directive
    self.ownerPeerID = ownerPeerID
    self.revision = revision
    self.quarantined = quarantined
  }
}

public final class GlobalAuthorityServiceCore: @unchecked Sendable {
  private let lock = NSLock()
  private let journal: any AuthorityJournalCommitting
  private let randomness: any AuthorityTicketRandomness
  private let clock: any AuthorityMonotonicClock
  private let secrets: TunnelSecretLifecycle
  private let readyObservations: any AuthorityReadyObservationProviding
  private var reducer: GlobalAuthorityReducer
  private var proxyCapability: PendingProxyCapability?
  private var configurationDescriptor: AuthorityConfigurationDescriptor?
  private var boundPeerID: UUID?

  public init(
    reducer: GlobalAuthorityReducer,
    journal: any AuthorityJournalCommitting,
    randomness: any AuthorityTicketRandomness = SystemAuthorityTicketRandomness(),
    clock: any AuthorityMonotonicClock = SystemAuthorityMonotonicClock(),
    readyObservations: any AuthorityReadyObservationProviding =
      FailClosedAuthorityReadyObservationProvider()
  ) {
    self.reducer = reducer
    self.journal = journal
    self.randomness = randomness
    self.clock = clock
    self.readyObservations = readyObservations
    secrets = TunnelSecretLifecycle(randomness: randomness, clock: clock)
  }

  public var leaseOwnerUID: uid_t? {
    lock.withLock { reducer.lease.map { uid_t($0.operation.ownerUID) } }
  }

  /// Current durable machine-wide state. Exposed for the liveness supervisor and
  /// recovery reconciliation; never discloses lease secrets.
  public var authorityState: AuthorityState { lock.withLock { reducer.state } }

  public var currentRevision: UInt64 { lock.withLock { reducer.revision } }

  /// True once the current owner has durably attested a stop. Used by the liveness
  /// supervisor to escalate an elapsed stop timeout to Quarantined.
  public var ownerHasAttestedStopped: Bool { lock.withLock { reducer.ownerStopped } }

  /// Re-observes the public live console user and revokes the lease when the owner's
  /// user is no longer the live console user (Fast User Switching or logout). Returns
  /// a forced-stop outcome only when a revocation was durably committed; a lock screen
  /// that preserves the same console UID performs no transition and returns nil. The
  /// lease is never transferred to the new user.
  @discardableResult
  public func observeLiveConsoleUser(
    _ liveConsoleUID: uid_t?
  ) throws -> AuthorityForcedStopOutcome? {
    try lock.withLock {
      guard let lease = reducer.lease else { return nil }
      let before = reducer.revision
      var candidate = reducer
      let revision = try candidate.revokeForConsoleChange(
        liveConsoleUID: liveConsoleUID.map { UInt32($0) },
        ownerConnectionNonce: lease.ownerConnectionNonce)
      guard revision != before else { return nil }
      try persist(candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try forcedOutcomeLocked(revision: revision)
    }
  }

  /// Forced revocation for an owner-liveness failure (connection loss, missed
  /// heartbeat, owner identity drift, or an elapsed stop/reattest timeout). Returns a
  /// forced-stop outcome only when a revocation was durably committed.
  @discardableResult
  public func forceStop(
    trigger: AuthorityLivenessTrigger
  ) throws -> AuthorityForcedStopOutcome? {
    try lock.withLock {
      guard reducer.lease != nil else { return nil }
      let before = reducer.revision
      var candidate = reducer
      let revision = try candidate.revokeForLiveness()
      guard revision != before else { return nil }
      try persist(candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try forcedOutcomeLocked(revision: revision)
    }
  }

  /// Applies an owner/OS Off proof. Off is committed only when every barrier
  /// predicate is proven; any ambiguity retains Quarantined instead of Off.
  @discardableResult
  public func resolveOff(_ proof: GlobalOffProof) throws -> AuthorityOffResolution {
    try lock.withLock {
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        proof, expectedRevision: reducer.revision)
      try persist(candidate)
      reducer = candidate
      if case .off = resolution {
        proxyCapability = nil
        configurationDescriptor = nil
        boundPeerID = nil
      }
      secrets.terminate(.cancellation)
      return resolution
    }
  }

  private func forcedOutcomeLocked(
    revision: UInt64
  ) throws -> AuthorityForcedStopOutcome {
    let directive: StopDirective?
    if let lease = reducer.lease {
      directive = try StopDirective(
        operation: lease.operation, leaseID: lease.leaseID,
        deadlineMonotonic: stopDeadline(), revision: revision)
    } else {
      directive = nil
    }
    return AuthorityForcedStopOutcome(
      directive: directive, ownerPeerID: boundPeerID,
      revision: revision, quarantined: reducer.state == .quarantined)
  }

  public func handshake(_ request: HandshakeRequest) throws -> HandshakeResponse {
    try request.validateAuthorityV1()
    guard request.version == (try AuthorityProtocolVersion()) else {
      throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
    }
    return try HandshakeResponse.v1()
  }

  public func prepare(
    _ request: PrepareStartRequest, configuration: Data,
    secretPayload: Data?, peer: PeerIdentity
  ) throws -> PreparedStart {
    guard peer.role == .host, peer.euid == request.operation.ownerUID else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    try AuthorityV1Codec.validateConfiguration(
      configuration, descriptor: request.configuration)
    return try lock.withLock {
      try prepareLocked(
        request, configuration: configuration,
        secretPayload: secretPayload)
    }
  }
  private func prepareLocked(
    _ request: PrepareStartRequest, configuration: Data,
    secretPayload: Data?
  ) throws -> PreparedStart {
    let leaseID = AuthorityIdentifier(UUID())
    let nonce = try randomDigest()
    let issued = clock.nowMilliseconds()
    let expiry = try addLifetime(to: issued)
    var candidate = reducer

    switch request.operation.mode {
    case .tunnel:
      var configurationCopy = configuration
      defer {
        configurationCopy.resetBytes(
          in: configurationCopy.startIndex..<configurationCopy.endIndex)
      }
      let sensitiveConfiguration = try SensitiveBytes(
        copying: configurationCopy,
        maximumCount: AuthorityV1Limits.maximumConfigurationBytes)
      let material: AuthoritySecretMaterial
      do {
        material = try AuthoritySecretPayloadCodec.decode(
          secretPayload, descriptor: request.configuration)
      } catch {
        sensitiveConfiguration.erase()
        throw AuthorityDomainError(code: .secretBoundsExceeded)
      }
      let issuedTicket: AuthorityIssuedTicketTransport
      do {
        issuedTicket = try secrets.prepare(
          request: request, leaseID: leaseID,
          configuration: sensitiveConfiguration, secrets: material)
      } catch {
        throw mapSecretError(error)
      }
      do {
        try candidate.prepare(
          AuthorityPrepareInput(
            request: request, leaseID: leaseID,
            ownerConnectionNonce: nonce, issuedMonotonic: issued,
            expiryMonotonic: issuedTicket.expiresMonotonic,
            retainsSecretBuffer: true))
        try persist(candidate)
        let ticket = try issuedTicket.withTicket { value in
          try value.withUnsafeBytes { try StartTicket(copying: Data($0)) }
        }
        reducer = candidate
        configurationDescriptor = request.configuration
        proxyCapability = nil
        return try PreparedStart(
          operation: request.operation, leaseID: leaseID,
          ticket: ticket, ownerCapability: nil,
          expiresMonotonic: issuedTicket.expiresMonotonic,
          preferenceDescriptorSHA256: request.configuration.identitySHA256)
      } catch {
        issuedTicket.erase()
        secrets.terminate(.error)
        throw error
      }

    case .systemProxy:
      guard secretPayload == nil else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      var rawCapability = try randomness.randomBytes(
        count: AuthorityV1Limits.capabilityBytes)
      defer { rawCapability.resetBytes(in: rawCapability.startIndex..<rawCapability.endIndex) }
      guard rawCapability.count == AuthorityV1Limits.capabilityBytes else {
        throw AuthorityDomainError(code: .secretLifecycleViolation)
      }
      let capability = try OwnerCapability(copying: rawCapability)
      do {
        try candidate.prepare(
          AuthorityPrepareInput(
            request: request, leaseID: leaseID,
            ownerConnectionNonce: nonce, issuedMonotonic: issued,
            expiryMonotonic: expiry, retainsSecretBuffer: false))
        try persist(candidate)
        reducer = candidate
        proxyCapability = PendingProxyCapability(
          operation: request.operation, leaseID: leaseID,
          digest: try digest(rawCapability))
        configurationDescriptor = request.configuration
        return try PreparedStart(
          operation: request.operation, leaseID: leaseID,
          ticket: nil, ownerCapability: capability,
          expiresMonotonic: expiry,
          preferenceDescriptorSHA256: request.configuration.identitySHA256)
      } catch {
        capability.erase()
        throw error
      }
    }
  }
  public func bindProxyOwner(
    _ request: BindProxyOwnerRequest, peer: PeerIdentity, peerID: UUID
  ) throws -> LeaseView {
    guard peer.role == .proxyAgent,
      peer.euid == request.operation.ownerUID
    else { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) }
    defer { request.capability.erase() }
    return try lock.withLock {
      guard let pending = proxyCapability,
        pending.operation == request.operation,
        pending.leaseID == request.leaseID,
        try request.capability.withUnsafeBytes({ try digest(Data($0)) }) == pending.digest,
        let lease = reducer.lease
      else { throw AuthorityDomainError(code: .ticketInvalid) }
      var candidate = reducer
      try candidate.bindOwner(
        AuthorityOwnerBinding(
          operation: request.operation, leaseID: request.leaseID,
          leaseOwnerUID: peer.euid,
          connectionNonce: lease.ownerConnectionNonce,
          role: .proxyAgent, mode: .systemProxy))
      try persist(candidate)
      reducer = candidate
      proxyCapability = nil
      boundPeerID = peerID
      return try leaseView(candidate.lease)
    }
  }

  public struct RedeemResult: @unchecked Sendable {
    public let metadata: RedeemedTunnelMetadata
    public let transport: AuthorityRedeemedTunnelTransport
  }

  public func redeemTunnelTicket(
    _ request: RedeemTunnelTicketRequest,
    peer: PeerIdentity, peerID: UUID
  ) throws -> RedeemResult {
    guard peer.role == .provider else {
      request.ticket.erase()
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard let descriptor = configurationDescriptor,
        let lease = reducer.lease
      else {
        request.ticket.erase()
        throw AuthorityDomainError(code: .ticketInvalid)
      }
      let transport: AuthorityRedeemedTunnelTransport
      do {
        transport = try secrets.redeem(
          ticket: request.ticket, operation: request.operation,
          leaseID: request.leaseID)
      } catch {
        throw mapSecretError(error)
      }
      do {
        var candidate = reducer
        try candidate.bindOwner(
          AuthorityOwnerBinding(
            operation: request.operation, leaseID: request.leaseID,
            leaseOwnerUID: request.operation.ownerUID,
            connectionNonce: lease.ownerConnectionNonce,
            role: .provider, mode: .tunnel))
        try persist(candidate)
        reducer = candidate
        boundPeerID = peerID
        return RedeemResult(
          metadata: try RedeemedTunnelMetadata(
            operation: request.operation, lease: leaseView(candidate.lease),
            configuration: descriptor),
          transport: transport)
      } catch {
        transport.erase()
        throw error
      }
    }
  }
  public func attestReady(
    _ attestation: ReadyAttestation, peer: PeerIdentity, peerID: UUID
  ) throws -> AuthorityAcknowledgement {
    try lock.withLock {
      try requireBoundOwner(peer: peer, peerID: peerID, operation: attestation.operation)
      guard let lease = reducer.lease else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      var candidate = reducer
      let revision = try candidate.attestReady(
        attestation,
        osObservation: readyObservations.observation(for: attestation),
        ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      try persist(candidate)
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }

  public func beginStop(
    _ request: BeginStopRequest, peer: PeerIdentity
  ) throws -> StopDirective {
    guard peer.role == .host, peer.euid == request.operation.ownerUID else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      var candidate = reducer
      let revision = try candidate.beginStop(request)
      try persist(candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      let deadline = try stopDeadline()
      return try StopDirective(
        operation: request.operation, leaseID: request.leaseID,
        deadlineMonotonic: deadline, revision: revision)
    }
  }

  public func attestStopped(
    _ attestation: StoppedAttestation, peer: PeerIdentity, peerID: UUID
  ) throws -> AuthorityAcknowledgement {
    try lock.withLock {
      try requireBoundOwner(peer: peer, peerID: peerID, operation: attestation.operation)
      guard let lease = reducer.lease else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      var candidate = reducer
      let revision = try candidate.attestStopped(
        attestation, ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      try persist(candidate)
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }
  public func cancelPrepared(
    _ request: CancelPreparedRequest, peer: PeerIdentity
  ) throws -> AuthorityAcknowledgement {
    guard peer.role == .host, peer.euid == request.operation.ownerUID else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      var candidate = reducer
      let revision = try candidate.abortPrepared(
        operation: request.operation,
        expectedRevision: request.expectedRevision)
      try persist(candidate)
      reducer = candidate
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try AuthorityAcknowledgement(
        operationID: request.operation.operationID,
        revision: revision)
    }
  }

  public func snapshot(peer: PeerIdentity) throws -> AuthoritySnapshot {
    try lock.withLock {
      guard let cursor = reducer.replayCursor else {
        throw AuthorityDomainError(code: .globalAuthorityRecovering)
      }
      if let lease = reducer.lease {
        switch peer.role {
        case .host:
          guard peer.euid == lease.operation.ownerUID else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        case .proxyAgent:
          guard boundPeerID != nil, peer.euid == lease.operation.ownerUID else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        case .provider:
          guard boundPeerID != nil else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        }
      }
      return try AuthoritySnapshot(
        protocolVersion: AuthorityProtocolVersion(),
        state: reducer.state, revision: reducer.revision,
        replayCursor: cursor,
        leaseView: try reducer.lease.map(leaseView),
        lastFailure: nil, consoleUID: peer.consoleUID)
    }
  }

  public func ownerPeerID() -> UUID? { lock.withLock { boundPeerID } }

  private func requireBoundOwner(
    peer: PeerIdentity, peerID: UUID, operation: OperationContext
  ) throws {
    let expectedRole: AuthorityRole = operation.mode == .tunnel ? .provider : .proxyAgent
    guard peer.role == expectedRole, boundPeerID == peerID else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
  }

  private func leaseView(_ lease: GlobalLease?) throws -> LeaseView {
    guard let lease else { throw AuthorityDomainError(code: .staleOperation) }
    return try LeaseView(
      leaseID: lease.leaseID, operation: lease.operation,
      state: lease.state, expiryMonotonic: lease.expiryMonotonic)
  }
  private func persist(_ value: GlobalAuthorityReducer) throws {
    guard let cursor = value.replayCursor,
      let mutation = value.lastMutation
    else { throw AuthorityDomainError(code: .journalCorrupt) }
    let operation = value.lease?.operation
    do {
      _ = try journal.appendCommitted(
        AuthorityCommittedState(
          installationID: cursor.installationID,
          epoch: cursor.acceptedEpoch,
          generation: cursor.acceptedGeneration,
          revision: value.revision,
          transition: journalTransition(mutation),
          state: value.state,
          operationID: operation?.operationID,
          mode: operation?.mode,
          configSHA256: operation?.configSHA256,
          leaseID: value.lease?.leaseID,
          ownerUID: operation?.ownerUID))
    } catch {
      throw AuthorityDomainError(code: .journalCorrupt)
    }
  }

  private func journalTransition(
    _ mutation: AuthorityDurableMutationKind
  ) -> AuthorityJournalTransition {
    switch mutation {
    case .enrollAndPrepare: .enrollAndPrepare
    case .prepare: .prepare
    case .bindOwner: .bindOwner
    case .ready: .ready
    case .beginStop: .beginStop
    case .ownerStopped: .ownerStopped
    case .abortPrepared: .abortPrepared
    case .revokeForConsoleChange: .revokeForConsoleChange
    case .revokeForTimeout: .revokeForTimeout
    case .globalOff: .globalOff
    case .reconcileOff: .reconcileOff
    }
  }

  private func randomDigest() throws -> SHA256Digest {
    var bytes = try randomness.randomBytes(
      count: AuthorityV1Limits.connectionNonceBytes)
    defer { bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex) }
    guard bytes.count == AuthorityV1Limits.connectionNonceBytes else {
      throw AuthorityDomainError(code: .secretLifecycleViolation)
    }
    return try digest(bytes)
  }

  private func digest(_ data: Data) throws -> SHA256Digest {
    try SHA256Digest(
      hex: SHA256.hash(data: data).map {
        String(format: "%02x", $0)
      }.joined())
  }

  private func addLifetime(to value: UInt64) throws -> UInt64 {
    let (result, overflow) = value.addingReportingOverflow(
      AuthorityV1Limits.preparationLifetimeMilliseconds)
    guard !overflow else { throw AuthorityDomainError(code: .invalidMessage) }
    return result
  }

  private func stopDeadline() throws -> UInt64 {
    let (result, overflow) = clock.nowMilliseconds().addingReportingOverflow(
      AuthorityV1Limits.stopAttestationTimeoutMilliseconds)
    guard !overflow else { throw AuthorityDomainError(code: .invalidMessage) }
    return result
  }

  private func mapSecretError(_ error: Error) -> AuthorityDomainError {
    guard let value = error as? AuthoritySecretLifecycleError else {
      return AuthorityDomainError(code: .secretLifecycleViolation)
    }
    return switch value {
    case .ticketExpired: AuthorityDomainError(code: .ticketExpired)
    case .ticketAlreadyRedeemed: AuthorityDomainError(code: .ticketAlreadyRedeemed)
    case .ticketInvalid: AuthorityDomainError(code: .ticketInvalid)
    case .invalidPreparation: AuthorityDomainError(code: .secretBoundsExceeded)
    default: AuthorityDomainError(code: .secretLifecycleViolation)
    }
  }
}
public final class AuthorityEventHub: @unchecked Sendable {
  private let lock = NSLock()
  private var channels: [UUID: AuthorityPeerEventChannel] = [:]

  public init() {}
  public func register(_ channel: AuthorityPeerEventChannel, peerID: UUID) {
    lock.withLock { channels[peerID] = channel }
  }
  public func remove(peerID: UUID) {
    lock.withLock { _ = channels.removeValue(forKey: peerID) }
  }
  public func send(_ event: AuthorityEvent, to peerID: UUID) {
    lock.withLock { channels[peerID] }?.enqueue(event)
  }
}

public final class AuthorityPeerEventChannel: @unchecked Sendable {
  private let queue = BoundedAuthorityEventQueue()
  private let sink: CFWGlobalAuthorityEventSinkProtocol?
  private let invalidate: @Sendable () -> Void
  private let stateLock = NSLock()
  private var draining = false

  public init(
    sink: CFWGlobalAuthorityEventSinkProtocol?,
    invalidate: @escaping @Sendable () -> Void
  ) {
    self.sink = sink
    self.invalidate = invalidate
  }

  public func enqueue(_ event: AuthorityEvent) {
    guard sink != nil else {
      invalidate()
      return
    }
    guard queue.enqueue(event) == .queued else {
      invalidate()
      return
    }
    let shouldDrain = stateLock.withLock {
      guard !draining else { return false }
      draining = true
      return true
    }
    if shouldDrain { drainNext() }
  }

  private func drainNext() {
    guard let event = queue.dequeue(), let sink else {
      stateLock.withLock { draining = false }
      return
    }
    do {
      let data = try AuthorityV1Codec.encodeEvent(event)
      sink.deliverEvent(data) { [weak self] error in
        guard let self else { return }
        if error != nil {
          self.invalidate()
          self.stateLock.withLock { self.draining = false }
        } else {
          self.drainNext()
        }
      }
    } catch {
      invalidate()
      stateLock.withLock { draining = false }
    }
  }
}
public final class AuthenticatedAuthorityPeerService: NSObject,
  CFWGlobalAuthorityXPCProtocol, @unchecked Sendable
{
  public typealias Reauthorize = @Sendable () throws -> PeerIdentity

  private let peerID: UUID
  private let initialPeer: PeerIdentity
  private let reauthorize: Reauthorize
  private let core: GlobalAuthorityServiceCore
  private let concurrency: AuthorityConcurrencyGate
  private let events: AuthorityEventHub

  public init(
    peerID: UUID, peer: PeerIdentity,
    reauthorize: @escaping Reauthorize,
    core: GlobalAuthorityServiceCore,
    concurrency: AuthorityConcurrencyGate,
    events: AuthorityEventHub
  ) {
    self.peerID = peerID
    initialPeer = peer
    self.reauthorize = reauthorize
    self.core = core
    self.concurrency = concurrency
    self.events = events
  }

  public func handshake(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    read(request, expected: .handshake, reply: reply) { envelope in
      guard case .handshake(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      return try self.response(
        self.core.handshake(value), envelope: envelope, operationID: nil)
    }
  }

  public func prepareStart(
    _ request: Data, configuration: Data, secretPayload: Data?,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .prepareStart, reply: reply) { envelope, peer in
      guard case .prepareStart(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let prepared = try self.core.prepare(
        value, configuration: configuration,
        secretPayload: secretPayload, peer: peer)
      defer {
        prepared.ticket?.erase()
        prepared.ownerCapability?.erase()
      }
      return try AuthorityPreparedStartCodec.encode(
        prepared, requestID: envelope.requestID)
    }
  }
  public func bindProxyOwner(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .bindProxyOwner, reply: reply) { envelope, peer in
      guard case .bindProxyOwner(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let lease = try self.core.bindProxyOwner(
        value, peer: peer, peerID: self.peerID)
      return try self.response(
        lease, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func redeemTunnelTicket(
    _ request: Data,
    reply: @escaping (Data?, Data?, Data?, NSError?) -> Void
  ) {
    do {
      let envelope = try decode(request, expected: .redeemTunnelTicket)
      let peer = try reauthorize()
      let result = try concurrency.withMutation { () -> GlobalAuthorityServiceCore.RedeemResult in
        guard case .redeemTunnelTicket(let value) = envelope.command else {
          throw AuthorityDomainError(code: .invalidMessage)
        }
        return try core.redeemTunnelTicket(
          value, peer: peer, peerID: peerID)
      }
      var configurationData = Data()
      var secretData: Data?
      let response = try result.transport.withMaterial { configuration, secrets in
        configurationData = try configuration.withUnsafeBytes { Data($0) }
        let encodedSecrets = try AuthoritySecretPayloadCodec.encode(secrets)
        defer { encodedSecrets?.erase() }
        secretData = try encodedSecrets?.withUnsafeBytes { Data($0) }
        return try self.response(
          result.metadata, envelope: envelope,
          operationID: result.metadata.operation.operationID)
      }
      defer {
        configurationData.resetBytes(
          in: configurationData.startIndex..<configurationData.endIndex)
        if var secretData {
          secretData.resetBytes(in: secretData.startIndex..<secretData.endIndex)
        }
      }
      reply(response, configurationData, secretData, nil)
    } catch {
      reply(nil, nil, nil, xpcError(error))
    }
  }

  public func attestReady(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .attestReady, reply: reply) { envelope, peer in
      guard case .attestReady(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.attestReady(
        value, peer: peer, peerID: self.peerID)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }
  public func beginStop(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .beginStop, reply: reply) { envelope, peer in
      guard case .beginStop(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let directive = try self.core.beginStop(value, peer: peer)
      if let ownerPeerID = self.core.ownerPeerID() {
        self.events.send(.stop(directive), to: ownerPeerID)
      }
      return try self.response(
        directive, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func attestStopped(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .attestStopped, reply: reply) { envelope, peer in
      guard case .attestStopped(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.attestStopped(
        value, peer: peer, peerID: self.peerID)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func cancelPrepared(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    mutate(request, expected: .cancelPrepared, reply: reply) { envelope, peer in
      guard case .cancelPrepared(let value) = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      let result = try self.core.cancelPrepared(value, peer: peer)
      return try self.response(
        result, envelope: envelope,
        operationID: value.operation.operationID)
    }
  }

  public func snapshot(
    _ request: Data, reply: @escaping (Data?, NSError?) -> Void
  ) {
    read(request, expected: .snapshot, reply: reply) { envelope in
      guard case .snapshot = envelope.command else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      return try self.response(
        self.core.snapshot(peer: self.initialPeer),
        envelope: envelope, operationID: nil)
    }
  }
  private func read(
    _ request: Data, expected: AuthorityXPCMethod,
    reply: @escaping (Data?, NSError?) -> Void,
    body: (AuthorityRequestEnvelope) throws -> Data
  ) {
    do {
      let envelope = try decode(request, expected: expected)
      reply(try concurrency.withRead { try body(envelope) }, nil)
    } catch {
      reply(nil, xpcError(error))
    }
  }

  private func mutate(
    _ request: Data, expected: AuthorityXPCMethod,
    reply: @escaping (Data?, NSError?) -> Void,
    body: (AuthorityRequestEnvelope, PeerIdentity) throws -> Data
  ) {
    do {
      let envelope = try decode(request, expected: expected)
      let peer = try reauthorize()
      reply(try concurrency.withMutation { try body(envelope, peer) }, nil)
    } catch {
      reply(nil, xpcError(error))
    }
  }

  private func decode(
    _ request: Data, expected: AuthorityXPCMethod
  ) throws -> AuthorityRequestEnvelope {
    do {
      let envelope = try AuthorityV1Codec.decodeRequest(request)
      guard method(for: envelope.command) == expected else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      return envelope
    } catch let error as AuthorityV1ValidationError {
      switch error {
      case .unsupportedMajor, .unsupportedMinor, .unsupportedRequiredFeatures:
        throw AuthorityDomainError(code: .globalAuthorityProtocolMismatch)
      default:
        throw AuthorityDomainError(code: .invalidMessage)
      }
    }
  }

  private func response<Payload: AuthorityV1WireModel>(
    _ payload: Payload, envelope: AuthorityRequestEnvelope,
    operationID: AuthorityIdentifier?
  ) throws -> Data {
    try AuthorityV1Codec.encodeResponse(
      AuthorityResponseEnvelope(
        requestID: envelope.requestID,
        operationID: operationID, result: payload))
  }

  private func method(for command: AuthorityCommand) -> AuthorityXPCMethod {
    switch command {
    case .handshake: .handshake
    case .prepareStart: .prepareStart
    case .bindProxyOwner: .bindProxyOwner
    case .redeemTunnelTicket: .redeemTunnelTicket
    case .attestReady: .attestReady
    case .beginStop: .beginStop
    case .attestStopped: .attestStopped
    case .cancelPrepared: .cancelPrepared
    case .snapshot: .snapshot
    }
  }

  private func xpcError(_ error: Error) -> NSError {
    if let domain = error as? AuthorityDomainError {
      return AuthorityXPCErrorContract.error(domain.code)
    }
    if error is GlobalAuthorityAuthorizationError {
      return AuthorityXPCErrorContract.error(.globalAuthorityIdentityRejected)
    }
    return AuthorityXPCErrorContract.error(.invalidMessage)
  }
}
public enum AuthorityConnectionAdmission {
  public static func authorizeBeforeExport(
    authorize: () throws -> PeerIdentity,
    export: (PeerIdentity) -> Void
  ) -> Bool {
    do {
      let peer = try authorize()
      export(peer)
      return true
    } catch {
      return false
    }
  }
}

private final class AuthorityAuditTokenBox: @unchecked Sendable {
  let value: audit_token_t
  init(_ value: audit_token_t) { self.value = value }
}

private final class AuthorityWeakConnectionBox: @unchecked Sendable {
  weak var connection: NSXPCConnection?
  init(_ connection: NSXPCConnection) { self.connection = connection }
}

public final class AuthenticatedGlobalAuthorityListenerDelegate: NSObject,
  NSXPCListenerDelegate, @unchecked Sendable
{
  public typealias Authorize = @Sendable (audit_token_t, uid_t?) throws -> PeerIdentity

  private let core: GlobalAuthorityServiceCore
  private let concurrency = AuthorityConcurrencyGate()
  private let events = AuthorityEventHub()
  private let authorize: Authorize

  public init(core: GlobalAuthorityServiceCore, authorize: @escaping Authorize) {
    self.core = core
    self.authorize = authorize
  }

  public convenience init(core: GlobalAuthorityServiceCore) {
    let authorizer = AuditTokenPeerAuthorizer()
    self.init(core: core) { token, ownerUID in
      try authorizer.authorizeConnection(
        auditToken: token, leaseOwnerUID: ownerUID)
    }
  }

  public static func production() throws -> Self {
    let journal = try DescriptorRelativeAuthorityJournalStore()
    let reducer = try GlobalAuthorityReducer.reconciled(from: journal.recover())
    return Self(
      core: GlobalAuthorityServiceCore(
        reducer: reducer, journal: journal))
  }

  public func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    // Identity is derived only from the kernel-supplied audit token. If the
    // token cannot be read, no interface is exported and the connection is
    // rejected (fail closed).
    guard let auditToken = CFWXPCConnectionAuditToken.read(connection) else {
      connection.invalidate()
      return false
    }
    let token = AuthorityAuditTokenBox(auditToken)
    var admittedPeer: PeerIdentity?
    guard
      AuthorityConnectionAdmission.authorizeBeforeExport(
        authorize: { try authorize(token.value, core.leaseOwnerUID) },
        export: { admittedPeer = $0 }
      ), let peer = admittedPeer
    else {
      connection.invalidate()
      return false
    }

    let peerID = UUID()
    let service = AuthenticatedAuthorityPeerService(
      peerID: peerID, peer: peer,
      reauthorize: { [authorize, core] in
        try authorize(token.value, core.leaseOwnerUID)
      }, core: core, concurrency: concurrency, events: events)
    connection.remoteObjectInterface = NSXPCInterface(
      with: CFWGlobalAuthorityEventSinkProtocol.self)
    let sink = connection.remoteObjectProxy as? CFWGlobalAuthorityEventSinkProtocol
    let connectionBox = AuthorityWeakConnectionBox(connection)
    let channel = AuthorityPeerEventChannel(
      sink: sink, invalidate: { connectionBox.connection?.invalidate() })
    events.register(channel, peerID: peerID)
    connection.exportedInterface = NSXPCInterface(
      with: CFWGlobalAuthorityXPCProtocol.self)
    connection.exportedObject = service
    connection.invalidationHandler = { [events] in events.remove(peerID: peerID) }
    connection.activate()
    return true
  }
}
