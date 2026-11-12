import CFWSharedProtocol
import Darwin
import Foundation
import OSLog
@preconcurrency import SystemConfiguration

import struct CryptoKit.SHA256

public protocol AuthorityJournalCommitting: Sendable {
  @discardableResult
  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead
}

extension DescriptorRelativeAuthorityJournalStore: AuthorityJournalCommitting {}

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
  let expiresMonotonic: UInt64
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
  private static let logger = Logger(
    subsystem: "com.bill.clashformac", category: "global-authority")
  private let lock = NSLock()
  private let journal: any AuthorityJournalCommitting
  private let randomness: any AuthorityTicketRandomness
  private let clock: any AuthorityMonotonicClock
  private let processTable: any AuthorityProcessTable
  private let secrets: TunnelSecretLifecycle
  private var reducer: GlobalAuthorityReducer
  private var proxyCapability: PendingProxyCapability?
  private var configurationDescriptor: AuthorityConfigurationDescriptor?
  private var boundPeerID: UUID?
  private var ownerAuditSessionID: UInt32?
  private var stopDeadlineMonotonic: UInt64?
  private var lastOwnerHeartbeatMonotonic: UInt64?
  private var boundOwnerProcess: AuthorityOwnerProcess?
  private var ownerQuarantine: AuthorityOwnerQuarantine?
  private var recoveredLease: AuthorityRecoveredLease?

  public init(
    reducer: GlobalAuthorityReducer,
    journal: any AuthorityJournalCommitting,
    randomness: any AuthorityTicketRandomness = SystemAuthorityTicketRandomness(),
    clock: any AuthorityMonotonicClock = SystemAuthorityMonotonicClock(),
    processTable: any AuthorityProcessTable = KernelAuthorityProcessTable()
  ) {
    self.reducer = reducer
    self.journal = journal
    self.randomness = randomness
    self.clock = clock
    self.processTable = processTable
    lastOwnerHeartbeatMonotonic = reducer.lease?.issuedMonotonic
    secrets = TunnelSecretLifecycle(randomness: randomness, clock: clock)
  }

  public var leaseOwnerUID: uid_t? {
    lock.withLock { reducer.lease.map { uid_t($0.operation.ownerUID) } }
  }

  /// Current durable machine-wide state. Exposed for the liveness supervisor and
  /// recovery reconciliation; never discloses lease secrets.
  public var authorityState: AuthorityState { lock.withLock { reducer.state } }

  public var currentRevision: UInt64 { lock.withLock { reducer.revision } }

  func releaseObservationState() -> (
    state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?
  ) {
    lock.withLock {
      (
        state: reducer.state,
        revision: reducer.revision,
        leaseOwnerUID: reducer.lease.map { uid_t($0.operation.ownerUID) }
      )
    }
  }

  /// True once the current owner has durably attested a stop. Connection-loss
  /// handling must not revoke an owner whose cleanup has already been attested.
  public var ownerHasAttestedStopped: Bool { lock.withLock { reducer.ownerStopped } }

  /// Expires an owner that never arrived. Preparing has no data-plane or OS
  /// mutation yet, so the Authority can prove and commit Off itself after
  /// erasing the single-use capability/ticket and secret buffers.
  @discardableResult
  public func expireUnboundPreparationIfNeeded() throws -> Bool {
    try lock.withLock {
      guard reducer.state == .preparing,
        let lease = reducer.lease,
        clock.nowMilliseconds() >= lease.expiryMonotonic
      else { return false }
      try abortUnboundPreparationLocked(operation: lease.operation)
      return true
    }
  }

  /// The deadline and the owner it protects belong to the same durable stop.
  /// Check and quarantine under the reducer lock so a delayed notification or
  /// timer observation cannot apply an older stop's deadline to a new lease.
  @discardableResult
  public func quarantineExpiredStopIfNeeded() throws -> Bool {
    try lock.withLock {
      guard reducer.state == .stopping, !reducer.ownerStopped,
        reducer.lease != nil,
        let deadline = stopDeadlineMonotonic,
        clock.nowMilliseconds() >= deadline
      else { return false }
      let owner = boundOwnerProcess
      let (resolution, commit) = try resolveOffLocked(
        GlobalOffProof(
          leaseReleased: false, capabilityOrTicketCleared: false,
          secretBufferCleared: false, ownerEndpointCleared: false,
          cleanup: .unknown, managedTunnel: .unknown))
      if case .quarantined = resolution, let owner {
        ownerQuarantine = AuthorityOwnerQuarantine(owner: owner, commit: commit)
      }
      return true
    }
  }

  /// The owner of a quarantined stop may still run whatever it never attested
  /// stopped, so only a restart, which ends it, used to recover the machine.
  /// Once the owner's process provably ended nothing is left to wait for: the
  /// Authority becomes the Recovering state a restart would rebuild from the
  /// quarantine's own journal record, without writing a record, and the Host
  /// proves both owners and the OS Off before any start. It keeps one
  /// requirement a restart does not: only a Host of the user whose System Proxy
  /// lease it recovered proves Off, since only that user's ProxyAgent can
  /// restore the settings it applied. An unreadable process table proves
  /// nothing and is read again on the next evaluation.
  @discardableResult
  public func recoverFromEndedOwnerIfNeeded() throws -> Bool {
    try lock.withLock {
      // The quarantine's record must still be the Authority's latest, so a
      // record never outlives the quarantine it describes.
      guard reducer.state == .quarantined, var quarantine = ownerQuarantine,
        quarantine.commit.state.revision == reducer.revision
      else {
        return false
      }
      let entry: KernelProcessIdentity?
      do {
        entry = try processTable.lookup(quarantine.owner.processIdentifier)
      } catch {
        if !quarantine.reportedUnreadableProcessTable {
          Self.logger.fault(
            "The process table could not be read for a quarantined owner, so its quarantine lasts until it can: \(String(describing: error), privacy: .public)"
          )
          quarantine.reportedUnreadableProcessTable = true
          ownerQuarantine = quarantine
        }
        return false
      }
      guard quarantine.owner.hasEnded(given: entry) else { return false }
      // A record a restart keeps quarantined stays quarantined here too.
      let posture = AuthorityJournalRecoveryReducer.restartPosture(
        for: quarantine.commit.state)
      guard case .recovering = posture else { return false }
      reducer = try GlobalAuthorityReducer.reconciled(
        from: AuthorityJournalRecovery(
          committedState: quarantine.commit.state, head: quarantine.commit.head,
          posture: posture))
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      stopDeadlineMonotonic = nil
      lastOwnerHeartbeatMonotonic = nil
      boundOwnerProcess = nil
      ownerQuarantine = nil
      recoveredLease = quarantine.lease
      secrets.terminate(.cancellation)
      Self.logger.notice(
        "The owner of a quarantined \(quarantine.lease.mode.rawValue, privacy: .public) lease ended; the Authority released the lease as a restart would"
      )
      return true
    }
  }

  /// Heartbeat age and revocation are checked against the same current owner.
  /// Binding seeds its timestamp before publishing Starting; a previous lease's
  /// contact time must never revoke a newly bound owner.
  public func revokeExpiredHeartbeatIfNeeded(
    timeoutMilliseconds: UInt64
  ) throws -> AuthorityForcedStopOutcome? {
    try lock.withLock {
      guard reducer.state == .starting || reducer.state == .active else { return nil }
      guard let last = lastOwnerHeartbeatMonotonic else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      let now = clock.nowMilliseconds()
      guard now >= last, now - last >= timeoutMilliseconds else { return nil }
      return try forceStopLocked()
    }
  }

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
      guard liveConsoleUID.map({ UInt32($0) }) != lease.operation.ownerUID else {
        return nil
      }
      if reducer.state == .preparing {
        try abortUnboundPreparationLocked(operation: lease.operation)
        return AuthorityForcedStopOutcome(
          directive: nil, ownerPeerID: nil,
          revision: reducer.revision, quarantined: false)
      }
      let before = reducer.revision
      var candidate = reducer
      let revision = try candidate.revokeForConsoleChange(
        liveConsoleUID: liveConsoleUID.map { UInt32($0) },
        ownerConnectionNonce: lease.ownerConnectionNonce)
      guard revision != before else { return nil }
      try persist(&candidate)
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
    try lock.withLock { try forceStopLocked() }
  }

  private func forceStopLocked() throws -> AuthorityForcedStopOutcome? {
    guard let lease = reducer.lease else { return nil }
    if reducer.state == .preparing {
      try abortUnboundPreparationLocked(operation: lease.operation)
      return AuthorityForcedStopOutcome(
        directive: nil, ownerPeerID: nil,
        revision: reducer.revision, quarantined: false)
    }
    let before = reducer.revision
    var candidate = reducer
    let revision = try candidate.revokeForLiveness()
    guard revision != before else { return nil }
    try persist(&candidate)
    reducer = candidate
    proxyCapability = nil
    secrets.terminate(.cancellation)
    return try forcedOutcomeLocked(revision: revision)
  }

  /// Applies an owner/OS Off proof. Off is committed only when every barrier
  /// predicate is proven; any ambiguity retains Quarantined instead of Off.
  @discardableResult
  public func resolveOff(_ proof: GlobalOffProof) throws -> AuthorityOffResolution {
    try lock.withLock { try resolveOffLocked(proof).resolution }
  }

  private func resolveOffLocked(
    _ proof: GlobalOffProof
  ) throws -> (resolution: AuthorityOffResolution, commit: AuthorityJournalCommit) {
    var candidate = reducer
    let resolution = try candidate.applyOffProof(
      proof, expectedRevision: reducer.revision)
    let commit = try persist(&candidate)
    reducer = candidate
    stopDeadlineMonotonic = nil
    lastOwnerHeartbeatMonotonic = nil
    ownerQuarantine = nil
    if case .off = resolution {
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      boundOwnerProcess = nil
      recoveredLease = nil
    }
    secrets.terminate(.cancellation)
    return (resolution, commit)
  }

  /// Commits the post-restart recovery barrier to Off only when the exact
  /// durable journal cursor, the authenticated live Host, both owner cleanup
  /// domains, and the public NetworkExtension state all agree. Transient
  /// capability/ticket/secret evidence is derived exclusively from Authority
  /// process state and is never accepted from request bytes.
  public func reconcileOff(
    _ request: ReconcileOffRequest, peer: PeerIdentity
  ) throws -> ReconcileOffReceipt {
    guard peer.role == .host,
      let consoleUID = peer.consoleUID,
      peer.euid == consoleUID,
      peer.auditSessionID != 0,
      peer.auditSessionID != UInt32.max
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }

    return try lock.withLock {
      switch reducer.state {
      case .recovering:
        break
      case .quarantined:
        throw AuthorityDomainError(code: .quarantined)
      default:
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      guard request.expectedRevision == reducer.revision else {
        throw AuthorityDomainError(code: .staleOperation)
      }
      guard let replayCursor = reducer.replayCursor,
        request.replayCursor == replayCursor
      else {
        throw AuthorityDomainError(code: .replayRejected)
      }
      // Only the ended owner's own ProxyAgent can restore the System Proxy
      // settings it applied, so only that user's Host can prove them restored.
      if let recoveredLease, recoveredLease.mode == .systemProxy,
        peer.euid != recoveredLease.ownerUID
      {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      let managedTunnel: ManagedTunnelObservation
      switch request.managedTunnel {
      case .disconnected:
        managedTunnel = .disconnected
      case .invalid:
        managedTunnel = .invalid
      case .connecting, .connected, .unknown:
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      guard request.proxy.ownershipCleared,
        request.proxy.listenerClosed,
        request.proxy.effectiveSystemConfigurationRestored,
        request.provider.ownershipCleared,
        request.provider.libboxStopped,
        request.provider.packetPumpClosed
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      let leaseReleased = reducer.lease == nil
      let capabilityOrTicketCleared =
        !reducer.retainsCapabilityOrTicket && proxyCapability == nil
      let secretBufferCleared =
        !reducer.retainsSecretBuffer && !secrets.hasPendingMaterial
      let hasNoOwnerBinding = reducer.ownerBinding == nil
      let hasNoBoundPeer = boundPeerID == nil
      let hasNoOwnerAuditSession = ownerAuditSessionID == nil
      let ownerEndpointCleared =
        hasNoOwnerBinding && hasNoBoundPeer && hasNoOwnerAuditSession

      guard leaseReleased,
        capabilityOrTicketCleared,
        secretBufferCleared,
        ownerEndpointCleared,
        configurationDescriptor == nil
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }

      let proof = GlobalOffProof(
        leaseReleased: leaseReleased,
        capabilityOrTicketCleared: capabilityOrTicketCleared,
        secretBufferCleared: secretBufferCleared,
        ownerEndpointCleared: ownerEndpointCleared,
        cleanup: .reconciledBoth(
          proxyListenerClosed: request.proxy.listenerClosed,
          systemConfigurationRestored:
            request.proxy.effectiveSystemConfigurationRestored,
          providerLibboxStopped: request.provider.libboxStopped,
          packetPumpClosed: request.provider.packetPumpClosed),
        managedTunnel: managedTunnel)
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        proof, expectedRevision: request.expectedRevision)
      guard case .off(let revision) = resolution else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      let receipt = try ReconcileOffReceipt(
        revision: revision, replayCursor: replayCursor)
      try persist(&candidate)
      reducer = candidate
      stopDeadlineMonotonic = nil
      lastOwnerHeartbeatMonotonic = nil
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      boundOwnerProcess = nil
      ownerQuarantine = nil
      recoveredLease = nil
      secrets.terminate(.cancellation)
      return receipt
    }
  }

  private func forcedOutcomeLocked(
    revision: UInt64
  ) throws -> AuthorityForcedStopOutcome {
    let directive: StopDirective?
    if let lease = reducer.lease {
      let deadline = try stopDeadlineMonotonic ?? stopDeadline()
      stopDeadlineMonotonic = deadline
      directive = try StopDirective(
        operation: lease.operation, leaseID: lease.leaseID,
        deadlineMonotonic: deadline, revision: revision)
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
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID,
      peer.auditSessionID != 0,
      peer.auditSessionID != UInt32.max
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    try AuthorityV1Codec.validateConfiguration(
      configuration, descriptor: request.configuration)
    return try lock.withLock {
      let prepared = try prepareLocked(
        request, configuration: configuration,
        secretPayload: secretPayload)
      ownerAuditSessionID = peer.auditSessionID
      return prepared
    }
  }
  private func prepareLocked(
    _ request: PrepareStartRequest, configuration: Data,
    secretPayload: Data?
  ) throws -> PreparedStart {
    let leaseID = AuthorityIdentifier(UUID())
    let nonce = try randomDigest()
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
      try ensureEnrollmentLocked(request.operation.root.installationID)
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
            ownerConnectionNonce: nonce, issuedMonotonic: issuedTicket.issuedMonotonic,
            expiryMonotonic: issuedTicket.expiresMonotonic,
            retainsSecretBuffer: true))
        try persist(&candidate)
        let ticket = try issuedTicket.withTicket { value in
          try value.withUnsafeBytes { try StartTicket(copying: Data($0)) }
        }
        reducer = candidate
        stopDeadlineMonotonic = nil
        lastOwnerHeartbeatMonotonic = nil
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

    case .localProxy, .systemProxy:
      let issued = clock.nowMilliseconds()
      let expiry = try addLifetime(to: issued)
      guard secretPayload == nil else {
        throw AuthorityDomainError(code: .invalidMessage)
      }
      try ensureEnrollmentLocked(request.operation.root.installationID)
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
        try persist(&candidate)
        reducer = candidate
        stopDeadlineMonotonic = nil
        lastOwnerHeartbeatMonotonic = nil
        proxyCapability = PendingProxyCapability(
          operation: request.operation, leaseID: leaseID,
          digest: try digest(rawCapability),
          expiresMonotonic: expiry)
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

  private func ensureEnrollmentLocked(
    _ installationID: AuthorityIdentifier
  ) throws {
    guard reducer.installationID == nil else { return }
    switch reducer.state {
    case .recovering: throw AuthorityDomainError(code: .globalAuthorityRecovering)
    case .quarantined: throw AuthorityDomainError(code: .quarantined)
    default: break
    }
    var enrollment = reducer
    try enrollment.enrollOff(installationID)
    try persist(&enrollment)
    reducer = enrollment
  }
  public func bindProxyOwner(
    _ request: BindProxyOwnerRequest, peer: PeerIdentity, peerID: UUID
  ) throws -> LeaseView {
    guard peer.role == .proxyAgent,
      peer.euid == request.operation.ownerUID
    else { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) }
    defer { request.capability.erase() }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      guard let pending = proxyCapability else {
        throw AuthorityDomainError(code: .ticketInvalid)
      }
      guard clock.nowMilliseconds() < pending.expiresMonotonic else {
        try abortUnboundPreparationLocked(operation: pending.operation)
        throw AuthorityDomainError(code: .ticketExpired)
      }
      guard
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
          role: .proxyAgent, mode: request.operation.mode))
      try persist(&candidate)
      reducer = candidate
      proxyCapability = nil
      boundPeerID = peerID
      boundOwnerProcess = ownerProcessLocked(peer, leaseID: request.leaseID)
      lastOwnerHeartbeatMonotonic = clock.nowMilliseconds()
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
      let redemption: AuthorityTicketRedemption
      do {
        redemption = try secrets.redeem(ticket: request.ticket)
      } catch {
        throw mapSecretError(error)
      }
      do {
        guard redemption.operation == lease.operation,
          redemption.leaseID == lease.leaseID
        else {
          redemption.transport.erase()
          throw AuthorityDomainError(code: .ticketInvalid)
        }
        var candidate = reducer
        try candidate.bindOwner(
          AuthorityOwnerBinding(
            operation: redemption.operation, leaseID: redemption.leaseID,
            leaseOwnerUID: redemption.operation.ownerUID,
            connectionNonce: lease.ownerConnectionNonce,
            role: .provider, mode: .tunnel))
        try persist(&candidate)
        reducer = candidate
        boundPeerID = peerID
        boundOwnerProcess = ownerProcessLocked(peer, leaseID: redemption.leaseID)
        lastOwnerHeartbeatMonotonic = clock.nowMilliseconds()
        return RedeemResult(
          metadata: try RedeemedTunnelMetadata(
            operation: redemption.operation, lease: leaseView(candidate.lease),
            configuration: descriptor),
          transport: redemption.transport)
      } catch {
        redemption.transport.erase()
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
      let previousRevision = candidate.revision
      let revision = try candidate.attestReady(
        attestation,
        ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }

  public func beginStop(
    _ request: BeginStopRequest, peer: PeerIdentity
  ) throws -> StopDirective {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      var candidate = reducer
      let previousRevision = candidate.revision
      let revision = try candidate.beginStop(request)
      let deadline = try stopDeadlineMonotonic ?? stopDeadline()
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      stopDeadlineMonotonic = deadline
      proxyCapability = nil
      secrets.terminate(.cancellation)
      return try StopDirective(
        operation: request.operation, leaseID: request.leaseID,
        deadlineMonotonic: deadline, revision: revision)
    }
  }

  public func completeStop(
    _ request: CompleteStopRequest, peer: PeerIdentity
  ) throws -> AuthorityAcknowledgement {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      guard reducer.state == .stopping,
        let lease = reducer.lease,
        lease.operation == request.operation,
        lease.leaseID == request.leaseID,
        reducer.ownerStopped
      else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      var candidate = reducer
      let resolution = try candidate.applyOffProof(
        Self.stoppedOwnerOffProof(for: request.operation.mode),
        expectedRevision: request.expectedRevision)
      guard case .off(let revision) = resolution else {
        throw AuthorityDomainError(code: .cleanupUnproven)
      }
      try persist(&candidate)
      reducer = candidate
      stopDeadlineMonotonic = nil
      lastOwnerHeartbeatMonotonic = nil
      proxyCapability = nil
      configurationDescriptor = nil
      boundPeerID = nil
      ownerAuditSessionID = nil
      boundOwnerProcess = nil
      secrets.terminate(.cancellation)
      return try AuthorityAcknowledgement(
        operationID: request.operation.operationID,
        revision: revision)
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
      let previousRevision = candidate.revision
      let revision = try candidate.attestStopped(
        attestation, ownerUID: attestation.operation.ownerUID,
        connectionNonce: lease.ownerConnectionNonce)
      if revision != previousRevision {
        try persist(&candidate)
      }
      reducer = candidate
      return try AuthorityAcknowledgement(
        operationID: attestation.operation.operationID,
        revision: revision)
    }
  }
  public func cancelPrepared(
    _ request: CancelPreparedRequest, peer: PeerIdentity
  ) throws -> AuthorityAcknowledgement {
    guard peer.role == .host,
      peer.euid == request.operation.ownerUID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      guard peer.auditSessionID == ownerAuditSessionID else {
        throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
      }
      let revision = try abortUnboundPreparationLocked(
        operation: request.operation,
        expectedRevision: request.expectedRevision)
      return try AuthorityAcknowledgement(
        operationID: request.operation.operationID,
        revision: revision)
    }
  }

  private func abortUnboundPreparationLocked(
    operation: OperationContext
  ) throws {
    _ = try abortUnboundPreparationLocked(
      operation: operation,
      expectedRevision: reducer.revision)
  }

  private func abortUnboundPreparationLocked(
    operation: OperationContext,
    expectedRevision: UInt64
  ) throws -> UInt64 {
    var candidate = reducer
    let deadline = try stopDeadline()
    _ = try candidate.abortPrepared(
      operation: operation,
      expectedRevision: expectedRevision)
    try persist(&candidate)
    // The abort record is already durable. Advance the in-memory high-water and
    // erase the one-use authorization before attempting the separate Off record,
    // so an Off-persist failure cannot leave memory projecting Preparing behind
    // the journal's committed Stopping state.
    reducer = candidate
    stopDeadlineMonotonic = deadline
    proxyCapability = nil
    boundPeerID = nil
    secrets.terminate(.cancellation)

    let resolution = try candidate.applyOffProof(
      Self.unboundPreparationOffProof(for: operation.mode),
      expectedRevision: candidate.revision)
    guard case .off(let revision) = resolution else {
      throw AuthorityDomainError(code: .cleanupUnproven)
    }
    try persist(&candidate)
    reducer = candidate
    stopDeadlineMonotonic = nil
    lastOwnerHeartbeatMonotonic = nil
    proxyCapability = nil
    configurationDescriptor = nil
    boundPeerID = nil
    ownerAuditSessionID = nil
    boundOwnerProcess = nil
    secrets.terminate(.cancellation)
    return revision
  }

  private static func unboundPreparationOffProof(
    for mode: AuthorityMode
  ) -> GlobalOffProof {
    let cleanup: AuthorityCleanupObservation =
      switch mode {
      case .localProxy, .systemProxy:
        .systemProxy(listenerClosed: true, systemConfigurationRestored: true)
      case .tunnel:
        .tunnel(libboxStopped: true, packetPumpClosed: true)
      }
    return GlobalOffProof(
      leaseReleased: true,
      capabilityOrTicketCleared: true,
      secretBufferCleared: true,
      ownerEndpointCleared: true,
      cleanup: cleanup,
      managedTunnel: .disconnected)
  }

  /// A cooperative stop is completed only after the authenticated owner has
  /// durably attested its local teardown and the authenticated Host has observed
  /// the matching OS-facing endpoint at its Off barrier. The Host's
  /// `completeStop` request is that second proof boundary.
  private static func stoppedOwnerOffProof(
    for mode: AuthorityMode
  ) -> GlobalOffProof {
    unboundPreparationOffProof(for: mode)
  }

  public func installationRecoveryIdentity(peer: PeerIdentity) throws -> InstallationRecoveryState {
    guard peer.role == .host, let consoleUID = peer.consoleUID,
      peer.euid == consoleUID, consoleUID > 0, consoleUID != UInt32.max,
      peer.auditSessionID != 0, peer.auditSessionID != UInt32.max
    else { throw AuthorityDomainError(code: .globalAuthorityIdentityRejected) }
    return try lock.withLock {
      guard reducer.state != .quarantined else {
        throw AuthorityDomainError(code: .quarantined)
      }
      guard reducer.state != .recovering else {
        throw AuthorityDomainError(code: .globalAuthorityRecovering)
      }
      guard reducer.state == .off, reducer.lease == nil,
        !reducer.retainsCapabilityOrTicket, proxyCapability == nil,
        !reducer.retainsSecretBuffer, !secrets.hasPendingMaterial,
        reducer.ownerBinding == nil, boundPeerID == nil, ownerAuditSessionID == nil,
        configurationDescriptor == nil
      else { throw AuthorityDomainError(code: .cleanupUnproven) }
      return try InstallationRecoveryState(
        identity: reducer.installationID.map {
          try InstallationRecoveryIdentity(
            installationID: $0, acceptedEpoch: reducer.replayCursor?.acceptedEpoch ?? 0,
            revision: reducer.revision, consoleUID: consoleUID)
        })
    }
  }

  public func snapshot(peer: PeerIdentity) throws -> AuthoritySnapshot {
    try lock.withLock {
      if let lease = reducer.lease {
        switch peer.role {
        case .host:
          // Another user's Host learns only that a lease it does not hold
          // exists, and waits for it to end.
          guard peer.euid == lease.operation.ownerUID else {
            throw AuthorityDomainError(code: .globalLeaseConflict)
          }
          guard peer.auditSessionID == ownerAuditSessionID else {
            throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
          }
        case .proxyAgent:
          guard boundPeerID != nil,
            peer.euid == lease.operation.ownerUID,
            peer.auditSessionID == ownerAuditSessionID
          else {
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
        replayCursor: reducer.replayCursor,
        leaseView: try reducer.lease.map(leaseView),
        lastFailure: nil, consoleUID: peer.consoleUID)
    }
  }

  public func ownerPeerID() -> UUID? { lock.withLock { boundPeerID } }

  /// Tells a ProxyAgent what the Authority knows of the lease it bound, so an
  /// owner whose stopped attestation failed learns whether that lease still
  /// exists. It answers only for the caller's own lease, one the authenticated
  /// connection's user owns, and only to a ProxyAgent. An Authority that has
  /// not read its journal yet, or quarantined the journal it read, cannot tell
  /// and says so instead of claiming the lease absent.
  public func ownerLeaseStatus(
    _ request: OwnerLeaseStatusRequest, peer: PeerIdentity
  ) throws -> OwnerLeaseStatus {
    guard peer.role == .proxyAgent else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
    return try lock.withLock {
      if let lease = reducer.lease, lease.leaseID == request.leaseID {
        guard lease.operation.mode.isProxyAgent, lease.operation.ownerUID == peer.euid else {
          throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
        }
        return reducer.state == .quarantined ? .quarantined : .held
      }
      switch reducer.state {
      case .recovering where reducer.replayCursor == nil:
        // Recovering without a cursor still waits to read its journal.
        return .notReady
      case .quarantined where reducer.lease == nil:
        // A quarantine without a lease came from a journal it cannot trust.
        return .notReady
      default:
        return .absent
      }
    }
  }

  public func recordOwnerHeartbeat(
    peer: PeerIdentity,
    peerID: UUID
  ) throws {
    try lock.withLock {
      guard let lease = reducer.lease,
        [.starting, .active, .stopping].contains(reducer.state)
      else { throw AuthorityDomainError(code: .staleOperation) }
      try requireBoundOwner(
        peer: peer, peerID: peerID, operation: lease.operation)
      lastOwnerHeartbeatMonotonic = clock.nowMilliseconds()
    }
  }

  private func requireBoundOwner(
    peer: PeerIdentity, peerID: UUID, operation: OperationContext
  ) throws {
    let expectedRole: AuthorityRole = operation.mode == .tunnel ? .provider : .proxyAgent
    guard peer.role == expectedRole, boundPeerID == peerID,
      expectedRole == .provider || peer.auditSessionID == ownerAuditSessionID
    else {
      throw AuthorityDomainError(code: .globalAuthorityIdentityRejected)
    }
  }

  /// The binding owner's process as the kernel holds it now, while the owner
  /// waits for the bind reply. Without it the Authority cannot later prove that
  /// the owner ended, so a quarantine of this lease lasts until restart.
  private func ownerProcessLocked(
    _ peer: PeerIdentity, leaseID: AuthorityIdentifier
  ) -> AuthorityOwnerProcess? {
    let entry: KernelProcessIdentity?
    do {
      entry = try processTable.lookup(peer.pid)
    } catch {
      Self.logger.fault(
        "The binding owner's process could not be read, so a quarantine of its lease lasts until restart: \(String(describing: error), privacy: .public)"
      )
      return nil
    }
    // A process that ended before the bind was recorded, or a later one of
    // another user at its pid, is not the owner.
    guard let entry, entry.effectiveUserIdentifier == peer.euid else {
      Self.logger.notice(
        "The binding owner no longer runs at its pid, so a quarantine of its lease lasts until restart"
      )
      return nil
    }
    return AuthorityOwnerProcess(entry, leaseID: leaseID)
  }

  private func leaseView(_ lease: GlobalLease?) throws -> LeaseView {
    guard let lease else { throw AuthorityDomainError(code: .staleOperation) }
    return try LeaseView(
      leaseID: lease.leaseID, operation: lease.operation,
      state: lease.state, expiryMonotonic: lease.expiryMonotonic)
  }
  @discardableResult
  private func persist(_ value: inout GlobalAuthorityReducer) throws -> AuthorityJournalCommit {
    guard let installationID = value.installationID,
      let mutation = value.lastMutation
    else { throw AuthorityDomainError(code: .journalCorrupt) }
    let operation = value.lease?.operation
    let cursor = value.replayCursor
    do {
      let state = try AuthorityCommittedState(
        installationID: installationID,
        epoch: cursor?.acceptedEpoch ?? 0,
        generation: cursor?.acceptedGeneration ?? 0,
        revision: value.revision,
        transition: journalTransition(mutation),
        state: value.state,
        operationID: operation?.operationID,
        mode: operation?.mode,
        configSHA256: operation?.configSHA256,
        leaseID: value.lease?.leaseID,
        ownerUID: operation?.ownerUID)
      let head = try journal.appendCommitted(state)
      try value.recordPersistedHead(head)
      return AuthorityJournalCommit(state: state, head: head)
    } catch AuthorityJournalStorageError.capacityExhausted {
      throw AuthorityDomainError(code: .journalCapacityExhausted)
    } catch {
      throw AuthorityDomainError(code: .journalCorrupt)
    }
  }

  private func journalTransition(
    _ mutation: AuthorityDurableMutationKind
  ) -> AuthorityJournalTransition {
    switch mutation {
    case .enrollOff: .enrollOff
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
