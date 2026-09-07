import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

/// Monotonic time source for provider attestations. Injected so tests can
/// assert exact readiness/stopped timestamps without a real clock.
protocol ProviderMonotonicClock: Sendable {
  func nowMilliseconds() -> UInt64
}

struct SystemProviderMonotonicClock: ProviderMonotonicClock {
  func nowMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
  }
}

/// Local engine lease that grants no machine-wide authority. The Global Authority
/// owns the single machine lease under the ticket-only model, so the Provider must
/// never construct `CrossProcessEngineLeaseStore` in its Release start path.
final class UnleasedEngineOwnership: EngineLeaseHolding, @unchecked Sendable {
  func release() throws {}
  func markStopFailed() throws {}
}

final class TunnelRevocationChannel: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  func onRevoke(_ handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }

  func revoke() {
    let handler = lock.withLock { self.handler }
    handler?()
  }
}

/// Bounds reported in the ready attestation. They mirror the production packet pump
/// so the Authority's readiness proof matches the transport that is actually running.
enum ProviderPacketPumpLimits {
  static let maximumQueuedPackets: UInt16 = 1_024
  static let maximumQueuedBytes: UInt32 = 4 * 1_048_576
  static let maximumReadBatch: UInt8 = 64

  static func attestation(mtu: UInt16) throws -> PacketPumpLimits {
    try PacketPumpLimits(
      maximumQueuedPackets: maximumQueuedPackets,
      maximumQueuedBytes: maximumQueuedBytes,
      maximumPacketBytes: mtu,
      maximumReadBatch: maximumReadBatch
    )
  }
}

/// Orchestrates the ticket-only Tunnel bootstrap: redeem the opaque Authority ticket
/// exactly once, inject the returned configuration and secrets into libbox, wipe every
/// transport buffer, and attest exact readiness/stopped state to the Authority.
///
/// All Authority (XPC), libbox, and OS side effects live behind injected seams so the
/// coordinator can be driven deterministically with fakes.
final class TunnelTicketStartCoordinator: @unchecked Sendable {
  private typealias StopCompletion =
    @Sendable (
      Result<Void, PacketTunnelStopError>
    ) -> Void

  private enum Phase {
    case idle
    case busy
  }

  private struct ActiveContext {
    let operation: OperationContext
    let leaseID: AuthorityIdentifier
    let descriptor: ConfigurationDescriptor
  }

  private struct StopFlight {
    let id: UUID
    let context: ActiveContext?
    var completions: [StopCompletion]
    var revocationRequested: Bool
  }

  private enum PendingCancellation: Equatable {
    case explicitStop
    case authorityRevocation
  }

  private struct PendingStart {
    let id: UUID
    var cancellation: PendingCancellation?
    var stopCompletions: [StopCompletion] = []
  }

  private struct PendingStartResolution {
    let cancellation: PendingCancellation?
    let stopCompletions: [StopCompletion]
  }

  private let authority: any EngineOwnerAuthorityClient
  private let sessionLifecycle: PacketTunnelSessionLifecycle
  private let clock: any ProviderMonotonicClock
  private let reportRevocationFailure: @Sendable (PacketTunnelStopError) -> Void
  private let completeRevocation: @Sendable () -> Void
  private let revocation: TunnelRevocationChannel
  private let stateLock = NSLock()
  private var phase = Phase.idle
  private var pendingStart: PendingStart?
  private var activeContext: ActiveContext?
  private var pendingReadyLeaseID: AuthorityIdentifier?
  private var pendingReadyCancellation: PendingCancellation?
  private var locallyStoppedLeaseID: AuthorityIdentifier?
  private var locallyStoppedProof: PacketTunnelStopProof?
  private var stopFlight: StopFlight?

  init(
    authority: any EngineOwnerAuthorityClient,
    sessionLifecycle: PacketTunnelSessionLifecycle,
    revocation: TunnelRevocationChannel = TunnelRevocationChannel(),
    clock: any ProviderMonotonicClock = SystemProviderMonotonicClock(),
    reportRevocationFailure: @escaping @Sendable (PacketTunnelStopError) -> Void = { _ in },
    completeRevocation: @escaping @Sendable () -> Void = {}
  ) {
    self.authority = authority
    self.sessionLifecycle = sessionLifecycle
    self.clock = clock
    self.reportRevocationFailure = reportRevocationFailure
    self.completeRevocation = completeRevocation
    self.revocation = revocation
    revocation.onRevoke { [weak self] in self?.handleRevocation() }
  }

  /// Redeems `ticket` and starts the tunnel. `ticket` is consumed (erased) on every
  /// path. The completion fires with `nil` only after libbox is injected and running
  /// and the Authority has accepted the exact ready attestation.
  func start(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Error?) -> Void
  ) {
    let startID = UUID()
    let admitted = stateLock.withLock { () -> Bool in
      guard case .idle = phase else { return false }
      phase = .busy
      pendingStart = PendingStart(
        id: startID, cancellation: nil)
      return true
    }
    guard admitted else {
      ticket.erase()
      completion(PacketTunnelProviderError.lifecycleConflict)
      return
    }
    Task { [self] in
      await performStart(
        ticket: ticket, descriptor: descriptor,
        startID: startID, completion: completion)
    }
  }

  func stop(
    completion: @escaping @Sendable (Result<Void, PacketTunnelStopError>) -> Void
  ) {
    let deferred = stateLock.withLock { () -> Bool in
      guard activeContext == nil, var pending = pendingStart else { return false }
      if pending.cancellation == nil {
        pending.cancellation = .explicitStop
      }
      pending.stopCompletions.append(completion)
      pendingStart = pending
      return true
    }
    guard !deferred else { return }
    requestStop(completion: completion, revocationRequested: false)
  }

  private func handleRevocation() {
    let hasActiveContext = stateLock.withLock { () -> Bool in
      if var pending = pendingStart {
        pending.cancellation = .authorityRevocation
        pendingStart = pending
        return false
      }
      return activeContext != nil
    }
    guard hasActiveContext else { return }
    requestStop(completion: nil, revocationRequested: true)
  }

  private func performStart(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    startID: UUID,
    completion: @escaping @Sendable (Error?) -> Void
  ) async {
    let redeemed: RedeemedTunnelStart
    do {
      redeemed = try await authority.redeem(ticket)
    } catch {
      finishUnboundFailure(
        Self.mapRedeemError(error), startID: startID, completion: completion)
      return
    }
    // The redeemed configuration and secrets are the Authority transport buffers.
    // They are erased on every path once copied into the libbox injection inputs.
    // `eraseRedeemedTransport` is idempotent, so it runs before every completion
    // (making the wipe observable to the caller as a barrier) and the `defer`
    // remains the unconditional backstop for any path that returns early.
    func eraseRedeemedTransport() {
      redeemed.configuration.erase()
      redeemed.secrets.erase()
    }
    defer { eraseRedeemedTransport() }

    let operation = redeemed.operation
    let leaseID = redeemed.lease.leaseID
    let context = ActiveContext(
      operation: operation, leaseID: leaseID, descriptor: descriptor)
    guard redeemed.lease.state == .starting,
      operation.mode == .tunnel,
      operation.root.installationID.rawValue == descriptor.installationID,
      operation.root.epoch == descriptor.epoch,
      operation.root.generation == descriptor.generation,
      operation.configSHA256 == descriptor.sha256,
      operation.identitySHA256 == descriptor.identitySHA256,
      descriptor.slot == .tunnel
    else {
      eraseRedeemedTransport()
      let pending = installBoundContext(context, startID: startID)
      finishBoundFailure(
        .invalidConfigurationSlot,
        completion: completion,
        revocationRequested: pending.cancellation == .authorityRevocation,
        additionalStopCompletions: pending.stopCompletions)
      return
    }

    var configurationTemplate: Data
    var credentialMaterial: CredentialMaterial
    do {
      configurationTemplate = try redeemed.configuration.withUnsafeBytes { Data($0) }
      credentialMaterial = try Self.makeCredentialMaterial(from: redeemed.secrets)
    } catch {
      configurationTemplate = Data()
      eraseRedeemedTransport()
      let pending = installBoundContext(context, startID: startID)
      finishBoundFailure(
        .configuration(String(describing: error)),
        completion: completion,
        revocationRequested: pending.cancellation == .authorityRevocation,
        additionalStopCompletions: pending.stopCompletions)
      return
    }
    // Nothing below reads the Authority transport buffers again, so wipe them before
    // the session lifecycle can call back and complete the start.
    eraseRedeemedTransport()
    let injectedConfiguration = configurationTemplate
    let injectedCredentials = credentialMaterial

    var pendingResolution = PendingStartResolution(
      cancellation: nil, stopCompletions: [])
    let mayStart = stateLock.withLock { () -> Bool in
      guard let pending = pendingStart, pending.id == startID else { return false }
      pendingResolution = PendingStartResolution(
        cancellation: pending.cancellation,
        stopCompletions: pending.stopCompletions)
      pendingStart = nil
      activeContext = context
      locallyStoppedLeaseID = nil
      locallyStoppedProof = nil
      guard pending.cancellation == nil else { return false }
      pendingReadyLeaseID = context.leaseID
      pendingReadyCancellation = nil
      // This enqueue is the claim→start barrier. Stop/revoke use the same lock,
      // so either cancellation is recorded first or teardown observes the newly
      // installed exact context after the enqueue.
      sessionLifecycle.start(
        descriptor: descriptor,
        configuration: injectedConfiguration,
        credentialMaterial: injectedCredentials
      ) { [self] error in
        if let error {
          finishBoundFailure(mappedStartError(error), completion: completion)
          return
        }
        Task { [self] in
          await completeReadyAttestation(
            operation: operation, leaseID: leaseID,
            descriptor: descriptor, completion: completion)
        }
      }
      return true
    }
    guard mayStart else {
      configurationTemplate.resetBytes(
        in: configurationTemplate.startIndex..<configurationTemplate.endIndex)
      credentialMaterial.erase()
      let failure: PacketTunnelProviderError =
        pendingResolution.cancellation == .explicitStop
        ? .startupCancelled : .globalAuthorityUnavailable
      finishBoundFailure(
        failure,
        completion: completion,
        revocationRequested: pendingResolution.cancellation == .authorityRevocation,
        additionalStopCompletions: pendingResolution.stopCompletions)
      return
    }
    // The session lifecycle captured value copies of the injection inputs above,
    // so erasing these working copies here (copy-on-write) cannot corrupt libbox
    // injection while still wiping the last provider-held plaintext buffers.
    configurationTemplate.resetBytes(
      in: configurationTemplate.startIndex..<configurationTemplate.endIndex)
    credentialMaterial.erase()
  }

  private func completeReadyAttestation(
    operation: OperationContext,
    leaseID: AuthorityIdentifier,
    descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Error?) -> Void
  ) async {
    do {
      guard let tunnelOptions = descriptor.tunnelOptions else {
        throw PacketTunnelProviderError.malformedProviderConfiguration
      }
      let attestation = try ReadyAttestation(
        operation: operation,
        leaseID: leaseID,
        runtimeDigest: operation.identitySHA256,
        ownerRole: .provider,
        readyFlags: .all,
        packetPumpLimits: try ProviderPacketPumpLimits.attestation(mtu: tunnelOptions.mtu),
        monotonicTimestamp: monotonicTimestamp()
      )
      try await authority.attestReady(attestation)
      let cancellation = stateLock.withLock { () -> PendingCancellation? in
        guard pendingReadyLeaseID == leaseID else { return .authorityRevocation }
        pendingReadyLeaseID = nil
        let cancellation = pendingReadyCancellation
        pendingReadyCancellation = nil
        return cancellation
      }
      guard let cancellation else {
        completion(nil)
        return
      }
      let failure: PacketTunnelProviderError =
        cancellation == .explicitStop ? .startupCancelled : .globalAuthorityUnavailable
      finishBoundFailure(failure, completion: completion)
    } catch {
      stateLock.withLock {
        guard pendingReadyLeaseID == leaseID else { return }
        pendingReadyLeaseID = nil
        pendingReadyCancellation = nil
      }
      // Exact readiness could not be attested; tear the runtime down and fail closed.
      // The failure is reported only after the teardown barrier completes, so no
      // caller can observe a failed start while libbox and the transport are still
      // owned, and no retry can be admitted before the coordinator is idle again.
      let failure = Self.mapAttestationError(error)
      finishBoundFailure(failure, completion: completion)
    }
  }

  private func attestStopped(
    proof: PacketTunnelStopProof,
    context: ActiveContext
  ) async -> Result<Void, PacketTunnelStopError> {
    do {
      let attestation = try StoppedAttestation(
        operation: context.operation,
        leaseID: context.leaseID,
        libboxStopped: proof.libboxStopped,
        transportClosed: proof.transportClosed,
        osRestored: proof.osRestored,
        monotonicTimestamp: monotonicTimestamp())
      try await authority.attestStopped(attestation)
      return .success(())
    } catch {
      // Local resources remain stopped, but the Authority still owns the exact
      // operation until it accepts this proof. Preserve activeContext/phase so
      // another stop retries only the missing attestation barrier.
      return .failure(.authorityAttestation(Self.mapAttestationError(error)))
    }
  }

  private func finishUnboundFailure(
    _ error: PacketTunnelProviderError,
    startID: UUID,
    completion: @escaping @Sendable (Error?) -> Void
  ) {
    let pending = stateLock.withLock { () -> PendingStartResolution in
      guard let pending = pendingStart, pending.id == startID else {
        return PendingStartResolution(cancellation: nil, stopCompletions: [])
      }
      pendingStart = nil
      activeContext = nil
      pendingReadyLeaseID = nil
      pendingReadyCancellation = nil
      phase = .idle
      return PendingStartResolution(
        cancellation: pending.cancellation,
        stopCompletions: pending.stopCompletions)
    }
    completion(error)
    for stopCompletion in pending.stopCompletions {
      stopCompletion(.success(()))
    }
    if pending.cancellation == .authorityRevocation {
      completeRevocation()
    }
  }

  private func finishBoundFailure(
    _ error: PacketTunnelProviderError,
    completion: @escaping @Sendable (Error?) -> Void,
    revocationRequested: Bool = false,
    additionalStopCompletions: [StopCompletion] = []
  ) {
    var completions = additionalStopCompletions
    completions.append { result in
      switch result {
      case .success:
        completion(error)
      case .failure(let stopError):
        completion(stopError.providerError)
      }
    }
    requestStop(
      completions: completions,
      revocationRequested: revocationRequested)
  }

  private func requestStop(
    completion: StopCompletion?,
    revocationRequested: Bool
  ) {
    requestStop(
      completions: completion.map { [$0] } ?? [],
      revocationRequested: revocationRequested)
  }

  private func requestStop(
    completions incomingCompletions: [StopCompletion],
    revocationRequested: Bool
  ) {
    var flightToStart: StopFlight?
    var existingProof: PacketTunnelStopProof?
    stateLock.withLock {
      if var current = stopFlight {
        current.completions.append(contentsOf: incomingCompletions)
        current.revocationRequested = current.revocationRequested || revocationRequested
        stopFlight = current
        return
      }
      let context = activeContext
      if let context, pendingReadyLeaseID == context.leaseID {
        if pendingReadyCancellation == nil || revocationRequested {
          pendingReadyCancellation = revocationRequested ? .authorityRevocation : .explicitStop
        }
      }
      let flight = StopFlight(
        id: UUID(), context: context,
        completions: incomingCompletions,
        revocationRequested: revocationRequested)
      stopFlight = flight
      if let context, locallyStoppedLeaseID == context.leaseID {
        existingProof = locallyStoppedProof
      }
      flightToStart = flight
    }
    guard let flight = flightToStart else { return }
    if let proof = existingProof, let context = flight.context {
      attestStopFlight(flight, proof: proof, context: context)
      return
    }
    sessionLifecycle.stop { [self] result in
      switch result {
      case .failure(let error):
        finishStopFlight(flight.id, result: .failure(error))
      case .success(let proof):
        guard let context = flight.context else {
          finishStopFlight(flight.id, result: .success(()))
          return
        }
        stateLock.withLock {
          guard activeContext?.leaseID == context.leaseID else { return }
          locallyStoppedLeaseID = context.leaseID
          locallyStoppedProof = proof
        }
        attestStopFlight(flight, proof: proof, context: context)
      }
    }
  }

  private func attestStopFlight(
    _ flight: StopFlight,
    proof: PacketTunnelStopProof,
    context: ActiveContext
  ) {
    Task { [self] in
      let result = await attestStopped(proof: proof, context: context)
      finishStopFlight(flight.id, result: result)
    }
  }

  private func finishStopFlight(
    _ id: UUID,
    result: Result<Void, PacketTunnelStopError>
  ) {
    let outcome = stateLock.withLock {
      () -> (completions: [StopCompletion], revocation: Bool)? in
      guard let current = stopFlight, current.id == id else { return nil }
      stopFlight = nil
      if let context = current.context,
        activeContext?.leaseID == context.leaseID,
        case .success = result
      {
        activeContext = nil
        locallyStoppedLeaseID = nil
        locallyStoppedProof = nil
        if pendingReadyLeaseID != context.leaseID {
          phase = .idle
        }
      } else if current.context == nil,
        pendingReadyLeaseID == nil,
        case .success = result
      {
        phase = .idle
      }
      return (current.completions, current.revocationRequested)
    }
    guard let outcome else { return }
    if outcome.revocation {
      switch result {
      case .success:
        completeRevocation()
      case .failure(let error):
        reportRevocationFailure(error)
      }
    }
    for completion in outcome.completions {
      completion(result)
    }
  }

  private func installBoundContext(
    _ context: ActiveContext,
    startID: UUID
  ) -> PendingStartResolution {
    stateLock.withLock {
      guard let pending = pendingStart, pending.id == startID else {
        return PendingStartResolution(cancellation: nil, stopCompletions: [])
      }
      pendingStart = nil
      activeContext = context
      locallyStoppedLeaseID = nil
      locallyStoppedProof = nil
      return PendingStartResolution(
        cancellation: pending.cancellation,
        stopCompletions: pending.stopCompletions)
    }
  }

  private func monotonicTimestamp() -> UInt64 {
    max(1, clock.nowMilliseconds())
  }

  private func mappedStartError(_ error: Error) -> PacketTunnelProviderError {
    (error as? PacketTunnelProviderError) ?? .engineStart(String(describing: error))
  }

  static func makeCredentialMaterial(
    from secrets: AuthoritySecretMaterial
  ) throws -> CredentialMaterial {
    var entries: [CredentialMaterialEntry] = []
    entries.reserveCapacity(secrets.slots.count)
    for slot in secrets.slots {
      var secret = try slot.withUnsafeBytes { Data($0) }
      defer { secret.resetBytes(in: secret.startIndex..<secret.endIndex) }
      entries.append(try CredentialMaterialEntry(reference: slot.reference, secret: secret))
    }
    return try CredentialMaterial(entries: entries)
  }

  static func mapRedeemError(_ error: Error) -> PacketTunnelProviderError {
    guard let domain = error as? AuthorityDomainError else {
      return .globalAuthorityUnavailable
    }
    switch domain.code {
    case .ticketInvalid, .ticketExpired, .ticketAlreadyRedeemed:
      return .invalidStartTicket
    default:
      return .globalAuthorityUnavailable
    }
  }

  static func mapAttestationError(_ error: Error) -> PacketTunnelProviderError {
    if let providerError = error as? PacketTunnelProviderError {
      return providerError
    }
    return .globalAuthorityUnavailable
  }
}
