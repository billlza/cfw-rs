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

/// Fail-closed owner client used until the authenticated Provider owner XPC channel
/// is wired end to end. Every entry point erases sensitive inputs and reports the
/// Authority as unavailable so no start can proceed without a real redemption.
struct FailClosedEngineOwnerAuthorityClient: EngineOwnerAuthorityClient {
  func bind(_ capability: OwnerCapability) async throws -> LeaseView {
    capability.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func redeem(_ ticket: StartTicket) async throws -> RedeemedTunnelStart {
    ticket.erase()
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func attestReady(_ attestation: ReadyAttestation) async throws {
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }

  func attestStopped(_ attestation: StoppedAttestation) async throws {
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
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
  private enum Phase {
    case idle
    case busy
  }

  private let authority: any EngineOwnerAuthorityClient
  private let sessionLifecycle: PacketTunnelSessionLifecycle
  private let clock: any ProviderMonotonicClock
  private let stateLock = NSLock()
  private var phase = Phase.idle
  private var activeContext: (operation: OperationContext, leaseID: AuthorityIdentifier)?

  init(
    authority: any EngineOwnerAuthorityClient,
    sessionLifecycle: PacketTunnelSessionLifecycle,
    clock: any ProviderMonotonicClock = SystemProviderMonotonicClock()
  ) {
    self.authority = authority
    self.sessionLifecycle = sessionLifecycle
    self.clock = clock
  }

  /// Redeems `ticket` and starts the tunnel. `ticket` is consumed (erased) on every
  /// path. The completion fires with `nil` only after libbox is injected and running
  /// and the Authority has accepted the exact ready attestation.
  func start(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Error?) -> Void
  ) {
    let admitted = stateLock.withLock { () -> Bool in
      guard case .idle = phase else { return false }
      phase = .busy
      return true
    }
    guard admitted else {
      ticket.erase()
      completion(PacketTunnelProviderError.lifecycleConflict)
      return
    }
    Task { [self] in
      await performStart(ticket: ticket, descriptor: descriptor, completion: completion)
    }
  }

  func stop(completion: @escaping @Sendable () -> Void) {
    let context = stateLock.withLock { activeContext }
    sessionLifecycle.stop { [self] in
      Task { [self] in
        await attestStoppedIfNeeded(context)
        stateLock.withLock {
          activeContext = nil
          phase = .idle
        }
        completion()
      }
    }
  }

  private func performStart(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Error?) -> Void
  ) async {
    let redeemed: RedeemedTunnelStart
    do {
      redeemed = try await authority.redeem(ticket)
    } catch {
      finishFailure(Self.mapRedeemError(error), completion: completion)
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
    guard operation.mode == .tunnel,
      operation.configSHA256 == descriptor.sha256,
      operation.identitySHA256 == descriptor.identitySHA256,
      descriptor.slot == .tunnel
    else {
      eraseRedeemedTransport()
      finishFailure(.invalidConfigurationSlot, completion: completion)
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
      finishFailure(.configuration(String(describing: error)), completion: completion)
      return
    }
    // Nothing below reads the Authority transport buffers again, so wipe them before
    // the session lifecycle can call back and complete the start.
    eraseRedeemedTransport()

    stateLock.withLock { activeContext = (operation, leaseID) }

    sessionLifecycle.start(
      descriptor: descriptor,
      configuration: configurationTemplate,
      credentialMaterial: credentialMaterial
    ) { [self] error in
      if let error {
        finishFailure(mappedStartError(error), completion: completion)
        return
      }
      Task { [self] in
        await completeReadyAttestation(
          operation: operation, leaseID: leaseID,
          descriptor: descriptor, completion: completion)
      }
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
      completion(nil)
    } catch {
      // Exact readiness could not be attested; tear the runtime down and fail closed.
      // The failure is reported only after the teardown barrier completes, so no
      // caller can observe a failed start while libbox and the transport are still
      // owned, and no retry can be admitted before the coordinator is idle again.
      let failure = Self.mapAttestationError(error)
      sessionLifecycle.stop { [self] in
        stateLock.withLock {
          activeContext = nil
          phase = .idle
        }
        completion(failure)
      }
    }
  }

  private func attestStoppedIfNeeded(
    _ context: (operation: OperationContext, leaseID: AuthorityIdentifier)?
  ) async {
    guard let context else { return }
    guard
      let attestation = try? StoppedAttestation(
        operation: context.operation,
        leaseID: context.leaseID,
        libboxStopped: true,
        transportClosed: true,
        osRestored: true,
        monotonicTimestamp: monotonicTimestamp())
    else { return }
    // The local stop already closed libbox and the transport; a failed attestation
    // does not reopen them. The Host/Authority prove the global Off barrier.
    try? await authority.attestStopped(attestation)
  }

  private func finishFailure(
    _ error: PacketTunnelProviderError,
    completion: @escaping @Sendable (Error?) -> Void
  ) {
    stateLock.withLock {
      activeContext = nil
      phase = .idle
    }
    completion(error)
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
