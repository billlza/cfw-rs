import CFWSharedProtocol
import Foundation

/// The System Proxy owner surface the ProxyAgent XPC service drives. It is
/// deliberately identical to `ProxySessionLifecycle`'s completion-based API so the
/// service is unaware of whether it is talking to the raw data-plane lifecycle
/// (tests) or the Authority-owning coordinator (production).
protocol ProxySystemProxyOwning: Sendable {
  func start(
    configuration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  )
  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  )
  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void)
}

extension ProxySessionLifecycle: ProxySystemProxyOwning {}

/// Local engine ownership that grants no machine-wide authority. Under the
/// Authority-owned model the single machine lease belongs to the Global Authority,
/// so the ProxyAgent must never construct `CrossProcessEngineLeaseStore` in its
/// Release start path. The data-plane lifecycle keeps using the lease-holding seam,
/// but this implementation binds no ports and asserts no cross-process exclusion.
final class UnleasedProxyOwnership: ProxyEngineLeaseHolding, @unchecked Sendable {
  func release() throws {}
  func markStopFailed() throws {}
}

/// Monotonic time source for ProxyAgent attestations. Injected so tests can assert
/// exact ready/stopped timestamps without a real clock.
protocol ProxyOwnerMonotonicClock: Sendable {
  func nowMilliseconds() -> UInt64
}

struct SystemProxyOwnerMonotonicClock: ProxyOwnerMonotonicClock {
  func nowMilliseconds() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds / 1_000_000
  }
}

/// Source of the one-use owner capability the Authorized Host hands to the
/// ProxyAgent for a given start. The capability is bound to the Authority before
/// any libbox or System Proxy mutation. The production default fails closed until
/// the authenticated Host→ProxyAgent capability channel is wired end to end, so no
/// System Proxy start can proceed without a real Authority-issued capability.
protocol ProxyOwnerCapabilitySource: Sendable {
  func capability(for descriptor: ConfigurationDescriptor) throws -> OwnerCapability
}

struct FailClosedProxyOwnerCapabilitySource: ProxyOwnerCapabilitySource {
  func capability(for descriptor: ConfigurationDescriptor) throws -> OwnerCapability {
    throw AuthorityDomainError(code: .globalAuthorityUnavailable)
  }
}

/// Fail-closed owner client used until the authenticated ProxyAgent owner XPC
/// channel is wired end to end. Every entry point erases sensitive inputs and
/// reports the Authority as unavailable so no owner binding, attestation, or start
/// can proceed without a real Global Authority. Mirrors the Provider's fail-closed
/// `EngineOwnerAuthorityClient`.
struct FailClosedProxyOwnerAuthorityClient: EngineOwnerAuthorityClient {
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

/// The effective System Proxy state observed after the ProxyAgent applies its owned
/// SCPreferences. Ready attestation is refused unless the product's mixed listener
/// endpoint is effectively applied for every proxy protocol, so `NEVPNStatus`- or
/// journal-only readiness can never be attested as an active owner.
struct EffectiveSystemProxyObservation: Equatable, Sendable {
  let httpApplied: Bool
  let httpsApplied: Bool
  let socksApplied: Bool

  var isFullyApplied: Bool { httpApplied && httpsApplied && socksApplied }
}

protocol EffectiveSystemProxyObserving: Sendable {
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation
}

/// Production observer default. Effective proxy observation is a fail-closed input:
/// until the SCDynamicStore effective-state probe is wired, it reports the effective
/// state as unproven so readiness is never attested from an unverified boundary.
struct FailClosedEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    EffectiveSystemProxyObservation(
      httpApplied: false, httpsApplied: false, socksApplied: false)
  }
}

/// Bounded heartbeat/revocation channel. The Authority delivers a revocation (owner
/// liveness loss, console-user change, Fast User Switching, or a missed heartbeat)
/// by invoking `revoke()`, which forces the owner to stop within its bounded window.
final class ProxyRevocationChannel: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable () -> Void)?

  init() {}

  func onRevoke(_ handler: @escaping @Sendable () -> Void) {
    lock.withLock { self.handler = handler }
  }

  func revoke() {
    let handler = lock.withLock { self.handler }
    handler?()
  }
}

/// Owns the Global Authority interaction for System Proxy operation and sits above
/// the data-plane `ProxySessionLifecycle`:
///
/// 1. binds the owner capability to the Authority BEFORE any libbox start or System
///    Proxy / SCPreferences mutation, failing closed with a typed Authority error
///    when the capability is unavailable or rejected;
/// 2. starts the data-plane lifecycle only after the lease is confirmed;
/// 3. attests exact ready state with the exact operation context and an effective
///    System Proxy observation, tearing the runtime down if readiness cannot be
///    attested;
/// 4. attests exact stopped state on stop; and
/// 5. forces a stop when the Authority revokes the lease (heartbeat loss/FUS/logout).
///
/// There is no local-lease fallback: machine-wide Proxy/Tunnel/multi-user exclusion
/// is enforced only through the Authority lease. All Authority (XPC), effective-proxy
/// observation, and data-plane side effects live behind injected seams so the
/// coordinator is driven deterministically with fakes.
final class ProxySystemProxyOwnerCoordinator: ProxySystemProxyOwning, @unchecked Sendable {
  private struct ActiveContext {
    let operation: OperationContext
    let leaseID: AuthorityIdentifier
    let descriptor: ConfigurationDescriptor
  }

  private let authority: any EngineOwnerAuthorityClient
  private let capabilitySource: any ProxyOwnerCapabilitySource
  private let observer: any EffectiveSystemProxyObserving
  private let lifecycle: ProxySessionLifecycle
  private let clock: any ProxyOwnerMonotonicClock
  private let stateLock = NSLock()
  private var activeContext: ActiveContext?

  init(
    authority: any EngineOwnerAuthorityClient,
    capabilitySource: any ProxyOwnerCapabilitySource,
    observer: any EffectiveSystemProxyObserving,
    lifecycle: ProxySessionLifecycle,
    revocation: ProxyRevocationChannel,
    clock: any ProxyOwnerMonotonicClock = SystemProxyOwnerMonotonicClock()
  ) {
    self.authority = authority
    self.capabilitySource = capabilitySource
    self.observer = observer
    self.lifecycle = lifecycle
    self.clock = clock
    revocation.onRevoke { [weak self] in
      self?.handleRevocation()
    }
  }

  func start(
    configuration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Task { [self] in
      await performStart(configuration: configuration, completion: completionHandler)
    }
  }

  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lifecycle.stop(expectedConfiguration: expectedConfiguration) { [self] result in
      if case .success = result {
        let context = stateLock.withLock { activeContext }
        Task { [self] in
          await attestStoppedIfNeeded(context)
          stateLock.withLock { activeContext = nil }
          completionHandler(result)
        }
      } else {
        completionHandler(result)
      }
    }
  }

  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    lifecycle.snapshot(completionHandler: completionHandler)
  }

  private func performStart(
    configuration descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) async {
    // (1) Obtain and bind the owner capability to the Authority BEFORE any libbox or
    // System Proxy mutation. A missing/unavailable capability or a rejected binding
    // fails closed here, before the data-plane lifecycle is ever started.
    let capability: OwnerCapability
    do {
      capability = try capabilitySource.capability(for: descriptor)
    } catch {
      completion(.failure(.engineLease(Self.authorityMessage(error))))
      return
    }
    let lease: LeaseView
    do {
      lease = try await authority.bind(capability)
    } catch {
      completion(.failure(.engineLease(Self.authorityMessage(error))))
      return
    }
    let operation = lease.operation
    guard operation.mode == .systemProxy,
      operation.configSHA256 == descriptor.sha256,
      operation.identitySHA256 == descriptor.identitySHA256
    else {
      let message = "Authority lease does not match the exact System Proxy start context."
      completion(.failure(.engineLease(message)))
      return
    }
    stateLock.withLock {
      activeContext = ActiveContext(
        operation: operation, leaseID: lease.leaseID, descriptor: descriptor)
    }

    // (2) Start the data-plane lifecycle only after the lease is confirmed.
    lifecycle.start(configuration: descriptor) { [self] result in
      switch result {
      case .success:
        Task { [self] in
          await completeReadyAttestation(
            operation: operation, leaseID: lease.leaseID,
            descriptor: descriptor, completion: completion)
        }
      case .failure(let error):
        Task { [self] in
          await attestStoppedIfNeeded(stateLock.withLock { activeContext })
          stateLock.withLock { activeContext = nil }
          completion(.failure(error))
        }
      }
    }
  }

  private func completeReadyAttestation(
    operation: OperationContext,
    leaseID: AuthorityIdentifier,
    descriptor: ConfigurationDescriptor,
    completion: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) async {
    do {
      // (3) Readiness is attested only when the effective System Proxy state proves
      // the product endpoint is applied for every proxy protocol.
      let observation = try await observer.observe(descriptor)
      guard observation.isFullyApplied else {
        throw AuthorityDomainError(code: .globalAuthorityUnavailable)
      }
      let attestation = try ReadyAttestation(
        operation: operation, leaseID: leaseID,
        runtimeDigest: operation.identitySHA256, ownerRole: .proxyAgent,
        readyFlags: .all, packetPumpLimits: nil,
        monotonicTimestamp: monotonicTimestamp())
      try await authority.attestReady(attestation)
      completion(.success(()))
    } catch {
      // Exact readiness could not be attested; tear the owned runtime and System
      // Proxy state down and fail closed.
      let message = Self.authorityMessage(error)
      lifecycle.stop(expectedConfiguration: descriptor) { [self] _ in
        let context = stateLock.withLock { activeContext }
        Task { [self] in
          await attestStoppedIfNeeded(context)
          stateLock.withLock { activeContext = nil }
          completion(.failure(.engineLease(message)))
        }
      }
    }
  }

  private func handleRevocation() {
    let context = stateLock.withLock { activeContext }
    guard let context else { return }
    // A revocation forces the owner to stop within its bounded window.
    lifecycle.stop(expectedConfiguration: context.descriptor) { [self] _ in
      Task { [self] in
        await attestStoppedIfNeeded(context)
        stateLock.withLock { activeContext = nil }
      }
    }
  }

  private func attestStoppedIfNeeded(_ context: ActiveContext?) async {
    guard let context else { return }
    guard
      let attestation = try? StoppedAttestation(
        operation: context.operation, leaseID: context.leaseID,
        libboxStopped: true, transportClosed: true, osRestored: true,
        monotonicTimestamp: monotonicTimestamp())
    else { return }
    // The local stop already closed libbox and restored owned System Proxy state; a
    // failed attestation does not reopen them. The Host/Authority prove global Off.
    try? await authority.attestStopped(attestation)
  }

  private func monotonicTimestamp() -> UInt64 {
    max(1, clock.nowMilliseconds())
  }

  private static func authorityMessage(_ error: Error) -> String {
    if let domain = error as? AuthorityDomainError {
      return domain.code.stableMessage
    }
    return GlobalAuthorityGateError.stableMessage
  }
}
