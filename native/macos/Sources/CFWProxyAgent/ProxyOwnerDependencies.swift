import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation

/// The System Proxy owner surface the ProxyAgent XPC service drives. It is
/// deliberately identical to `ProxySessionLifecycle`'s completion-based API so the
/// service is unaware of whether it is talking to the raw data-plane lifecycle
/// (tests) or the Authority-owning coordinator (production).
protocol ProxySystemProxyOwning: Sendable {
  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  )
  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  )
  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void)
  /// Restores the System Proxy settings left for want of the network
  /// preferences rights the user just granted; see `ProxySessionLifecycle`.
  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void)
  /// Restores an active session's System Proxy settings before its stop; see
  /// `ProxySessionLifecycle`.
  func restoreSettingsBeforeStop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  )
  /// Whether checks and probes may still reach libbox: not once the agent is
  /// spent or retired. Answers without waiting on any queue.
  var callsLibbox: Bool { get }
  /// A check or probe left in libbox what this process cannot release: the
  /// agent refuses every later check, probe and start, lets a running session
  /// stop as usual, and ends once it is idle.
  func retire(after failure: LibboxInstanceUnclosable)
}

/// One-use Host→ProxyAgent authorization package. The high-entropy capability
/// is transported as a separate bounded XPC Data argument and erased on every
/// path; the non-secret context is canonical Authority v1 metadata.
final class ProxyOwnerAuthorization: @unchecked Sendable {
  let context: ProxyOwnerContext
  private let lock = NSLock()
  private var capability: OwnerCapability?

  init(context: ProxyOwnerContext, capability: OwnerCapability) {
    self.context = context
    self.capability = capability
  }

  deinit { erase() }

  func consumeCapability() throws -> OwnerCapability {
    try lock.withLock {
      guard let capability else {
        throw AuthorityDomainError(code: .ticketAlreadyRedeemed)
      }
      self.capability = nil
      return capability
    }
  }

  func erase() {
    let value = lock.withLock {
      let value = capability
      capability = nil
      return value
    }
    value?.erase()
  }
}

/// Local engine ownership that grants no machine-wide authority. Under the
/// Authority-owned model the single machine lease belongs to the Global Authority,
/// so the ProxyAgent must never construct `CrossProcessEngineLeaseStore` in its
/// Release start path. The data-plane lifecycle keeps using the lease-holding seam,
/// but this implementation binds no ports and asserts no cross-process exclusion.
final class UnleasedProxyOwnership: ProxyEngineLeaseHolding, @unchecked Sendable {
  func release() throws {}
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
/// Fail-closed owner client used until the authenticated ProxyAgent owner XPC
/// channel is wired end to end. Every entry point erases sensitive inputs and
/// reports the Authority as unavailable so no owner binding, attestation, or start
/// can proceed without a real Global Authority. Mirrors the Provider's fail-closed
/// `EngineOwnerAuthorityClient`.
struct FailClosedProxyOwnerAuthorityClient: ProxyOwnerAuthorityClient {
  func bind(
    _ capability: OwnerCapability, context: ProxyOwnerContext
  ) async throws -> LeaseView {
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

  func ownerLeaseStatus(_ leaseID: AuthorityIdentifier) async throws -> OwnerLeaseStatus {
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

struct JournalBackedEffectiveSystemProxyObserver: EffectiveSystemProxyObserving {
  let preferences: SCPreferencesSystemProxyPreferences
  let journalStore: any ProxyOwnershipJournalStoring

  func observe(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> EffectiveSystemProxyObservation {
    try preferences.observeEffectiveAppliedValues(
      descriptor: descriptor,
      journalStore: journalStore)
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
