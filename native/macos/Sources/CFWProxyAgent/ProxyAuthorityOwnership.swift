import CFWCredentialTransport
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
/// Fail-closed owner client used until the authenticated ProxyAgent owner XPC
/// channel is wired end to end. Every entry point erases sensitive inputs and
/// reports the Authority as unavailable so no owner binding, attestation, or start
/// can proceed without a real Global Authority. Mirrors the Provider's fail-closed
/// `EngineOwnerAuthorityClient`.
struct FailClosedProxyOwnerAuthorityClient: EngineOwnerAuthorityClient {
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
  private typealias StopCompletion =
    @Sendable (
      Result<Void, ProxySessionLifecycleError>
    ) -> Void

  private struct ActiveContext {
    let operation: OperationContext
    let leaseID: AuthorityIdentifier
    let descriptor: ConfigurationDescriptor
  }

  private struct StopFlight {
    let id: UUID
    let context: ActiveContext?
    let descriptor: ConfigurationDescriptor
    var completions: [StopCompletion]
  }

  private enum PendingCancellation: Equatable {
    case explicitStop
    case authorityRevocation
  }

  private struct PendingStart {
    let id: UUID
    let descriptor: ConfigurationDescriptor
    let configuration: SensitiveDataBuffer
    var cancellation: PendingCancellation?
    var stopCompletions: [StopCompletion] = []
  }

  private let authority: any EngineOwnerAuthorityClient
  private let observer: any EffectiveSystemProxyObserving
  private let lifecycle: ProxySessionLifecycle
  private let clock: any ProxyOwnerMonotonicClock
  private let revocation: ProxyRevocationChannel
  private let stateLock = NSLock()
  private var pendingStart: PendingStart?
  private var activeContext: ActiveContext?
  private var locallyStoppedLeaseID: AuthorityIdentifier?
  private var pendingStopFailure: ProxySessionLifecycleError?
  private var stopFlight: StopFlight?

  init(
    authority: any EngineOwnerAuthorityClient,
    observer: any EffectiveSystemProxyObserving,
    lifecycle: ProxySessionLifecycle,
    revocation: ProxyRevocationChannel,
    clock: any ProxyOwnerMonotonicClock = SystemProxyOwnerMonotonicClock()
  ) {
    self.authority = authority
    self.observer = observer
    self.lifecycle = lifecycle
    self.clock = clock
    self.revocation = revocation
    revocation.onRevoke { [weak self] in
      self?.handleRevocation()
    }
  }

  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    let startID = UUID()
    let admitted = stateLock.withLock { () -> Bool in
      guard pendingStart == nil, activeContext == nil, stopFlight == nil else { return false }
      pendingStart = PendingStart(
        id: startID,
        descriptor: descriptor,
        configuration: configuration,
        cancellation: nil)
      return true
    }
    guard admitted else {
      configuration.erase()
      authorization.erase()
      completionHandler(.failure(.lifecycleConflict))
      return
    }
    Task { [self] in
      await performStart(
        configuration: descriptor,
        authorization: authorization,
        startID: startID,
        completion: completionHandler)
    }
  }

  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    var deferred = false
    var immediate: Result<Void, ProxySessionLifecycleError>?
    stateLock.withLock {
      guard activeContext == nil, var pending = pendingStart else { return }
      guard pending.descriptor == expectedConfiguration else {
        immediate = .failure(.staleStopRequest)
        return
      }
      if pending.cancellation == nil {
        pending.cancellation = .explicitStop
      }
      pending.stopCompletions.append(completionHandler)
      pendingStart = pending
      deferred = true
    }
    if let immediate {
      completionHandler(immediate)
      return
    }
    guard !deferred else { return }
    requestStop(
      expectedConfiguration: expectedConfiguration,
      completion: completionHandler)
  }

  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    lifecycle.snapshot { [self] snapshot in
      let pending = stateLock.withLock { () -> (ActiveContext, ProxySessionLifecycleError)? in
        guard let activeContext, let pendingStopFailure else { return nil }
        return (activeContext, pendingStopFailure)
      }
      guard let (context, failure) = pending else {
        completionHandler(snapshot)
        return
      }
      completionHandler(
        .proxyFailed(
          failure.engineFailure,
          configuration: context.descriptor,
          sequence: snapshot.sequence))
    }
  }

  private func performStart(
    configuration descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    startID: UUID,
    completion: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) async {
    // (1) Obtain and bind the owner capability to the Authority BEFORE any libbox or
    // System Proxy mutation. A missing/unavailable capability or a rejected binding
    // fails closed here, before the data-plane lifecycle is ever started.
    let capability: OwnerCapability
    do {
      capability = try authorization.consumeCapability()
    } catch {
      let deferredStops = finishUnboundStart(startID)
      completion(.failure(.engineLease(Self.authorityMessage(error))))
      completeDeferredStops(deferredStops, with: .success(()))
      return
    }
    let lease: LeaseView
    do {
      let context = authorization.context
      guard context.operation.root.installationID.rawValue == descriptor.installationID,
        context.operation.root.epoch == descriptor.epoch,
        context.operation.root.generation == descriptor.generation,
        context.operation.configSHA256 == descriptor.sha256,
        context.operation.identitySHA256 == descriptor.identitySHA256
      else {
        capability.erase()
        throw AuthorityDomainError(code: .staleOperation)
      }
      lease = try await authority.bind(capability, context: context)
    } catch {
      let deferredStops = finishUnboundStart(startID)
      completion(.failure(.engineLease(Self.authorityMessage(error))))
      completeDeferredStops(deferredStops, with: .success(()))
      return
    }
    let operation = lease.operation
    let context = ActiveContext(
      operation: operation, leaseID: lease.leaseID, descriptor: descriptor)
    guard lease.state == .starting,
      operation == authorization.context.operation,
      lease.leaseID == authorization.context.leaseID,
      operation.mode == .systemProxy,
      operation.configSHA256 == descriptor.sha256,
      operation.identitySHA256 == descriptor.identitySHA256
    else {
      let deferredStops = installBoundContext(context, startID: startID)
      markLocallyStopped(context)
      finishFailedStart(
        originalError: .engineLease(
          "Authority lease does not match the exact System Proxy start context."),
        descriptor: descriptor,
        localStopAlreadyProven: true,
        additionalStopCompletions: deferredStops,
        completion: completion)
      return
    }
    var deferredStops: [StopCompletion] = []
    var cancellation: PendingCancellation?
    let mayStart = stateLock.withLock { () -> Bool in
      guard let pending = pendingStart, pending.id == startID else { return false }
      deferredStops = pending.stopCompletions
      cancellation = pending.cancellation
      pendingStart = nil
      activeContext = context
      locallyStoppedLeaseID = nil
      pendingStopFailure = nil
      guard pending.cancellation == nil else {
        pending.configuration.erase()
        return false
      }
      // Scheduling while `stateLock` is held is the claim→start barrier. Revocation
      // and explicit stop both acquire this same lock before they may decide whether
      // a pending start can proceed.
      lifecycle.start(
        configuration: pending.configuration,
        descriptor: descriptor
      ) { [self] result in
        switch result {
        case .success:
          Task { [self] in
            await completeReadyAttestation(
              operation: operation, leaseID: lease.leaseID,
              descriptor: descriptor, completion: completion)
          }
        case .failure(let error):
          finishFailedStart(
            originalError: error,
            descriptor: descriptor,
            completion: completion)
        }
      }
      return true
    }
    guard mayStart else {
      let cancellationError: ProxySessionLifecycleError =
        cancellation == .explicitStop
        ? .startupCancelled
        : .engineLease("Global Authority revoked the owner before activation.")
      // The claim lock proves `lifecycle.start` was never scheduled. Preserve that
      // proof so an attestation retry does not manufacture a stale local stop.
      markLocallyStopped(context)
      finishFailedStart(
        originalError: cancellationError,
        descriptor: descriptor,
        localStopAlreadyProven: true,
        additionalStopCompletions: deferredStops,
        completion: completion)
      return
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
      // Proxy state down and fail closed. A failed cleanup or stopped attestation
      // retains the owner context so an explicit stop or another revocation can
      // retry the exact operation instead of manufacturing global Off.
      finishFailedStart(
        originalError: .engineLease(Self.authorityMessage(error)),
        descriptor: descriptor,
        completion: completion)
    }
  }

  private func handleRevocation() {
    let context = stateLock.withLock { () -> ActiveContext? in
      if var pending = pendingStart {
        pending.cancellation = .authorityRevocation
        pendingStart = pending
        return nil
      }
      return activeContext
    }
    guard let context else { return }
    // A revocation forces the owner to stop within its bounded window.
    requestStop(expectedConfiguration: context.descriptor, completion: nil)
  }

  private func finishFailedStart(
    originalError: ProxySessionLifecycleError,
    descriptor: ConfigurationDescriptor,
    localStopAlreadyProven: Bool = false,
    additionalStopCompletions: [StopCompletion] = [],
    completion: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    if localStopAlreadyProven,
      let context = stateLock.withLock({ activeContext })
    {
      markLocallyStopped(context)
    }
    var completions = additionalStopCompletions
    completions.append { result in
      switch result {
      case .success:
        completion(.failure(originalError))
      case .failure(let cleanupError):
        completion(.failure(Self.combinedFailure(originalError, cleanupError)))
      }
    }
    requestStop(
      expectedConfiguration: descriptor,
      completions: completions)
  }

  private func requestStop(
    expectedConfiguration: ConfigurationDescriptor,
    completion: StopCompletion?
  ) {
    requestStop(
      expectedConfiguration: expectedConfiguration,
      completions: completion.map { [$0] } ?? [])
  }

  private func requestStop(
    expectedConfiguration: ConfigurationDescriptor,
    completions incomingCompletions: [StopCompletion]
  ) {
    var immediate: Result<Void, ProxySessionLifecycleError>?
    var flightToStart: StopFlight?
    var useExistingProof = false
    stateLock.withLock {
      if let context = activeContext,
        context.descriptor != expectedConfiguration
      {
        immediate = .failure(.staleStopRequest)
        return
      }
      if var current = stopFlight {
        guard current.descriptor == expectedConfiguration else {
          immediate = .failure(.staleStopRequest)
          return
        }
        current.completions.append(contentsOf: incomingCompletions)
        stopFlight = current
        return
      }
      let context = activeContext
      let flight = StopFlight(
        id: UUID(), context: context, descriptor: expectedConfiguration,
        completions: incomingCompletions)
      stopFlight = flight
      useExistingProof = context.map { locallyStoppedLeaseID == $0.leaseID } ?? false
      flightToStart = flight
    }
    if let immediate {
      for completion in incomingCompletions {
        completion(immediate)
      }
      return
    }
    guard let flight = flightToStart else { return }
    if useExistingProof {
      attestStopFlight(flight)
      return
    }
    lifecycle.stop(expectedConfiguration: expectedConfiguration) { [self] result in
      switch result {
      case .failure(let error):
        finishStopFlight(flight.id, result: .failure(error))
      case .success:
        guard let context = flight.context else {
          finishStopFlight(flight.id, result: .success(()))
          return
        }
        markLocallyStopped(context)
        attestStopFlight(flight)
      }
    }
  }

  private func attestStopFlight(_ flight: StopFlight) {
    guard let context = flight.context else {
      finishStopFlight(flight.id, result: .success(()))
      return
    }
    Task { [self] in
      do {
        try await attestProvenStopped(context)
        finishStopFlight(flight.id, result: .success(()))
      } catch {
        finishStopFlight(
          flight.id,
          result: .failure(stoppedAttestationFailure(error)))
      }
    }
  }

  private func finishStopFlight(
    _ id: UUID,
    result: Result<Void, ProxySessionLifecycleError>
  ) {
    let completions = stateLock.withLock { () -> [StopCompletion] in
      guard let current = stopFlight, current.id == id else { return [] }
      stopFlight = nil
      if let context = current.context,
        activeContext?.leaseID == context.leaseID
      {
        switch result {
        case .success:
          activeContext = nil
          locallyStoppedLeaseID = nil
          pendingStopFailure = nil
        case .failure(let error):
          pendingStopFailure = error
        }
      }
      return current.completions
    }
    for completion in completions {
      completion(result)
    }
  }

  private func installBoundContext(
    _ context: ActiveContext,
    startID: UUID
  ) -> [StopCompletion] {
    stateLock.withLock {
      guard let pending = pendingStart, pending.id == startID else { return [] }
      pendingStart = nil
      pending.configuration.erase()
      activeContext = context
      locallyStoppedLeaseID = nil
      pendingStopFailure = nil
      return pending.stopCompletions
    }
  }

  private func finishUnboundStart(_ startID: UUID) -> [StopCompletion] {
    stateLock.withLock {
      guard let pending = pendingStart, pending.id == startID else { return [] }
      pendingStart = nil
      pending.configuration.erase()
      return pending.stopCompletions
    }
  }

  private func completeDeferredStops(
    _ completions: [StopCompletion],
    with result: Result<Void, ProxySessionLifecycleError>
  ) {
    for completion in completions {
      completion(result)
    }
  }

  private func markLocallyStopped(_ context: ActiveContext) {
    stateLock.withLock {
      guard activeContext?.leaseID == context.leaseID else { return }
      locallyStoppedLeaseID = context.leaseID
    }
  }

  /// Sends a stopped attestation only after a local no-ownership proof: either
  /// `ProxySessionLifecycle.stop` crossed every teardown barrier, or the synchronized
  /// pre-start revocation path proved `lifecycle.start` was never called. Both paths
  /// prove that libbox, the ownership journal/local lease, and SCPreferences are Off.
  private func attestProvenStopped(_ context: ActiveContext) async throws {
    let attestation = try StoppedAttestation(
      operation: context.operation, leaseID: context.leaseID,
      libboxStopped: true, transportClosed: true, osRestored: true,
      monotonicTimestamp: monotonicTimestamp())
    try await authority.attestStopped(attestation)
  }

  private func stoppedAttestationFailure(_ error: Error) -> ProxySessionLifecycleError {
    .engineLease("Stopped attestation failed: \(Self.authorityMessage(error))")
  }

  private static func combinedFailure(
    _ original: ProxySessionLifecycleError,
    _ cleanup: ProxySessionLifecycleError
  ) -> ProxySessionLifecycleError {
    .cleanupFailed(
      original: String(describing: original),
      cleanup: [String(describing: cleanup)])
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
