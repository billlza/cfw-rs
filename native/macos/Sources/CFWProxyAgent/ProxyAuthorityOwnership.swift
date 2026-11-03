import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import OSLog

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
  private static let logger = Logger(subsystem: "com.bill.clashformac", category: "proxy-owner")

  private let authority: any ProxyOwnerAuthorityClient
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
    authority: any ProxyOwnerAuthorityClient,
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
    // The Host's reply deadline started when it sent this request. Fixing the
    // libbox deadline now keeps a slow Authority bind from pushing the start's
    // end past it.
    let deadline = EngineStartDeadline(receivedAt: .now)
    let refusal = stateLock.withLock { () -> ProxySessionLifecycleError? in
      guard pendingStart == nil, activeContext == nil, stopFlight == nil else {
        return .lifecycleConflict
      }
      // A retired agent binds no new lease, so the Host cancels the prepared
      // start and finds this owner Off.
      guard !lifecycle.isRetired else { return .agentEnding }
      pendingStart = PendingStart(
        id: startID,
        descriptor: descriptor,
        configuration: configuration,
        deadline: deadline,
        cancellation: nil)
      return nil
    }
    if let refusal {
      configuration.erase()
      authorization.erase()
      completionHandler(.failure(refusal))
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

  /// A session the granted rights restored to Off, one whose engine failed or
  /// whose stop failed for want of the rights, has nothing left running, yet
  /// its bound owner still holds the lease, which the Host, finding the owner
  /// Off, would never stop. The agent stops it as a retried stop would,
  /// attesting Stopped, before it answers, so the Off that follows the answer
  /// finds the lease stopping and completes it. An Authority that quarantined
  /// the stop meanwhile makes the agent end after the answer. A session that
  /// runs, or settings still not restored, keep their state.
  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    lifecycle.restoreSettingsAfterAuthorization { [self] in
      guard let bound = stateLock.withLock({ activeContext }) else {
        completionHandler()
        endProcessIfIdle()
        return
      }
      lifecycle.snapshot { [self] snapshot in
        guard snapshot.state.kind == .off else {
          completionHandler()
          return
        }
        // A stop already in flight takes this one in.
        requestStop(
          expectedConfiguration: bound.descriptor, completions: [{ _ in completionHandler() }])
      }
    }
  }

  var callsLibbox: Bool { lifecycle.callsLibbox }

  func retire(after failure: LibboxInstanceUnclosable) {
    lifecycle.retire(after: failure)
    endProcessIfIdle()
  }

  /// Ends a retired agent once it owns nothing: no start pending and no owner
  /// context bound, so every attestation an operation owed went out first. A
  /// stop of no bound context answers on the lifecycle's queue ahead of the
  /// end. The lifecycle then ends the process once its settings are restored.
  private func endProcessIfIdle() {
    guard lifecycle.isRetired else { return }
    let idle = stateLock.withLock { pendingStart == nil && activeContext == nil }
    if idle { lifecycle.endProcessIfRetired() }
  }

  func restoreSettingsBeforeStop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    lifecycle.restoreSettingsBeforeStop(
      expectedConfiguration: expectedConfiguration, completionHandler: completionHandler)
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
      completion(.failure(Self.authorityFailure(error)))
      completeDeferredStops(deferredStops, with: .success(()))
      endProcessIfIdle()
      return
    }
    let lease: LeaseView
    do {
      let context = authorization.context
      guard context.operation.root.installationID.rawValue == descriptor.installationID,
        context.operation.root.epoch == descriptor.epoch,
        context.operation.root.generation == descriptor.generation,
        context.operation.mode == descriptor.slot.authorityMode,
        context.operation.configSHA256 == descriptor.sha256,
        context.operation.identitySHA256 == descriptor.identitySHA256
      else {
        capability.erase()
        throw AuthorityDomainError(code: .staleOperation)
      }
      lease = try await authority.bind(capability, context: context)
    } catch {
      let deferredStops = finishUnboundStart(startID)
      completion(.failure(Self.authorityFailure(error)))
      completeDeferredStops(deferredStops, with: .success(()))
      endProcessIfIdle()
      return
    }
    let operation = lease.operation
    let context = ActiveContext(
      operation: operation, leaseID: lease.leaseID, descriptor: descriptor)
    guard lease.state == .starting,
      operation == authorization.context.operation,
      lease.leaseID == authorization.context.leaseID,
      operation.mode.isProxyAgent,
      operation.mode == descriptor.slot.authorityMode,
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
        descriptor: descriptor,
        deadline: pending.deadline
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
      if descriptor.slot == .systemProxy {
        let observation = try await observer.observe(descriptor)
        guard observation.isFullyApplied else {
          throw AuthorityDomainError(code: .globalAuthorityUnavailable)
        }
      }
      let attestation = try ReadyAttestation(
        operation: operation, leaseID: leaseID,
        runtimeDigest: operation.identitySHA256, ownerRole: .proxyAgent,
        readyFlags: .required(for: operation.mode), packetPumpLimits: nil,
        monotonicTimestamp: monotonicTimestamp())
      try await authority.attestReady(attestation)
      completion(.success(()))
    } catch {
      // Exact readiness could not be attested; tear the owned runtime and System
      // Proxy state down and fail closed. A failed cleanup or stopped attestation
      // retains the owner context, so global Off is never manufactured: an
      // explicit stop or another revocation retries the exact operation, and a
      // runtime libbox could not close fails every retry with the same cause.
      finishFailedStart(
        originalError: Self.authorityFailure(error),
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
    var flightToAttest: StopFlight?
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
      if let context, locallyStoppedLeaseID == context.leaseID {
        flightToAttest = flight
        return
      }
      // Scheduling while `stateLock` is held is the publish→stop barrier: whoever
      // appends a completion to this flight queues its next work, ending the
      // process included, behind the stop that answers that completion.
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
    if let immediate {
      for completion in incomingCompletions {
        completion(immediate)
      }
      return
    }
    if let flightToAttest {
      attestStopFlight(flightToAttest)
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
        let failure = stoppedAttestationFailure(error)
        // A refused attestation does not say why; only the Authority's own
        // answer about this lease does, and only "absent" settles the stop.
        switch await leaseStatus(of: context) {
        case .absent:
          // The Authority released the lease, after a restart or once it
          // recovered. The local stop was all that was left; the Host proves Off.
          finishStopFlight(flight.id, result: .success(()))
        case .quarantined:
          // The Authority releases a quarantined lease once its owner's process
          // ended. The failure's reply goes first.
          finishStopFlight(flight.id, result: .failure(failure))
          lifecycle.endProcessAfterQuarantinedStop()
        case .held, .notReady, nil:
          finishStopFlight(flight.id, result: .failure(failure))
        }
      }
    }
  }

  /// What the Authority says of this owner's lease, or nil when it gave no
  /// answer, which proves nothing either way.
  private func leaseStatus(of context: ActiveContext) async -> OwnerLeaseStatus? {
    do {
      return try await authority.ownerLeaseStatus(context.leaseID)
    } catch {
      Self.logger.error(
        "The Authority did not say whether it holds the stopped owner's lease: \(Self.authorityMessage(error), privacy: .public)"
      )
      return nil
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
    endProcessIfIdle()
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

  private func monotonicTimestamp() -> UInt64 {
    max(1, clock.nowMilliseconds())
  }
}
