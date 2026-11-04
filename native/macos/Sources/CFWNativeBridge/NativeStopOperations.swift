import CFWAppleNetwork
import CFWSharedProtocol
import Foundation
import OSLog

extension NativeBridgeCoordinator {
  private static let restorationLog = Logger(
    subsystem: "com.bill.clashformac", category: "system-proxy-restoration")

  func requireNoPendingStopBeforeStart() throws {
    guard pendingStop == nil,
      pendingStartCleanup == nil,
      pendingFailedStartOff == nil,
      completedStartCleanup == nil
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A prior native stop transaction has not reached the global Off barrier."
      )
    }
  }

  func prepareExplicitStop(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws -> Bool {
    if let pendingStop {
      guard pendingStop.owner == owner,
        pendingStop.commandContext == context
      else {
        throw NativeBridgeExecutionError.failure(
          .identityRejected,
          "The stop retry does not match the pending native stop transaction."
        )
      }
      return true
    }

    let snapshot: EngineSnapshot
    do {
      snapshot = try await ownerSnapshot(owner)
    } catch {
      throw Self.map(error)
    }
    if Self.isStableOff(snapshot) {
      // The OS may finish a stop before the Host consumes its final status.
      // Bind the request to that exact completed/stopping generation, then
      // require both the independent OS barrier and the durable Off cursor.
      do {
        // An Authority that passed this generation since holds nothing of it,
        // whatever later start it holds now.
        if try await engineLease.stopResolution(context) == .superseded {
          try await requireOwnerOffAfterSupersededStop(owner, context: context)
          return false
        }
        if let recovered = try await engineLease.recoverStoppingLease() {
          guard recovered.commandContext == context, recovered.owner == owner else {
            throw NativeBridgeExecutionError.failure(
              .identityRejected, "The stop request does not match the released owner generation.")
          }
        }
        guard case .off = try await queryStatus() else {
          throw AuthorityDomainError(code: .cleanupUnproven)
        }
        guard try await engineLease.stopResolution(context) != .unresolved else {
          throw NativeBridgeExecutionError.failure(
            .identityRejected, "The stop request has no matching completed generation.")
        }
        return false
      } catch {
        throw Self.map(error)
      }
    }
    let expectedMode = owner.engineMode
    let stopDescriptor: ConfigurationDescriptor?
    if snapshot.state.kind == .failed,
      snapshot.mode == expectedMode,
      let descriptor = snapshot.configuration,
      descriptor.slot.engineMode == expectedMode
    {
      // Failed is never readiness. An explicit Stop may still clean this exact
      // retained owner; beginStop subsequently binds its content/identity digests
      // and generation to the Authority lease before any owner teardown.
      stopDescriptor = descriptor
    } else {
      stopDescriptor = try Self.activeDescriptor(snapshot, expectedMode: expectedMode)
    }
    guard let descriptor = stopDescriptor,
      Self.matches(descriptor, context: context)
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The native owner stop does not match the active generation."
      )
    }
    pendingStop = NativeStopTransaction(
      owner: owner,
      commandContext: context,
      descriptor: descriptor)
    return true
  }

  /// `restoringSettingsFirst` is for a System Proxy stop the user asked for:
  /// see `restoreSystemProxySettingsBeforeStop`.
  func drivePendingStop(restoringSettingsFirst: Bool) async throws {
    try await drivePendingStopToOwnerStopped(restoringSettingsFirst: restoringSettingsFirst)
    try await completePendingStopAfterOwnerStopped()
  }

  func beginPendingStopAtAuthority() async throws {
    guard var transaction = pendingStop else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "No native stop transaction is available to continue."
      )
    }

    guard case .unordered = transaction.authority else { return }
    do {
      transaction.authority = .ordered(
        try await engineLease.beginStop(for: transaction.descriptor))
    } catch let error as AuthorityDomainError where error.code == .globalAuthorityRecovering {
      // A restarted Authority, or one whose quarantined owner ended, holds no
      // lease to order. The owner is still stopped, and the Host's own Off
      // proof ends the stop.
      transaction.authority = .released
    } catch let stale as AuthorityDomainError where stale.code == .staleOperation {
      // An Authority that already reached Off at this stop's generation, for
      // example when a status query reconciled it after the owner ended, or
      // that passed the generation since, holds no lease to order either. Any
      // other state leaves the lease this stop names unaccounted for.
      let resolution: NativeStopResolution
      do {
        resolution = try await engineLease.stopResolution(transaction.commandContext)
      } catch {
        throw Self.map(error)
      }
      guard resolution != .unresolved else { throw Self.map(stale) }
      transaction.authority = .released
    } catch {
      throw Self.map(error)
    }
    pendingStop = transaction
  }

  func drivePendingStopToOwnerStopped(restoringSettingsFirst: Bool) async throws {
    var settingsRestored = false
    if restoringSettingsFirst, let transaction = pendingStop,
      transaction.authority == .unordered, transaction.owner == .systemProxy,
      !transaction.ownerStopped
    {
      settingsRestored = try await restoreSystemProxySettingsBeforeStop(transaction.descriptor)
    }
    do {
      try await beginPendingStopAtAuthority()
    } catch let orderingError where settingsRestored {
      // The settings no longer select the listener, so a session left running
      // would serve nothing while the status still reported it. The user asked
      // for Off: the owner stops now, and the stop stays pending until the
      // Authority orders and completes it.
      let ordering = Self.map(orderingError).responseFailure
      guard let localFailure = await attemptLocalStopAfterOrderingFailure() else {
        throw NativeBridgeExecutionError.failure(ordering.code, ordering.message)
      }
      throw NativeBridgeExecutionError.failure(
        ordering.code, "\(ordering.message) Local stop also failed: \(localFailure)")
    }
    guard var transaction = pendingStop else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The native stop transaction disappeared after Authority ordering."
      )
    }

    if !transaction.ownerStopped {
      do {
        try await stopOwner(transaction)
      } catch ProxyAgentHostError.agentFailure(let failure)
        where ProxyAgentFailure(code: failure.code) == .agent(.stopWithoutSession)
      {
        // The Authority is stopping this lease, so no owner can bind it any
        // more, and a ProxyAgent with no session and no record of the stop
        // holds nothing for it: its owner has ended, for example after an
        // engine it could not close, or attested Stopped before it started the
        // engine. No owner is left to stop. Authority completion decides: it
        // accepts only an owner that attested Stopped, and otherwise reports
        // unproven cleanup. A stale reply instead names a session of another
        // generation, whose owner has not ended, so it fails the stop below.
      } catch AppleNetworkError.staleStopRequest
        where transaction.owner == .tunnel && transaction.authority == .released
      {
        // The Authority holds no lease of this stop, and Network Extension no
        // manager of its generation: a later start replaced it, or none is
        // left. Nothing of this stop is left to stop, and completion proves
        // the tunnel Off.
      } catch {
        throw Self.map(error)
      }
      transaction.ownerStopped = true
      pendingStop = transaction
    }
  }

  func completePendingStopAfterOwnerStopped() async throws {
    guard var transaction = pendingStop, transaction.ownerStopped else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The owner is not proven stopped before Authority completion."
      )
    }

    switch transaction.authority {
    case .unordered:
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The Authority stop context was lost before completion."
      )
    case .ordered(let authorityContext):
      do {
        try await engineLease.completeStop(authorityContext)
        transaction.authority = .completed(authorityContext)
      } catch let error as AuthorityDomainError where error.code == .globalAuthorityRecovering {
        // The Authority released the lease, as a restart does, once the owner
        // that never attested this stop ended. Reconciling Off proves the stop.
        transaction.authority = .released
      } catch let error as AuthorityDomainError {
        // An Authority that passed this stop's generation since ended its
        // lease through a proven Off, so nothing is left to complete.
        guard try await stopResolution(transaction) == .superseded else {
          throw Self.map(error)
        }
        transaction.authority = .released
      } catch {
        throw Self.map(error)
      }
      pendingStop = transaction
    case .completed, .released:
      break
    }

    if case .released = transaction.authority,
      try await stopResolution(transaction) == .superseded
    {
      // What the Authority holds now belongs to a later start, so its Off
      // barrier says nothing of this stop's owner.
      try await requireOwnerOffAfterSupersededStop(
        transaction.owner, context: transaction.commandContext)
      pendingStop = nil
      return
    }
    // A Recovering Authority reaches Off only through this query's
    // reconciliation, after the Host proved both owners and the OS Off.
    guard case .off = try await queryStatus(enforcePreferenceBarrier: false) else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The native stop transaction did not reach the global Off barrier."
      )
    }
    if case .released = transaction.authority {
      guard try await stopResolution(transaction) != .unresolved else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "The Authority reached Off for another generation than this stop's."
        )
      }
    }
    pendingStop = nil
  }

  func stopResolution(
    _ transaction: NativeStopTransaction
  ) async throws -> NativeStopResolution {
    do {
      return try await engineLease.stopResolution(transaction.commandContext)
    } catch {
      throw Self.map(error)
    }
  }

  /// Ends a stop whose generation the Authority passed. Its lease ended
  /// through a proven Off, so one fresh snapshot of the stop's own owner
  /// showing it Off ends the stop. An explicit Tunnel stop also needs its
  /// preference journal settled, as the status barrier it replaces does.
  private func requireOwnerOffAfterSupersededStop(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws {
    let snapshot: EngineSnapshot
    do {
      snapshot = try await ownerSnapshot(owner)
    } catch {
      throw Self.map(error)
    }
    guard Self.isStableOff(snapshot) else {
      if let configuration = snapshot.configuration,
        configuration.installationID == context.installationID,
        (configuration.epoch, configuration.generation)
          > (context.configEpoch, context.generation)
      {
        throw NativeBridgeExecutionError.failure(
          .busy, "A later start holds the owner of this stop.")
      }
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven, "The owner of a stop the Authority passed is not Off.")
    }
    guard owner == .tunnel, pendingStartCleanup == nil else { return }
    let pendingMutation: ConfigurationDescriptor?
    do {
      pendingMutation = try await tunnel.pendingPreferenceMutationConfiguration()
    } catch {
      throw Self.map(error)
    }
    guard pendingMutation == nil else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "A durable Tunnel preference mutation must be recovered before the stop can end.")
    }
  }

  /// Has the ProxyAgent give the OS back the System Proxy settings of the
  /// session the user asked to stop while its engine still answers, before the
  /// Authority is asked to stop the session. A restore that cannot reach the
  /// settings then fails the stop with System Proxy still running, and the stop
  /// stays retryable, instead of the settings outliving the listener they
  /// select. Returns whether the ProxyAgent restored them. Only a ProxyAgent
  /// of this app's build can, so one of an earlier build, or one whose build
  /// cannot be told, is not asked: its session stops as that build stops it,
  /// restoring the settings as it ends.
  private func restoreSystemProxySettingsBeforeStop(
    _ descriptor: ConfigurationDescriptor
  ) async throws -> Bool {
    let inspection: CurrentAppServiceBuildInspection
    do {
      inspection = try serviceBuildObserver.inspect()
    } catch {
      Self.restorationLog.error(
        "The ProxyAgent build could not be told before a stop, so the stop restores no settings first: \(String(describing: error), privacy: .public)"
      )
      return false
    }
    guard inspection.proxy.isCurrent else { return false }
    do {
      try await proxy.restoreSettingsBeforeStop(configuration: descriptor)
    } catch {
      throw Self.map(error)
    }
    return true
  }

  func ownerSnapshot(_ owner: NativeStopOwner) async throws -> EngineSnapshot {
    switch owner {
    case .localProxy, .systemProxy: try await proxy.snapshot()
    case .tunnel: try await tunnel.snapshot()
    }
  }

  func stopOwner(_ transaction: NativeStopTransaction) async throws {
    switch transaction.owner {
    case .localProxy, .systemProxy:
      try await proxy.stop(configuration: transaction.descriptor)
    case .tunnel:
      try await tunnel.stopTunnel(expectedConfiguration: transaction.descriptor)
    }
  }

  /// If Authority ordering itself becomes unavailable during a failed start, or
  /// after a System Proxy stop the user asked for restored its settings, the
  /// already-started owner must still be asked to tear down. The transaction remains
  /// pending so a later retry can complete the missing Authority barrier exactly.
  func attemptLocalStopAfterOrderingFailure() async -> String? {
    guard var transaction = pendingStop, !transaction.ownerStopped else { return nil }
    do {
      try await stopOwner(transaction)
      transaction.ownerStopped = true
      pendingStop = transaction
      return nil
    } catch {
      return Self.map(error).responseFailure.message
    }
  }
}
