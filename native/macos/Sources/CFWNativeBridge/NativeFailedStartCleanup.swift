import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func rollbackStartedOwner(
    _ owner: NativeStopOwner,
    descriptor: ConfigurationDescriptor,
    commandContext: EngineCommandContext,
    after originalError: Error,
    cancellationFailure: Error? = nil
  ) async throws -> Never {
    if owner == .tunnel {
      if let pendingStartCleanup {
        guard pendingStartCleanup.owner == owner,
          pendingStartCleanup.commandContext == commandContext,
          pendingStartCleanup.descriptor == descriptor
        else {
          throw NativeBridgeExecutionError.failure(
            .cleanupUnproven,
            "Tunnel start verification conflicts with another cleanup transaction."
          )
        }
      } else {
        pendingStartCleanup = NativeStopTransaction(
          owner: owner,
          commandContext: commandContext,
          descriptor: descriptor)
      }
      do {
        try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
      } catch let error as NativeBridgeExecutionError {
        let localCleanup = await attemptLocalStopAfterOrderingFailure()
        let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start failed and durable preference cleanup remains unproven: \(error.responseFailure.message).\(local)"
        )
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel start cleanup failed at an untyped boundary."
        )
      }
      let transaction = NativeStopTransaction(
        owner: owner,
        commandContext: commandContext,
        descriptor: descriptor)
      try await proveFailedStartOff(transaction)
      throw Self.map(originalError)
    }

    if let pendingStop {
      guard pendingStop.owner == owner,
        pendingStop.commandContext == commandContext,
        pendingStop.descriptor == descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Start verification failed while another native stop transaction remained pending."
        )
      }
    } else {
      pendingStop = NativeStopTransaction(
        owner: owner,
        commandContext: commandContext,
        descriptor: descriptor)
    }

    do {
      // A rollback restores nothing first: the owner's own stop restores its
      // settings once the Authority ordered it, so a failed start's owner never
      // keeps running because they could not be restored. Restoring first is
      // for an Off the user asked for.
      try await drivePendingStop(restoringSettingsFirst: false)
    } catch let error as NativeBridgeExecutionError {
      let localCleanup = await attemptLocalStopAfterOrderingFailure()
      let original = Self.map(originalError).responseFailure.message
      let cancellation =
        cancellationFailure.map {
          " Preparation cancellation also failed: \(Self.map($0).responseFailure.message)"
        } ?? ""
      let cleanup = error.responseFailure.message
      let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Native start failed: \(original)\(cancellation) Cleanup remains unproven: \(cleanup).\(local)"
      )
    } catch {
      let localCleanup = await attemptLocalStopAfterOrderingFailure()
      let local = localCleanup.map { " Local stop also failed: \($0)" } ?? ""
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Native start cleanup failed at an untyped boundary.\(local)"
      )
    }
    rememberCompletedStartCleanup(
      owner: owner,
      commandContext: commandContext,
      descriptor: descriptor)
    throw Self.map(originalError)
  }

  func reconcilePendingTunnelStartCleanup(
    recordCompletion: Bool = true
  ) async throws {
    guard let transaction = pendingStartCleanup,
      transaction.owner == .tunnel
    else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "No exact Tunnel preparation cleanup is pending."
      )
    }

    var ownerControlled = false
    if let pendingStop {
      guard pendingStop.owner == transaction.owner,
        pendingStop.commandContext == transaction.commandContext,
        pendingStop.descriptor == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Tunnel preference cleanup conflicts with another stop transaction."
        )
      }
      ownerControlled = true
    } else {
      ownerControlled =
        !(try await engineLease.cancelPreparedStart(
          for: transaction.descriptor))
      if ownerControlled {
        pendingStop = transaction
      }
    }

    if ownerControlled {
      try await beginPendingStopAtAuthority()
    }

    let preferenceCompensated: Bool
    if pendingStop?.preferenceCompensated == true {
      // A prior attempt already restored the exact preference state and proved
      // OS Off, but Authority completion or the final global query failed. Do
      // not replay beginStop after a lost complete reply may have committed Off.
      // The final fresh verification below still guards journal removal.
      preferenceCompensated = true
    } else {
      let authority = pendingStop?.authority ?? .unordered
      let engineLease = self.engineLease
      let commandContext = transaction.commandContext
      do {
        preferenceCompensated = try await tunnel.compensatePendingPreferenceMutation(
          expectedConfiguration: transaction.descriptor,
          revokePreparation: {
            switch authority {
            case .completed:
              // The Authority committed Off for this lease, so nothing it
              // authorized can start any more.
              return
            case .ordered(let authorityContext):
              let observed: NativeAuthorityStopContext
              do {
                observed = try await engineLease.beginStop(for: transaction.descriptor)
              } catch let error as AuthorityDomainError
                where error.code == .globalAuthorityRecovering
              {
                // The Authority released the lease since, so nothing it
                // authorized can start any more.
                return
              } catch let stale as AuthorityDomainError where stale.code == .staleOperation {
                // The Authority reached Off at this generation or passed it
                // since, so the lease ended and nothing it authorized can
                // start any more.
                guard try await engineLease.stopResolution(commandContext) != .unresolved else {
                  throw stale
                }
                return
              }
              guard observed == authorityContext else {
                throw NativeBridgeExecutionError.failure(
                  .cleanupUnproven,
                  "Authority stop identity changed during preference compensation."
                )
              }
            case .unordered, .released:
              // A Recovering Authority holds no preparation either.
              guard try await engineLease.cancelPreparedStart(for: transaction.descriptor) else {
                throw NativeBridgeExecutionError.failure(
                  .cleanupUnproven,
                  "Authority retained owner control during preference compensation."
                )
              }
            }
          }
        )
      } catch {
        throw Self.map(error)
      }
    }

    if ownerControlled {
      if preferenceCompensated {
        guard var stoppedTransaction = pendingStop else {
          throw NativeBridgeExecutionError.failure(
            .cleanupUnproven,
            "Tunnel preference compensation lost its Authority stop transaction."
          )
        }
        // Compensation has independently stopped the exact written manager and
        // proved NetworkExtension Off. Authority completion remains the final,
        // independent durable owner-stopped check.
        stoppedTransaction.preferenceCompensated = true
        stoppedTransaction.ownerStopped = true
        pendingStop = stoppedTransaction
      } else {
        try await drivePendingStopToOwnerStopped(restoringSettingsFirst: false)
      }
      try await completePendingStopAfterOwnerStopped()
    }

    do {
      try await tunnel.finishPreferenceCompensation(
        expectedConfiguration: transaction.descriptor)
    } catch {
      throw Self.map(error)
    }

    pendingStartCleanup = nil
    if recordCompletion {
      rememberCompletedStartCleanup(
        owner: transaction.owner,
        commandContext: transaction.commandContext,
        descriptor: transaction.descriptor)
    }
  }

  private func rememberCompletedStartCleanup(
    owner: NativeStopOwner,
    commandContext: EngineCommandContext,
    descriptor: ConfigurationDescriptor
  ) {
    completedStartCleanup = NativeStartCleanupReceipt(
      owner: owner,
      commandContext: commandContext,
      descriptor: descriptor)
  }

  func acknowledgeCompletedStartCleanup(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws -> Bool {
    guard let receipt = completedStartCleanup else { return false }
    guard receipt.owner == owner,
      receipt.commandContext == context
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The cleanup acknowledgement does not match the failed start generation."
      )
    }
    try await requireFailedStartGlobalOff(
      "The failed-start cleanup receipt no longer has a fresh global Off proof.")
    completedStartCleanup = nil
    return true
  }

  func resumePendingFailedStartOff(
    _ owner: NativeStopOwner,
    context: EngineCommandContext
  ) async throws -> Bool {
    guard let transaction = pendingFailedStartOff else { return false }
    guard transaction.owner == owner,
      transaction.commandContext == context
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The failed-start Off retry does not match the pending generation."
      )
    }
    try await proveFailedStartOff(transaction)
    guard try await acknowledgeCompletedStartCleanup(owner, context: context) else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "The failed-start Off proof completed without an exact receipt."
      )
    }
    return true
  }

  private func retainPendingFailedStartOff(
    _ transaction: NativeStopTransaction
  ) throws {
    if let pendingFailedStartOff {
      guard pendingFailedStartOff.owner == transaction.owner,
        pendingFailedStartOff.commandContext == transaction.commandContext,
        pendingFailedStartOff.descriptor == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start Off proof conflicts with another cleanup transaction."
        )
      }
      return
    }
    guard completedStartCleanup == nil else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start Off proof conflicts with an unacknowledged cleanup receipt."
      )
    }
    pendingFailedStartOff = transaction
  }

  func proveFailedStartOff(
    _ transaction: NativeStopTransaction
  ) async throws {
    try retainPendingFailedStartOff(transaction)
    guard pendingStartCleanup == nil, pendingStop == nil else {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start Off proof began before its earlier cleanup phase completed."
      )
    }
    let initial: EngineSnapshot
    do {
      initial = try await ownerSnapshot(transaction.owner)
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "Failed-start owner state could not be observed: \(Self.map(error).responseFailure.message)"
      )
    }
    if !Self.isStableOff(initial) {
      guard initial.state.kind == .failed,
        initial.configuration == transaction.descriptor
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start owner state does not match the exact failed generation."
        )
      }
      do {
        try await stopOwner(transaction)
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Failed-start owner could not advance to Off: \(Self.map(error).responseFailure.message)"
        )
      }
      let stopped: EngineSnapshot
      do {
        stopped = try await ownerSnapshot(transaction.owner)
      } catch {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Stopped failed-start owner could not be observed: \(Self.map(error).responseFailure.message)"
        )
      }
      guard Self.isStableOff(stopped) else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "The exact failed-start owner did not attest Off after cleanup."
        )
      }
    }
    try await requireFailedStartGlobalOff(
      "Failed-start cleanup did not reach the independent global Off barrier.")
    pendingFailedStartOff = nil
    rememberCompletedStartCleanup(
      owner: transaction.owner,
      commandContext: transaction.commandContext,
      descriptor: transaction.descriptor)
  }

  private func requireFailedStartGlobalOff(_ context: String) async throws {
    let status: NativeEngineStatus
    do {
      status = try await queryStatus(enforcePreferenceBarrier: false)
    } catch {
      throw NativeBridgeExecutionError.failure(
        .cleanupUnproven,
        "\(context) Observation failed: \(Self.map(error).responseFailure.message)"
      )
    }
    guard case .off = status else {
      throw NativeBridgeExecutionError.failure(.cleanupUnproven, context)
    }
  }
}
