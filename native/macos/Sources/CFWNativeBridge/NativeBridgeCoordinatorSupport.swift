import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import CFWSharedProtocol
import Foundation
@preconcurrency import Security
@preconcurrency import SystemExtensions

extension NativeBridgeCoordinator {
  func beginOperation() throws -> UUID {
    guard activeOperation == nil else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Another native engine operation is already in progress."
      )
    }
    let operationID = UUID()
    activeOperation = operationID
    return operationID
  }

  func beginMutation() async throws -> UUID {
    let mutationID = try beginOperation()
    do {
      try await recoverStartupPreferenceMutationIfNeeded()
      return mutationID
    } catch {
      endMutation(mutationID)
      throw Self.map(error)
    }
  }

  /// Clears only the operation that acquired the coordinator. A stale completion
  /// can never release a newer read or mutation after an await/retry boundary.
  func endOperation(_ operationID: UUID) {
    guard activeOperation == operationID else { return }
    activeOperation = nil
  }

  func endMutation(_ mutationID: UUID) { endOperation(mutationID) }

  private func recoverStartupPreferenceMutationIfNeeded() async throws {
    guard !startupPreferenceRecoveryComplete else { return }
    let descriptor = try await tunnel.pendingPreferenceMutationConfiguration()
    guard let descriptor else {
      startupPreferenceRecoveryComplete = true
      return
    }
    let context = try EngineCommandContext(
      installationID: descriptor.installationID,
      configEpoch: descriptor.epoch,
      generation: descriptor.generation
    )
    let recoveredTransaction = NativeStopTransaction(
      owner: .tunnel,
      commandContext: context,
      descriptor: descriptor
    )
    if let pendingStartCleanup {
      guard pendingStartCleanup.owner == recoveredTransaction.owner,
        pendingStartCleanup.commandContext == recoveredTransaction.commandContext,
        pendingStartCleanup.descriptor == recoveredTransaction.descriptor,
        pendingFailedStartOff == nil,
        completedStartCleanup == nil
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Startup Tunnel preference recovery conflicts with another cleanup transaction."
        )
      }
    } else {
      guard pendingStop == nil, pendingFailedStartOff == nil,
        completedStartCleanup == nil
      else {
        throw NativeBridgeExecutionError.failure(
          .cleanupUnproven,
          "Startup Tunnel preference recovery conflicts with another cleanup transaction."
        )
      }
      pendingStartCleanup = recoveredTransaction
    }
    try await reconcilePendingTunnelStartCleanup(recordCompletion: false)
    startupPreferenceRecoveryComplete = true
  }

  func awaitTunnelInstallation(
    context: EngineCommandContext
  ) async throws -> SystemExtensionInstallResult {
    if let pendingTunnelInstallation {
      guard pendingTunnelInstallation.context == context else {
        throw NativeBridgeExecutionError.failure(
          .busy,
          "A different System Extension installation generation is still pending."
        )
      }
      guard pendingTunnelInstallation.state == .retryable else {
        throw NativeBridgeExecutionError.failure(
          .busy,
          "The pending System Extension installation requires exact cancellation before retry."
        )
      }
    }
    pendingTunnelInstallation = NativePendingTunnelInstallation(
      context: context,
      state: .waiting
    )

    do {
      let result = try await tunnel.installTunnel()
      switch result {
      case .completed:
        pendingTunnelInstallation = nil
      case .awaitingApproval:
        pendingTunnelInstallation?.state = .retryable
      case .requiresRestart:
        pendingTunnelInstallation?.state = .terminalReceipt
      }
      return result
    } catch {
      pendingTunnelInstallation?.state =
        Self.isRetryableInstallationWaitError(error)
        ? .retryable : .terminalReceipt
      throw error
    }
  }

  static func isRetryableInstallationWaitError(_ error: Error) -> Bool {
    if error is CancellationError { return true }
    guard let error = error as? AppleNetworkError else { return false }
    return error == .systemExtensionInstallationTimedOut
  }

  static func observe<Value: Sendable>(
    _ operation: @escaping @Sendable () async throws -> Value
  ) async -> NativeObservation<Value> {
    do {
      return .value(try await operation())
    } catch {
      return .failure(error.localizedDescription)
    }
  }

  static func requireObservation<Value: Sendable>(
    _ observation: NativeObservation<Value>,
    component: String
  ) throws -> Value {
    switch observation {
    case .value(let value):
      return value
    case .failure(let message):
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "\(component) state query failed: \(message)"
      )
    }
  }

  static func activeDescriptor(
    _ snapshot: EngineSnapshot,
    expectedMode: EngineMode
  ) throws -> ConfigurationDescriptor? {
    if snapshot.state.kind == .off, snapshot.mode == .off, snapshot.configuration == nil {
      return nil
    }
    let expectedState: EngineStateKind = expectedMode == .systemProxy ? .proxyActive : .tunnelActive
    if snapshot.state.kind == expectedState, snapshot.mode == expectedMode,
      let configuration = snapshot.configuration
    {
      return configuration
    }
    if snapshot.state.kind == .failed {
      throw NativeBridgeExecutionError.failure(
        .unavailable,
        "\(expectedMode.rawValue) endpoint retained a failed native state."
      )
    }
    throw NativeBridgeExecutionError.failure(
      .busy,
      "\(expectedMode.rawValue) endpoint is in transitional state \(snapshot.state.kind.rawValue)."
    )
  }

  static func isStableOff(_ snapshot: EngineSnapshot) -> Bool {
    snapshot.mode == .off && snapshot.state.kind == .off && snapshot.configuration == nil
  }

  static func runtime(
    descriptor: ConfigurationDescriptor,
    proxy: Bool
  ) throws -> NativeRuntimeIdentity {
    NativeRuntimeIdentity(
      owner: proxy ? .proxyAgent : .packetTunnelSystemExtension,
      context: try EngineCommandContext(
        installationID: descriptor.installationID,
        configEpoch: descriptor.epoch,
        generation: descriptor.generation
      ),
      configDigest: descriptor.identitySHA256,
      ready: true
    )
  }

  static func matches(
    _ descriptor: ConfigurationDescriptor,
    context: EngineCommandContext
  ) -> Bool {
    descriptor.installationID == context.installationID
      && descriptor.epoch == context.configEpoch
      && descriptor.generation == context.generation
  }

  static func map(_ error: Error) -> NativeBridgeExecutionError {
    if let error = error as? NativeBridgeExecutionError {
      return error
    }
    if let error = error as? AuthorityDomainError {
      return .failure(error.code.nativeBridgeCode, error.code.stableMessage)
    }
    if error is GlobalAuthorityGateError {
      return .failure(.globalAuthorityUnavailable, GlobalAuthorityGateError.stableMessage)
    }
    if let error = error as? ProxyAgentHostError {
      switch error {
      case .registrationRequiresApproval:
        return .failure(.proxyAgentApprovalRequired, error.localizedDescription)
      case .registrationUnavailable, .transportUnavailable:
        return .failure(.unavailable, error.localizedDescription)
      case .transportTimedOut:
        return .failure(.timeout, error.localizedDescription)
      case .transportCapacityExceeded:
        return .failure(.busy, error.localizedDescription)
      case .agentFailure(let failure):
        return .failure(
          endpointConflictCode(failure, allowsMixed: true)
            ?? (failure.isRetryable ? .unavailable : .configurationRejected),
          error.localizedDescription
        )
      case .registrationFailed, .malformedResponse, .responseMismatch:
        return .failure(.identityRejected, error.localizedDescription)
      }
    }
    if error is CancellationError {
      return .failure(.timeout, "Native operation was cancelled at its bounded wait boundary.")
    }
    if let error = error as? AppleNetworkError {
      switch error {
      case .installationAlreadyInProgress, .systemExtensionRequestCapacityExceeded:
        return .failure(.busy, error.localizedDescription)
      case .systemExtensionInstallationTimedOut:
        return .failure(
          .timeout,
          "System Extension activation did not reach a callback before its internal deadline."
        )
      case .preferenceLoadTimedOut:
        return .failure(
          .timeout,
          "Network Extension preferences did not load before the internal deadline."
        )
      case .preferenceSaveTimedOut:
        return .failure(
          .timeout,
          "Network Extension preferences did not save before the internal deadline."
        )
      case .preferenceRemoveTimedOut:
        return .failure(
          .timeout,
          "Network Extension preferences did not remove before the internal deadline."
        )
      case .preferenceMutationUncertain:
        return .failure(
          .busy,
          "A prior Network Extension preference write is awaiting exact reconciliation."
        )
      case .preferenceMutationJournalUnavailable:
        return .failure(
          .cleanupUnproven,
          "The durable Tunnel preference mutation journal is unavailable."
        )
      case .systemExtensionStateTransportTimedOut, .providerMessageTimedOut,
        .tunnelStopTimedOut:
        return .failure(.timeout, error.localizedDescription)
      case .staleStopRequest, .providerResponseMismatch,
        .managedManagerVerificationFailed:
        return .failure(.identityRejected, error.localizedDescription)
      case .compensationConflict(let message):
        return .failure(.compensationConflict, message)
      case .cleanupUnproven(let message):
        return .failure(.cleanupUnproven, message)
      case .providerFailure(let failure):
        return .failure(
          endpointConflictCode(failure, allowsMixed: false)
            ?? (failure.isRetryable ? .unavailable : .configurationRejected),
          error.localizedDescription
        )
      case .globalAuthorityUnavailable:
        return .failure(.globalAuthorityUnavailable, GlobalAuthorityGateError.stableMessage)
      case .invalidConfigurationSlot:
        return .failure(.configurationRejected, error.localizedDescription)
      case .systemExtensionInstallationFailed(let domain, let code, let message):
        let mappedCode: NativeBridgeErrorCode =
          domain == OSSystemExtensionErrorDomain
            && code == OSSystemExtensionError.authorizationRequired.rawValue
          ? .approvalDenied : .unavailable
        return .failure(
          mappedCode,
          "System Extension activation failed (\(domain):\(code)): \(message)"
        )
      case .duplicateTunnelManagers:
        return .failure(.busy, error.localizedDescription)
      case .preferenceLoadFailed(let failure):
        return preferenceFailure(failure, operation: "load")
      case .preferenceSaveFailed(let failure):
        return preferenceFailure(failure, operation: "save")
      case .preferenceRemoveFailed(let failure):
        return preferenceFailure(failure, operation: "remove")
      case .systemExtensionStateTransportFailed, .tunnelStartFailed,
        .tunnelStartCleanupFailed, .providerDidNotRespond, .providerMessageFailed,
        .unknownSystemExtensionResult:
        return .failure(.unavailable, error.localizedDescription)
      }
    }
    if let error = error as? CredentialVaultError {
      switch error {
      case .immutableConflict:
        return .failure(.credentialConflict, "Credential UUID is immutable and conflicts.")
      case .missingCredential:
        return .failure(.credentialsUnavailable, "A required credential is missing.")
      case .compareAndSwapConflict:
        return .failure(.busy, "Credential vault changed concurrently; retry the exact batch.")
      case .garbageCollectionConfirmationExpired:
        return .failure(
          .credentialGCConflict,
          "Credential cleanup confirmation expired; preview again without deleting anything."
        )
      case .corrupt:
        return .failure(.identityRejected, "Credential vault data is corrupt.")
      case .unsupportedSchemaVersion:
        return .failure(
          .credentialMigrationRequired,
          "Credential vault schema is unsupported; clear and reprovision credentials."
        )
      case .missingVault:
        return .failure(.credentialVaultMissing, "Credential vault does not exist.")
      case .keychain(let status):
        let code: NativeBridgeErrorCode =
          status == errSecMissingEntitlement || status == errSecAuthFailed
          ? .permissionDenied : .unavailable
        return .failure(code, "Credential Keychain operation failed with status \(status).")
      case .invalidAccessGroup:
        return .failure(.identityRejected, "Credential Keychain access group is invalid.")
      case .capacityExceeded:
        return .failure(.resourceExhausted, "Credential vault capacity is exhausted.")
      case .invalidProfileIdentifier, .invalidProfileDigest, .kindMismatch, .duplicateReference,
        .unexpectedCredential:
        return .failure(.configurationRejected, "Credential request is invalid.")
      }
    }
    if let error = error as? CredentialMaterialError {
      switch error {
      case .missingReference:
        return .failure(.credentialsUnavailable, "A required credential is missing.")
      case .duplicateReference, .unexpectedReference, .kindMismatch,
        .nonEmptyPlaceholder, .invalidConfiguration, .configurationTooLarge,
        .malformedPayload, .unsupportedSchemaVersion, .tooManyEntries,
        .secretTooLarge, .totalSecretBytesExceeded, .invalidSecret:
        return .failure(.configurationRejected, "Credential material is invalid.")
      }
    }
    if error is NativeBridgeProtocolError || error is ProtocolValidationError {
      return .failure(.configurationRejected, error.localizedDescription)
    }
    if error is CodeIdentityError {
      return .failure(.identityRejected, error.localizedDescription)
    }
    return .failure(.internal, "Native bridge failed at an explicit internal boundary.")
  }

  private static func endpointConflictCode(
    _ failure: EngineFailure,
    allowsMixed: Bool
  ) -> NativeBridgeErrorCode? {
    switch failure.code {
    case "mixed-endpoint-in-use":
      !failure.isRetryable && allowsMixed ? .mixedEndpointInUse : .identityRejected
    case "controller-endpoint-in-use":
      !failure.isRetryable ? .controllerEndpointInUse : .identityRejected
    default: nil
    }
  }

  private static func preferenceFailure(
    _ failure: NetworkExtensionOperationFailure,
    operation: String
  ) -> NativeBridgeExecutionError {
    let code: NativeBridgeErrorCode =
      failure.disposition == .permissionDenied ? .permissionDenied : .unavailable
    return .failure(
      code,
      "Network Extension preference \(operation) failed (\(failure.domain):\(failure.code)): \(failure.diagnostic)"
    )
  }

  static func publicMessage(_ error: Error) -> String {
    if let error = error as? NativeBridgeExecutionError {
      switch error {
      case .failure(_, let message): return message
      }
    }
    return error.localizedDescription
  }
}
