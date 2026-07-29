import CFWAppleNetwork
import CFWCredentialTransport
import CFWCredentialVault
import CFWSharedProtocol
import Foundation
@preconcurrency import Security

extension NativeBridgeCoordinator {
  func beginMutation() throws {
    guard activeMutation == nil else {
      throw NativeBridgeExecutionError.failure(
        .busy,
        "Another native engine mutation is already in progress."
      )
    }
    activeMutation = UUID()
  }

  func endMutation() {
    activeMutation = nil
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
        return .failure(.permissionDenied, error.localizedDescription)
      case .registrationUnavailable, .transportUnavailable:
        return .failure(.unavailable, error.localizedDescription)
      case .transportTimedOut:
        return .failure(.timeout, error.localizedDescription)
      case .agentFailure(let failure):
        return .failure(
          failure.isRetryable ? .unavailable : .configurationRejected,
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
      case .installationAlreadyInProgress:
        return .failure(.busy, error.localizedDescription)
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
          failure.isRetryable ? .unavailable : .configurationRejected,
          error.localizedDescription
        )
      case .globalAuthorityUnavailable:
        return .failure(.globalAuthorityUnavailable, GlobalAuthorityGateError.stableMessage)
      case .invalidConfigurationSlot:
        return .failure(.configurationRejected, error.localizedDescription)
      case .systemExtensionInstallationFailed(let code, let message):
        return .failure(.approvalDenied, "System Extension activation failed (\(code)): \(message)")
      case .duplicateTunnelManagers:
        return .failure(.busy, error.localizedDescription)
      case .preferenceLoadFailed, .preferenceSaveFailed,
        .systemExtensionStateTransportFailed, .tunnelStartFailed,
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
      case .invalidProfileIdentifier, .invalidProfileDigest, .kindMismatch, .duplicateReference,
        .unexpectedCredential, .capacityExceeded:
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

  static func publicMessage(_ error: Error) -> String {
    if let error = error as? NativeBridgeExecutionError {
      switch error {
      case .failure(_, let message): return message
      }
    }
    return error.localizedDescription
  }
}
