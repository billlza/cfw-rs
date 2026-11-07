import CFWSharedProtocol

public enum AppleNetworkError: Error, Equatable, Sendable {
  case installationAlreadyInProgress
  case systemExtensionRequestCapacityExceeded
  case systemExtensionInstallationTimedOut
  case unknownSystemExtensionResult(Int)
  case systemExtensionInstallationFailed(domain: String, code: Int, message: String)
  case preferenceLoadFailed(NetworkExtensionOperationFailure)
  case preferenceLoadTimedOut
  case preferenceSaveFailed(NetworkExtensionOperationFailure)
  case preferenceSaveTimedOut
  case preferenceMutationUncertain
  case preferenceMutationJournalUnavailable(String)
  case preferenceRemoveFailed(NetworkExtensionOperationFailure)
  case preferenceRemoveTimedOut
  case duplicateTunnelManagers(Int)
  case globalAuthorityUnavailable
  case invalidConfigurationSlot
  case systemExtensionStateTransportFailed(String)
  case systemExtensionStateTransportTimedOut
  case tunnelStartFailed(String)
  case tunnelStartCleanupFailed(start: String, cleanup: String)
  case tunnelStopTimedOut
  case staleStopRequest
  case providerDidNotRespond
  case providerMessageTimedOut
  case providerMessageFailed(String)
  case providerResponseMismatch
  case providerFailure(EngineFailure)
  case managedManagerVerificationFailed(String)
  /// Compensation observed a managed-preference change it must not overwrite
  /// (external/administrator edit or a missing prior value); leaves Quarantined.
  case compensationConflict(String)
  /// Compensation could not prove cleanup within its bounded budget (stop timeout
  /// or an unverifiable restored result); leaves Quarantined.
  case cleanupUnproven(String)
}
