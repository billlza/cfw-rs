public enum SystemExtensionInstallResult: Equatable, Sendable {
  case completed
  case awaitingApproval
  case requiresRestart
}

/// What a bounded wait for the person's approval of a submitted activation
/// request found.
public enum SystemExtensionApprovalWait: Equatable, Sendable {
  /// The request reached its terminal callback; the next `install()` reads
  /// its result.
  case resolved
  /// The request was still waiting for the person when the wait ended.
  case stillAwaiting
  /// No submitted request awaits a terminal callback.
  case noPendingRequest
}
