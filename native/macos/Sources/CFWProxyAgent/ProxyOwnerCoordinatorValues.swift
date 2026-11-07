import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension ProxySystemProxyOwnerCoordinator {
  typealias StopCompletion =
    @Sendable (
      Result<Void, ProxySessionLifecycleError>
    ) -> Void

  struct ActiveContext {
    let operation: OperationContext
    let leaseID: AuthorityIdentifier
    let descriptor: ConfigurationDescriptor
  }

  struct StopFlight {
    let id: UUID
    let context: ActiveContext?
    let descriptor: ConfigurationDescriptor
    var completions: [StopCompletion]
  }

  enum PendingCancellation: Equatable {
    case explicitStop
    case authorityRevocation
  }

  struct PendingStart {
    let id: UUID
    let descriptor: ConfigurationDescriptor
    let configuration: SensitiveDataBuffer
    let deadline: EngineStartDeadline
    var cancellation: PendingCancellation?
    var stopCompletions: [StopCompletion] = []
  }

  static func combinedFailure(
    _ original: ProxySessionLifecycleError,
    _ cleanup: ProxySessionLifecycleError
  ) -> ProxySessionLifecycleError {
    .cleanupFailed(
      original: String(describing: original),
      cleanup: [String(describing: cleanup)])
  }

  static func authorityFailure(_ error: Error) -> ProxySessionLifecycleError {
    if let domain = error as? AuthorityDomainError {
      return .authority(domain.code)
    }
    if error is SystemProxyPreferencesError {
      return .preferences(error.localizedDescription)
    }
    return .engineLease(GlobalAuthorityGateError.stableMessage)
  }

  static func authorityMessage(_ error: Error) -> String {
    if let domain = error as? AuthorityDomainError {
      return domain.code.stableMessage
    }
    return GlobalAuthorityGateError.stableMessage
  }
}
