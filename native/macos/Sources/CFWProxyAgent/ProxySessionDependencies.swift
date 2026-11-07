import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation

protocol ProxyEngineLeaseHolding: AnyObject {
  func release() throws
}

struct PreparedProxyOwnership {
  let lease: any ProxyEngineLeaseHolding
}

/// Why the ProxyAgent ends its own process. launchd starts a fresh agent for
/// the next request.
enum ProxyAgentEndReason: Equatable, Sendable {
  /// libbox could not close a runtime: only the process ending releases what
  /// that close left open.
  case engineUnclosable(LibboxInstanceUnclosable)
  /// The Authority quarantined a stop this agent had finished locally. It
  /// releases the lease once this process ended.
  case quarantinedStop
  /// A configuration check or profile probe left in libbox what this process
  /// cannot release; the agent retired and ended once it was idle.
  case retired(LibboxInstanceUnclosable)
}

enum ProxySessionLifecycleError: Error, Equatable, Sendable {
  case invalidConfigurationSlot
  case lifecycleConflict
  case startupCancelled
  /// The stop names a generation other than the session this agent holds.
  case staleStopRequest
  /// This agent holds no session and has no record of the stop's generation.
  case stopWithoutSession
  case recoveryBlocked(String)
  case authorizationRequired
  case engineLease(String)
  case authority(AuthorityErrorCode)
  case configuration(String)
  case engineCreation(String)
  case engineStart(String)
  case engineStartTimedOut
  case endpointConflict(role: LibboxRuntimeEndpointRole, port: UInt16)
  case listenerReadinessTimedOut
  /// libbox could not close the runtime, so the ProxyAgent is spent.
  case engineUnclosable(LibboxInstanceUnclosable)
  case engineFailed(ProxyEngineFailure)
  case preferences(String)
  case existingSystemProxy
  case ownershipJournal(String)
  case ownershipConflict([ProxyOwnershipConflict])
  case cleanupFailed(original: String, cleanup: [String])
  /// The agent is spent or retired, so it takes no new start.
  case agentEnding

  var engineFailure: EngineFailure {
    EngineFailure(failure, message: safeMessage)
  }

  var failure: ProxyAgentFailure {
    switch self {
    case .invalidConfigurationSlot: .agent(.invalidConfigurationSlot)
    case .lifecycleConflict: .agent(.lifecycleConflict)
    case .startupCancelled: .agent(.startupCancelled)
    case .staleStopRequest: .agent(.staleStopRequest)
    case .stopWithoutSession: .agent(.stopWithoutSession)
    case .recoveryBlocked: .agent(.recoveryBlocked)
    case .authorizationRequired: .agent(.authorizationRequired)
    case .engineLease: .agent(.engineLeaseFailed)
    case .authority(let failure): .authority(failure)
    case .configuration: .agent(.configurationFailed)
    case .engineCreation: .agent(.engineCreationFailed)
    case .engineStart: .agent(.engineStartFailed)
    case .engineStartTimedOut: .agent(.engineStartTimedOut)
    case .endpointConflict(let role, _):
      role == .mixed ? .agent(.mixedEndpointInUse) : .agent(.controllerEndpointInUse)
    case .listenerReadinessTimedOut: .agent(.listenerReadinessTimedOut)
    case .engineUnclosable: .agent(.engineUnclosable)
    case .engineFailed: .agent(.engineCrashed)
    case .preferences: .agent(.preferencesFailed)
    case .existingSystemProxy: .agent(.existingSystemProxy)
    case .ownershipJournal: .agent(.ownershipJournalFailed)
    case .ownershipConflict: .agent(.ownershipConflict)
    case .cleanupFailed: .agent(.cleanupFailed)
    case .agentEnding: .agent(.agentEnding)
    }
  }

  private var safeMessage: String {
    switch self {
    case .invalidConfigurationSlot:
      "System Proxy received a configuration for another engine slot."
    case .lifecycleConflict:
      "System Proxy already owns a starting, active, or failed runtime."
    case .startupCancelled:
      "System Proxy startup was cancelled."
    case .staleStopRequest:
      "System Proxy stop does not match the active generation."
    case .stopWithoutSession:
      "System Proxy holds no session for the stopped generation."
    case .recoveryBlocked:
      "System Proxy recovery is blocked until owned settings can be restored safely."
    case .authorizationRequired:
      "Approve macOS network authorization before starting System Proxy."
    case .engineLease:
      "The machine-wide engine lease operation failed."
    case .authority(let failure):
      failure.stableMessage
    case .configuration:
      "System Proxy configuration validation failed."
    case .engineCreation:
      "System Proxy runtime creation failed."
    case .engineStart:
      "System Proxy runtime startup failed."
    case .engineStartTimedOut:
      "System Proxy runtime startup did not finish in time and was interrupted."
    case .endpointConflict(let role, let port):
      "The System Proxy \(role.rawValue) endpoint could not bind to port \(port)."
    case .listenerReadinessTimedOut:
      "System Proxy listener did not become ready before the bounded timeout."
    case .engineUnclosable:
      "System Proxy could not close its runtime."
    case .engineFailed:
      "System Proxy runtime exited unexpectedly."
    case .preferences:
      "System proxy preference transaction failed."
    case .existingSystemProxy:
      "Another system proxy is enabled. Existing proxy settings were not changed."
    case .ownershipJournal:
      "System proxy ownership journal operation failed."
    case .ownershipConflict:
      "System proxy settings changed externally and were preserved."
    case .cleanupFailed:
      "System Proxy cleanup did not reach a proven Off state."
    case .agentEnding:
      "The proxy agent is ending; the next one takes the request."
    }
  }
}

struct ProxySessionDependencies: @unchecked Sendable {
  let prepareOwnership: (ConfigurationDescriptor) throws -> PreparedProxyOwnership
  let resolveConfiguration: (Data, ConfigurationDescriptor) throws -> Data
  let recoverCleanupLease: (ConfigurationDescriptor) throws -> any ProxyEngineLeaseHolding
  let engineFactory: any ProxyEngineFactory
  let preferences: any SystemProxyPreferences
  let journalStore: any ProxyOwnershipJournalStoring
  let readinessTimeout: TimeInterval
  /// Ends the ProxyAgent process for one of `ProxyAgentEndReason`'s reasons.
  let endProcess: @Sendable (ProxyAgentEndReason) -> Void

  init(
    prepareOwnership: @escaping (ConfigurationDescriptor) throws -> PreparedProxyOwnership,
    resolveConfiguration: @escaping (Data, ConfigurationDescriptor) throws -> Data = {
      configuration,
      _ in configuration
    },
    recoverCleanupLease: @escaping (ConfigurationDescriptor) throws -> any ProxyEngineLeaseHolding,
    engineFactory: any ProxyEngineFactory,
    preferences: any SystemProxyPreferences,
    journalStore: any ProxyOwnershipJournalStoring,
    readinessTimeout: TimeInterval,
    endProcess: @escaping @Sendable (ProxyAgentEndReason) -> Void
  ) {
    self.prepareOwnership = prepareOwnership
    self.resolveConfiguration = resolveConfiguration
    self.recoverCleanupLease = recoverCleanupLease
    self.engineFactory = engineFactory
    self.preferences = preferences
    self.journalStore = journalStore
    self.readinessTimeout = readinessTimeout
    self.endProcess = endProcess
  }
}
