import CFWSharedProtocol

struct NativeAuthorityStopContext: Equatable, Sendable {
  let operation: OperationContext
  let leaseID: AuthorityIdentifier
}

enum NativeStopOwner: Equatable, Sendable {
  case localProxy
  case systemProxy
  case tunnel

  init(mode: AuthorityMode) {
    switch mode {
    case .localProxy: self = .localProxy
    case .systemProxy: self = .systemProxy
    case .tunnel: self = .tunnel
    }
  }

  var engineMode: EngineMode {
    switch self {
    case .localProxy: .localProxy
    case .systemProxy: .systemProxy
    case .tunnel: .tunnel
    }
  }
}

/// Exact, non-secret Host recovery view of a durable Authority lease that is
/// already stopping. A restarted Host has lost its in-process `pendingStop`, but
/// the Authority still retains the complete operation and lease identity needed
/// to finish the same stop transaction without reconstructing it from an
/// ambiguous owner Off snapshot.
struct NativeRecoveredStop: Equatable, Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let authorityContext: NativeAuthorityStopContext

  init(operation: OperationContext, leaseID: AuthorityIdentifier) throws {
    owner = NativeStopOwner(mode: operation.mode)
    commandContext = try EngineCommandContext(
      installationID: operation.root.installationID.rawValue,
      configEpoch: operation.root.epoch,
      generation: operation.root.generation)
    authorityContext = NativeAuthorityStopContext(
      operation: operation,
      leaseID: leaseID)
  }
}

/// Where the Global Authority stands in one native stop.
enum NativeStopAuthorityPhase: Equatable, Sendable {
  /// The Authority has not been asked to stop the lease yet.
  case unordered
  /// The Authority stops the lease the context names.
  case ordered(NativeAuthorityStopContext)
  /// The Authority committed Off for that lease.
  case completed(NativeAuthorityStopContext)
  /// The Authority holds no lease to stop: it is Recovering, after a restart or
  /// once the stop's quarantined owner ended, it already reached Off at this
  /// stop's generation, or it passed that generation. The stop ends with the
  /// Host's own Off proof: the reconciliation a restart needs, at this stop's
  /// generation, or, once the Authority passed it, the stop's own owner Off.
  case released
}

/// Host-side durable-within-process stop transaction. The exact descriptor and
/// Authority context are retained across command failures so a retry continues the
/// unfinished barrier instead of requiring an owner that may already be Off.
struct NativeStopTransaction: Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let descriptor: ConfigurationDescriptor
  var authority: NativeStopAuthorityPhase
  var ownerStopped: Bool
  var preferenceCompensated: Bool

  init(
    owner: NativeStopOwner,
    commandContext: EngineCommandContext,
    descriptor: ConfigurationDescriptor
  ) {
    self.owner = owner
    self.commandContext = commandContext
    self.descriptor = descriptor
    authority = .unordered
    ownerStopped = false
    preferenceCompensated = false
  }
}

struct NativeStartCleanupReceipt: Equatable, Sendable {
  let owner: NativeStopOwner
  let commandContext: EngineCommandContext
  let descriptor: ConfigurationDescriptor
}

/// What the Global Authority's state says of one stop's generation.
enum NativeStopResolution: Equatable, Sendable {
  /// Off, with the replay cursor at the stop's generation: the stop's lease
  /// ended with this Off.
  case completed
  /// The replay cursor of the same installation passed the stop's generation.
  /// The cursor advances only through a start prepared from a proven Off, so
  /// the stop's lease ended through a proven Off, and no lease of that
  /// generation can exist again.
  case superseded
  /// Neither: the Authority's state says nothing final of the stop's lease.
  case unresolved
}
