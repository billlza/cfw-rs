import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import OSLog

protocol ProxyEngineLeaseHolding: AnyObject {
  func release() throws
}

struct PreparedProxyOwnership {
  let lease: any ProxyEngineLeaseHolding
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
  /// Ends the ProxyAgent process after libbox could not close a runtime. Only
  /// the process ending releases what that close left open.
  let endProcess: @Sendable (LibboxInstanceUnclosable) -> Void

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
    endProcess: @escaping @Sendable (LibboxInstanceUnclosable) -> Void
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

private final class ProxyOperationCompletion: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable (Result<Void, ProxySessionLifecycleError>) -> Void)?

  init(
    _ handler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    self.handler = handler
  }

  func finish(_ result: Result<Void, ProxySessionLifecycleError>) {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    handler?(result)
  }
}

final class ProxySessionLifecycle: @unchecked Sendable {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac", category: "system-proxy-restoration")
  private final class Session {
    let id: UUID
    let configuration: ConfigurationDescriptor
    var engine: (any ProxyEngine)?
    var lease: (any ProxyEngineLeaseHolding)?
    var journal: ProxyOwnershipJournal?

    init(
      id: UUID,
      configuration: ConfigurationDescriptor,
      engine: (any ProxyEngine)?,
      lease: (any ProxyEngineLeaseHolding)?,
      journal: ProxyOwnershipJournal?
    ) {
      self.id = id
      self.configuration = configuration
      self.engine = engine
      self.lease = lease
      self.journal = journal
    }
  }

  private enum Lifecycle {
    case idle
    case starting(UUID)
    case active(UUID)
    case failed(UUID)
    /// libbox could not close the session's engine. Nothing in this process can
    /// release what that close left open, so the session stays referenced and
    /// every later start and stop fails with the same cause.
    case spent(LibboxInstanceUnclosable)
  }

  private let dependencies: ProxySessionDependencies
  private let stateQueue = DispatchQueue(label: "com.bill.clashformac.proxy-session-state")
  private var lifecycle = Lifecycle.idle
  private var session: Session?
  private var startCompletion: ProxyOperationCompletion?
  private var currentSnapshot = EngineSnapshot.off
  private var sequence: UInt64 = 0
  private var recoveryBlock: ProxySessionLifecycleError?
  private var lastStoppedConfiguration: ConfigurationDescriptor?
  private var lastFailedConfiguration: ConfigurationDescriptor?
  private var processEndScheduled = false

  init(dependencies: ProxySessionDependencies) {
    self.dependencies = dependencies
    recoverPersistedOwnership()
  }

  /// `deadline` is when the owner's libbox start must have returned; the owner
  /// fixed it when the start request arrived.
  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    deadline: EngineStartDeadline,
    completionHandler:
      @escaping @Sendable (
        Result<Void, ProxySessionLifecycleError>
      ) -> Void
  ) {
    let completion = ProxyOperationCompletion(completionHandler)
    stateQueue.async { [self] in
      beginStart(
        configuration: configuration,
        descriptor: descriptor,
        deadline: deadline,
        completion: completion)
    }
  }

  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler:
      @escaping @Sendable (
        Result<Void, ProxySessionLifecycleError>
      ) -> Void
  ) {
    let completion = ProxyOperationCompletion(completionHandler)
    stateQueue.async { [self] in
      performStop(expectedConfiguration: expectedConfiguration, completion: completion)
    }
  }

  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    stateQueue.async { [self] in
      if case .active(let sessionID) = lifecycle,
        let session,
        session.id == sessionID,
        let engine = session.engine
      {
        do {
          try engine.healthCheck()
        } catch {
          failOwnedSession(
            session,
            originalError: .engineStart(
              "Runtime health check failed: \(error.localizedDescription)"
            )
          )
        }
      }
      completionHandler(currentSnapshot)
    }
  }

  func testingSnapshot() -> EngineSnapshot {
    stateQueue.sync { currentSnapshot }
  }

  /// Restores the System Proxy settings this agent still owns but could not
  /// restore without the network preferences rights the user just granted: a
  /// launch whose recovery ran before the agent had them, a session whose
  /// cleanup failed after its engine stopped, or a spent session, which then
  /// ends the process. A session whose engine runs keeps its settings until it
  /// stops. The Host asks for the rights before every Off and before quitting,
  /// so either one completes a restore that failed.
  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    stateQueue.async { [self] in
      defer { completionHandler() }
      guard let session, session.journal != nil else { return }
      switch lifecycle {
      case .spent(let failure):
        let restoreErrors = restoreOwnedPreferences(session)
        if !restoreErrors.isEmpty {
          let codes = restoreErrors.map { $0.engineFailure.code }.joined(separator: ",")
          Self.logger.error(
            "System Proxy settings were not restored after authorization: \(codes, privacy: .public)"
          )
        }
        endProcessUnlessSettingsRemain(session, failure)
      case .failed(let sessionID) where sessionID == session.id && session.engine == nil:
        cleanUpSessionWithoutEngine(session)
      case .idle, .starting, .active, .failed:
        return
      }
    }
  }

  private func beginStart(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    deadline: EngineStartDeadline,
    completion: ProxyOperationCompletion
  ) {
    defer { configuration.erase() }
    guard descriptor.slot.isProxyAgent else {
      completion.finish(.failure(.invalidConfigurationSlot))
      return
    }
    if case .spent(let failure) = lifecycle {
      completion.finish(.failure(.engineUnclosable(failure)))
      return
    }
    if let recoveryBlock {
      completion.finish(.failure(recoveryBlock))
      return
    }
    guard session == nil else {
      completion.finish(.failure(.lifecycleConflict))
      return
    }

    let sessionID = UUID()
    lifecycle = .starting(sessionID)
    startCompletion = completion
    sequence &+= 1
    currentSnapshot = .proxyStarting(configuration: descriptor, sequence: sequence)
    lastStoppedConfiguration = nil
    lastFailedConfiguration = nil

    if descriptor.slot == .systemProxy {
      do {
        try dependencies.preferences.requireAuthorization()
      } catch SystemProxyPreferencesError.authorizationDenied {
        failStartWithoutOwnedSession(
          .authorizationRequired, configuration: descriptor, completion: completion)
        return
      } catch {
        failStartWithoutOwnedSession(
          .preferences(error.localizedDescription), configuration: descriptor,
          completion: completion)
        return
      }
    }
    let prepared: PreparedProxyOwnership
    do {
      prepared = try dependencies.prepareOwnership(descriptor)
    } catch {
      failStartWithoutOwnedSession(
        .engineLease(error.localizedDescription),
        configuration: descriptor,
        completion: completion
      )
      return
    }

    let startingSession = Session(
      id: sessionID,
      configuration: descriptor,
      engine: nil,
      lease: prepared.lease,
      journal: nil
    )
    session = startingSession
    do {
      try configuration.withErasingData { template in
        var resolvedConfiguration: Data
        do {
          resolvedConfiguration = try dependencies.resolveConfiguration(
            template,
            descriptor
          )
        } catch {
          throw ProxySessionLifecycleError.configuration(error.localizedDescription)
        }
        let sensitiveResolvedConfiguration = SensitiveDataBuffer(
          copying: resolvedConfiguration)
        resolvedConfiguration.resetBytes(
          in: resolvedConfiguration.startIndex..<resolvedConfiguration.endIndex
        )
        resolvedConfiguration.removeAll(keepingCapacity: false)
        try sensitiveResolvedConfiguration.withErasingData { runtimeConfiguration in
          let engine: any ProxyEngine
          do {
            engine = try dependencies.engineFactory.makeEngine(
              configuration: runtimeConfiguration
            )
          } catch {
            throw ProxySessionLifecycleError.engineCreation(error.localizedDescription)
          }
          startingSession.engine = engine
          do {
            try engine.start(configuration: runtimeConfiguration, deadline: deadline) {
              [weak self] event in
              self?.stateQueue.async { [weak self] in
                self?.handleEngineEvent(event, sessionID: sessionID)
              }
            }
          } catch let error as ProxyEngineError {
            if case .endpointConflict(let role, let port) = error {
              throw ProxySessionLifecycleError.endpointConflict(role: role, port: port)
            }
            if error == .startTimedOut {
              throw ProxySessionLifecycleError.engineStartTimedOut
            }
            throw ProxySessionLifecycleError.engineStart(error.localizedDescription)
          } catch {
            throw ProxySessionLifecycleError.engineStart(error.localizedDescription)
          }
        }
      }
      stateQueue.asyncAfter(deadline: .now() + dependencies.readinessTimeout) { [weak self] in
        self?.readinessTimedOut(sessionID: sessionID)
      }
    } catch let error as ProxySessionLifecycleError {
      failOwnedSession(startingSession, originalError: error)
    } catch {
      failOwnedSession(
        startingSession,
        originalError: .engineStart(String(describing: error))
      )
    }
  }

  private func handleEngineEvent(_ event: ProxyEngineEvent, sessionID: UUID) {
    if case .spent = lifecycle {
      return
    }
    guard let session, session.id == sessionID else {
      return
    }
    switch event {
    case .mixedListenerReady(let endpoint):
      guard case .starting(let activeSessionID) = lifecycle,
        activeSessionID == sessionID
      else {
        return
      }
      if session.configuration.slot == .localProxy {
        completeActivation(session)
      } else {
        activateSystemProxy(session: session, endpoint: endpoint)
      }
    case .failed(let failure):
      guard session.engine != nil else {
        return
      }
      handleEngineFailure(session: session, failure: failure)
    }
  }

  private func readinessTimedOut(sessionID: UUID) {
    guard let session, session.id == sessionID,
      case .starting(let activeSessionID) = lifecycle,
      activeSessionID == sessionID
    else {
      return
    }
    failOwnedSession(session, originalError: .listenerReadinessTimedOut)
  }

  private func activateSystemProxy(
    session: Session,
    endpoint: MixedListenerEndpoint
  ) {
    do {
      let preparedJournal: ProxyOwnershipJournal
      do {
        preparedJournal = try dependencies.preferences.prepareOwnership(
          configuration: session.configuration,
          endpoint: endpoint
        )
      } catch SystemProxyPreferencesError.existingProxyConfiguration {
        throw ProxySessionLifecycleError.existingSystemProxy
      } catch {
        throw ProxySessionLifecycleError.preferences(error.localizedDescription)
      }
      do {
        try dependencies.journalStore.save(preparedJournal)
      } catch {
        throw ProxySessionLifecycleError.ownershipJournal(error.localizedDescription)
      }
      session.journal = preparedJournal

      do {
        try dependencies.preferences.apply(preparedJournal)
      } catch SystemProxyPreferencesError.existingProxyConfiguration {
        throw ProxySessionLifecycleError.existingSystemProxy
      } catch {
        throw ProxySessionLifecycleError.preferences(error.localizedDescription)
      }
      let appliedJournal = try preparedJournal.markingApplied()
      do {
        try dependencies.journalStore.save(appliedJournal)
      } catch {
        throw ProxySessionLifecycleError.ownershipJournal(error.localizedDescription)
      }
      session.journal = appliedJournal

      completeActivation(session)
    } catch let error as ProxySessionLifecycleError {
      failOwnedSession(session, originalError: error)
    } catch {
      failOwnedSession(
        session,
        originalError: .preferences(String(describing: error))
      )
    }
  }

  private func completeActivation(_ session: Session) {
    lifecycle = .active(session.id)
    sequence &+= 1
    currentSnapshot = .proxyActive(configuration: session.configuration, sequence: sequence)
    let completion = startCompletion
    startCompletion = nil
    completion?.finish(.success(()))
  }

  private func handleEngineFailure(
    session: Session,
    failure: ProxyEngineFailure
  ) {
    session.engine = nil
    let originalError = ProxySessionLifecycleError.engineFailed(failure)
    var cleanupErrors = restoreOwnedPreferences(session)
    cleanupErrors.append(contentsOf: releaseLeaseIfFullyClean(session))
    finishOwnedSessionFailure(
      session,
      originalError: originalError,
      cleanupErrors: cleanupErrors
    )
  }

  private func failOwnedSession(
    _ session: Session,
    originalError: ProxySessionLifecycleError
  ) {
    var cleanupErrors = restoreOwnedPreferences(session)
    if let engine = session.engine {
      do {
        try engine.stop()
        session.engine = nil
      } catch {
        becomeSpent(
          error, session: session, stage: originalError, cleanupErrors: cleanupErrors,
          stopCompletion: nil)
        return
      }
    }
    cleanupErrors.append(contentsOf: releaseLeaseIfFullyClean(session))
    finishOwnedSessionFailure(
      session,
      originalError: originalError,
      cleanupErrors: cleanupErrors
    )
  }

  private func finishOwnedSessionFailure(
    _ failedSession: Session,
    originalError: ProxySessionLifecycleError,
    cleanupErrors: [ProxySessionLifecycleError]
  ) {
    let terminalError = combinedError(original: originalError, cleanup: cleanupErrors)
    let cleanupCodes = cleanupErrors.map { $0.engineFailure.code }.joined(separator: ",")
    Self.logger.error(
      "System Proxy start failed: stage=\(originalError.engineFailure.code, privacy: .public) cleanup=\(cleanupCodes, privacy: .public)"
    )
    if failedSession.engine == nil, failedSession.journal == nil, failedSession.lease == nil {
      session = nil
      lifecycle = .idle
    } else {
      lifecycle = .failed(failedSession.id)
    }
    lastFailedConfiguration = failedSession.configuration
    sequence &+= 1
    currentSnapshot = .proxyFailed(
      terminalError.engineFailure,
      configuration: failedSession.configuration,
      sequence: sequence
    )
    let completion = startCompletion
    startCompletion = nil
    completion?.finish(.failure(terminalError))
  }

  private func performStop(
    expectedConfiguration: ConfigurationDescriptor,
    completion: ProxyOperationCompletion
  ) {
    guard expectedConfiguration.slot.isProxyAgent else {
      completion.finish(.failure(.invalidConfigurationSlot))
      return
    }
    if case .spent(let failure) = lifecycle {
      stopWhileSpent(failure, completion: completion)
      return
    }
    guard let session else {
      if expectedConfiguration == lastStoppedConfiguration
        || expectedConfiguration == lastFailedConfiguration
      {
        sequence &+= 1
        currentSnapshot = .off(sequence: sequence)
        completion.finish(.success(()))
      } else {
        completion.finish(.failure(.stopWithoutSession))
      }
      return
    }
    guard session.configuration == expectedConfiguration else {
      completion.finish(.failure(.staleStopRequest))
      return
    }

    lifecycle = .failed(session.id)
    sequence &+= 1
    currentSnapshot = .proxyStopping(
      configuration: session.configuration,
      sequence: sequence
    )
    let pendingStart = startCompletion
    startCompletion = nil
    pendingStart?.finish(.failure(.startupCancelled))

    var cleanupErrors = acquireCleanupLeaseIfNeeded(session)
    if cleanupErrors.isEmpty {
      cleanupErrors.append(contentsOf: restoreOwnedPreferences(session))
    }
    if let engine = session.engine {
      do {
        try engine.stop()
        session.engine = nil
      } catch {
        becomeSpent(
          error, session: session, stage: nil, cleanupErrors: cleanupErrors,
          stopCompletion: completion)
        return
      }
    }
    cleanupErrors.append(contentsOf: releaseLeaseIfFullyClean(session))

    guard
      cleanupErrors.isEmpty,
      session.engine == nil,
      session.journal == nil,
      session.lease == nil
    else {
      let terminalError = combinedError(
        original: cleanupErrors.first ?? .recoveryBlocked("Proxy cleanup remains incomplete."),
        cleanup: Array(cleanupErrors.dropFirst())
      )
      lifecycle = .failed(session.id)
      lastFailedConfiguration = session.configuration
      sequence &+= 1
      currentSnapshot = .proxyFailed(
        terminalError.engineFailure,
        configuration: session.configuration,
        sequence: sequence
      )
      completion.finish(.failure(terminalError))
      return
    }

    self.session = nil
    lifecycle = .idle
    lastStoppedConfiguration = session.configuration
    lastFailedConfiguration = nil
    sequence &+= 1
    currentSnapshot = .off(sequence: sequence)
    completion.finish(.success(()))
  }

  /// libbox could not close the session's engine. The session stays, with its
  /// engine and lease, so nothing claims that the runtime ended; the pending
  /// completions fail with the cause, and the process ends once no owned
  /// system proxy setting still needs it.
  private func becomeSpent(
    _ failure: LibboxInstanceUnclosable,
    session: Session,
    stage: ProxySessionLifecycleError?,
    cleanupErrors: [ProxySessionLifecycleError],
    stopCompletion: ProxyOperationCompletion?
  ) {
    lifecycle = .spent(failure)
    let error = ProxySessionLifecycleError.engineUnclosable(failure)
    let stageCode = stage?.engineFailure.code ?? "stop"
    let cleanupCodes = cleanupErrors.map { $0.engineFailure.code }.joined(separator: ",")
    Self.logger.fault(
      "System Proxy runtime could not be closed: stage=\(stageCode, privacy: .public) cleanup=\(cleanupCodes, privacy: .public)"
    )
    lastFailedConfiguration = session.configuration
    sequence &+= 1
    currentSnapshot = .proxyFailed(
      error.engineFailure,
      configuration: session.configuration,
      sequence: sequence
    )
    let pendingStart = startCompletion
    startCompletion = nil
    pendingStart?.finish(.failure(error))
    stopCompletion?.finish(.failure(error))
    endProcessUnlessSettingsRemain(session, failure)
  }

  /// A stop cannot reach the engine any more, but owned system proxy settings
  /// that are still applied can be restored with the authorization this
  /// process holds; a relaunched ProxyAgent would have to ask for it again.
  private func stopWhileSpent(
    _ failure: LibboxInstanceUnclosable,
    completion: ProxyOperationCompletion
  ) {
    var restoreErrors: [ProxySessionLifecycleError] = []
    if let session, session.journal != nil {
      restoreErrors = restoreOwnedPreferences(session)
    }
    if !restoreErrors.isEmpty {
      let codes = restoreErrors.map { $0.engineFailure.code }.joined(separator: ",")
      Self.logger.error(
        "System Proxy settings were not restored after its runtime could not be closed: \(codes, privacy: .public)"
      )
    }
    completion.finish(.failure(.engineUnclosable(failure)))
    if let session {
      endProcessUnlessSettingsRemain(session, failure)
    }
  }

  /// Ends the process once its journal is gone. The end runs after every
  /// operation already queued, so each reply this failure produced has been
  /// handed to its transport first.
  private func endProcessUnlessSettingsRemain(
    _ session: Session,
    _ failure: LibboxInstanceUnclosable
  ) {
    guard session.journal == nil, !processEndScheduled else {
      return
    }
    processEndScheduled = true
    let endProcess = dependencies.endProcess
    stateQueue.async {
      endProcess(failure)
    }
  }

  private func restoreOwnedPreferences(
    _ session: Session
  ) -> [ProxySessionLifecycleError] {
    guard let journal = session.journal else {
      return []
    }
    do {
      let result = try dependencies.preferences.restore(journal)
      guard result.isComplete else {
        return [.ownershipConflict(result.conflicts)]
      }
      if !result.preservedExternalChanges.isEmpty {
        Self.logger.notice(
          "Preserving \(result.preservedExternalChanges.count, privacy: .public) externally changed proxy fields after verifying that the listener is no longer selected."
        )
      }
      do {
        try dependencies.journalStore.remove()
        session.journal = nil
        return []
      } catch {
        return [.ownershipJournal(error.localizedDescription)]
      }
    } catch {
      return [.preferences(error.localizedDescription)]
    }
  }

  private func acquireCleanupLeaseIfNeeded(
    _ session: Session
  ) -> [ProxySessionLifecycleError] {
    guard session.journal != nil, session.lease == nil else {
      return []
    }
    do {
      session.lease = try dependencies.recoverCleanupLease(session.configuration)
      return []
    } catch {
      return [
        .recoveryBlocked(
          "Cannot acquire the shared engine lease for proxy cleanup: \(error.localizedDescription)"
        )
      ]
    }
  }

  private func releaseLeaseIfFullyClean(
    _ session: Session
  ) -> [ProxySessionLifecycleError] {
    guard session.engine == nil, session.journal == nil else {
      return []
    }
    guard let lease = session.lease else {
      return []
    }
    do {
      try lease.release()
      session.lease = nil
      return []
    } catch {
      return [.engineLease(error.localizedDescription)]
    }
  }

  private func recoverPersistedOwnership() {
    do {
      guard let journal = try dependencies.journalStore.load() else {
        return
      }
      let recoverySession = Session(
        id: UUID(),
        configuration: journal.configuration,
        engine: nil,
        lease: nil,
        journal: journal
      )
      session = recoverySession
      cleanUpSessionWithoutEngine(recoverySession)
    } catch {
      let terminalError = ProxySessionLifecycleError.recoveryBlocked(error.localizedDescription)
      recoveryBlock = terminalError
      sequence &+= 1
      currentSnapshot = .proxyFailed(
        terminalError.engineFailure,
        configuration: nil,
        sequence: sequence
      )
    }
  }

  /// Restores what `owned`, a session with no running engine, still owns and
  /// releases its lease, then publishes Off, or the failure that keeps it.
  private func cleanUpSessionWithoutEngine(_ owned: Session) {
    var cleanupErrors = acquireCleanupLeaseIfNeeded(owned)
    if cleanupErrors.isEmpty {
      cleanupErrors.append(contentsOf: restoreOwnedPreferences(owned))
    }
    cleanupErrors.append(contentsOf: releaseLeaseIfFullyClean(owned))
    if cleanupErrors.isEmpty, owned.journal == nil, owned.lease == nil {
      session = nil
      lifecycle = .idle
      lastStoppedConfiguration = owned.configuration
      lastFailedConfiguration = nil
      sequence &+= 1
      currentSnapshot = .off(sequence: sequence)
    } else {
      let terminalError = combinedError(
        original: cleanupErrors.first ?? .recoveryBlocked("Unknown ownership recovery error."),
        cleanup: Array(cleanupErrors.dropFirst())
      )
      lifecycle = .failed(owned.id)
      recoveryBlock = nil
      lastFailedConfiguration = owned.configuration
      sequence &+= 1
      currentSnapshot = .proxyFailed(
        terminalError.engineFailure,
        configuration: owned.configuration,
        sequence: sequence
      )
    }
  }

  private func failStartWithoutOwnedSession(
    _ error: ProxySessionLifecycleError,
    configuration: ConfigurationDescriptor,
    completion: ProxyOperationCompletion
  ) {
    lifecycle = .idle
    startCompletion = nil
    lastFailedConfiguration = configuration
    sequence &+= 1
    currentSnapshot = .proxyFailed(
      error.engineFailure,
      configuration: configuration,
      sequence: sequence
    )
    completion.finish(.failure(error))
  }

  private func combinedError(
    original: ProxySessionLifecycleError,
    cleanup: [ProxySessionLifecycleError]
  ) -> ProxySessionLifecycleError {
    guard !cleanup.isEmpty else {
      return original
    }
    return .cleanupFailed(
      original: String(describing: original),
      cleanup: cleanup.map { String(describing: $0) }
    )
  }
}
