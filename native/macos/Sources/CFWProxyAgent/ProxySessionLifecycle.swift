import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

protocol ProxyEngineLeaseHolding: AnyObject {
  func release() throws
  func markStopFailed() throws
}

struct PreparedProxyOwnership {
  let lease: any ProxyEngineLeaseHolding
}

enum ProxySessionLifecycleError: Error, Equatable, Sendable {
  case invalidConfigurationSlot
  case lifecycleConflict
  case startupCancelled
  case staleStopRequest
  case recoveryBlocked(String)
  case engineLease(String)
  case configuration(String)
  case engineCreation(String)
  case engineStart(String)
  case listenerReadinessTimedOut
  case engineStop(String)
  case engineFailed(ProxyEngineFailure)
  case preferences(String)
  case ownershipJournal(String)
  case ownershipConflict([ProxyOwnershipConflict])
  case cleanupFailed(original: String, cleanup: [String])

  var engineFailure: EngineFailure {
    let code: String
    switch self {
    case .invalidConfigurationSlot: code = "invalid-configuration-slot"
    case .lifecycleConflict: code = "proxy-lifecycle-conflict"
    case .startupCancelled: code = "proxy-startup-cancelled"
    case .staleStopRequest: code = "stale-stop-request"
    case .recoveryBlocked: code = "proxy-recovery-blocked"
    case .engineLease: code = "proxy-engine-lease-failed"
    case .configuration: code = "proxy-configuration-failed"
    case .engineCreation: code = "proxy-engine-creation-failed"
    case .engineStart: code = "proxy-engine-start-failed"
    case .listenerReadinessTimedOut: code = "proxy-listener-readiness-timeout"
    case .engineStop: code = "proxy-engine-stop-failed"
    case .engineFailed: code = "proxy-engine-crashed"
    case .preferences: code = "system-proxy-preferences-failed"
    case .ownershipJournal: code = "proxy-ownership-journal-failed"
    case .ownershipConflict: code = "system-proxy-ownership-conflict"
    case .cleanupFailed: code = "proxy-cleanup-failed"
    }
    return EngineFailure(
      code: code,
      message: safeMessage,
      isRetryable: false
    )
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
    case .recoveryBlocked:
      "System Proxy recovery is blocked until owned settings can be restored safely."
    case .engineLease:
      "The machine-wide engine lease operation failed."
    case .configuration:
      "System Proxy configuration validation failed."
    case .engineCreation:
      "System Proxy runtime creation failed."
    case .engineStart:
      "System Proxy runtime startup failed."
    case .listenerReadinessTimedOut:
      "System Proxy listener did not become ready before the bounded timeout."
    case .engineStop:
      "System Proxy runtime stop failed."
    case .engineFailed:
      "System Proxy runtime exited unexpectedly."
    case .preferences:
      "System proxy preference transaction failed."
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
    readinessTimeout: TimeInterval
  ) {
    self.prepareOwnership = prepareOwnership
    self.resolveConfiguration = resolveConfiguration
    self.recoverCleanupLease = recoverCleanupLease
    self.engineFactory = engineFactory
    self.preferences = preferences
    self.journalStore = journalStore
    self.readinessTimeout = readinessTimeout
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

  init(dependencies: ProxySessionDependencies) {
    self.dependencies = dependencies
    recoverPersistedOwnership()
  }

  func start(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
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

  private func beginStart(
    configuration: SensitiveDataBuffer,
    descriptor: ConfigurationDescriptor,
    completion: ProxyOperationCompletion
  ) {
    defer { configuration.erase() }
    guard descriptor.slot == .systemProxy else {
      completion.finish(.failure(.invalidConfigurationSlot))
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
            try engine.start(configuration: runtimeConfiguration) { [weak self] event in
              self?.stateQueue.async { [weak self] in
                self?.handleEngineEvent(event, sessionID: sessionID)
              }
            }
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
      activateSystemProxy(session: session, endpoint: endpoint)
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

      lifecycle = .active(session.id)
      sequence &+= 1
      currentSnapshot = .proxyActive(
        configuration: session.configuration,
        sequence: sequence
      )
      let completion = startCompletion
      startCompletion = nil
      completion?.finish(.success(()))
    } catch let error as ProxySessionLifecycleError {
      failOwnedSession(session, originalError: error)
    } catch {
      failOwnedSession(
        session,
        originalError: .preferences(String(describing: error))
      )
    }
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
        cleanupErrors.append(.engineStop(error.localizedDescription))
        do {
          try session.lease?.markStopFailed()
        } catch {
          cleanupErrors.append(.engineLease(error.localizedDescription))
        }
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
    guard expectedConfiguration.slot == .systemProxy else {
      completion.finish(.failure(.invalidConfigurationSlot))
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
        completion.finish(.failure(.staleStopRequest))
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
        cleanupErrors.append(.engineStop(error.localizedDescription))
        do {
          try session.lease?.markStopFailed()
        } catch {
          cleanupErrors.append(.engineLease(error.localizedDescription))
        }
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
      var cleanupErrors = acquireCleanupLeaseIfNeeded(recoverySession)
      if cleanupErrors.isEmpty {
        cleanupErrors.append(contentsOf: restoreOwnedPreferences(recoverySession))
      }
      cleanupErrors.append(contentsOf: releaseLeaseIfFullyClean(recoverySession))
      if cleanupErrors.isEmpty, recoverySession.journal == nil, recoverySession.lease == nil {
        session = nil
        lifecycle = .idle
        lastStoppedConfiguration = journal.configuration
        sequence &+= 1
        currentSnapshot = .off(sequence: sequence)
      } else {
        let terminalError = combinedError(
          original: cleanupErrors.first ?? .recoveryBlocked("Unknown ownership recovery error."),
          cleanup: Array(cleanupErrors.dropFirst())
        )
        lifecycle = .failed(recoverySession.id)
        recoveryBlock = nil
        lastFailedConfiguration = journal.configuration
        sequence &+= 1
        currentSnapshot = .proxyFailed(
          terminalError.engineFailure,
          configuration: journal.configuration,
          sequence: sequence
        )
      }
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
