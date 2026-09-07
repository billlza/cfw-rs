import CFWCredentialTransport
import CFWPacketTransport
import CFWSharedProtocol
import Foundation

protocol PacketPumping: AnyObject {
  func takeEngineFileDescriptor() throws -> Int32
  func start() throws
  func stop()
}

extension PacketPump: PacketPumping {}

protocol EngineLeaseHolding: AnyObject {
  func release() throws
  func markStopFailed() throws
}

struct PreparedTunnelConfiguration {
  let descriptor: ConfigurationDescriptor
  let configuration: Data
  let lease: any EngineLeaseHolding
}

/// Evidence produced only after every provider-owned tunnel resource has crossed
/// its synchronous teardown barrier. The initializer is file-private so callers
/// cannot manufacture a successful stop without going through the lifecycle.
struct PacketTunnelStopProof: Equatable, Sendable {
  let libboxStopped: Bool
  let transportClosed: Bool
  let osRestored: Bool

  fileprivate init() {
    libboxStopped = true
    transportClosed = true
    // The provider never owns persistent system-proxy preferences. Once its
    // engine, packet transport, staged configuration, and lease are gone, no
    // provider-owned OS configuration remains for it to restore.
    osRestored = true
  }
}

enum PacketTunnelStopError: Error, Equatable, Sendable {
  case localRuntime(PacketTunnelProviderError)
  case authorityAttestation(PacketTunnelProviderError)

  var providerError: PacketTunnelProviderError {
    switch self {
    case .localRuntime(let error), .authorityAttestation(let error):
      return error
    }
  }
}

typealias PacketTunnelStopResult = Result<PacketTunnelStopProof, PacketTunnelStopError>

struct PacketTunnelSessionDependencies: @unchecked Sendable {
  let prepareConfiguration:
    (ConfigurationDescriptor, Data, CredentialMaterial) throws -> PreparedTunnelConfiguration
  let resolveConfiguration: (Data, ConfigurationDescriptor, CredentialMaterial) throws -> Data
  let makePump:
    (ConfigurationDescriptor, @escaping PacketPump.FailureHandler) throws -> any PacketPumping
  let applyNetworkSettings: (ConfigurationDescriptor, @escaping @Sendable (Error?) -> Void) -> Void
  let recordAcceptance: (ConfigurationDescriptor) throws -> Void

  init(
    prepareConfiguration:
      @escaping (ConfigurationDescriptor, Data, CredentialMaterial) throws
      -> PreparedTunnelConfiguration,
    resolveConfiguration:
      @escaping (Data, ConfigurationDescriptor, CredentialMaterial) throws -> Data = {
        configuration,
        _,
        _ in configuration
      },
    makePump:
      @escaping (
        ConfigurationDescriptor, @escaping PacketPump.FailureHandler
      ) throws -> any PacketPumping,
    applyNetworkSettings:
      @escaping (ConfigurationDescriptor, @escaping @Sendable (Error?) -> Void) -> Void,
    recordAcceptance: @escaping (ConfigurationDescriptor) throws -> Void = { _ in }
  ) {
    self.prepareConfiguration = prepareConfiguration
    self.resolveConfiguration = resolveConfiguration
    self.makePump = makePump
    self.applyNetworkSettings = applyNetworkSettings
    self.recordAcceptance = recordAcceptance
  }

}

private final class ProviderStartCompletion: @unchecked Sendable {
  private let lock = NSLock()
  private var handler: (@Sendable (Error?) -> Void)?

  init(_ handler: @escaping @Sendable (Error?) -> Void) {
    self.handler = handler
  }

  func finish(_ error: Error?) {
    lock.lock()
    let handler = handler
    self.handler = nil
    lock.unlock()
    handler?(error)
  }
}

final class PacketTunnelSessionLifecycle: @unchecked Sendable {
  typealias CancelTunnel = @Sendable (PacketTunnelProviderError) -> Void

  private let engineFactory: any PacketEngineFactory
  private let dependencies: PacketTunnelSessionDependencies
  private let cancelTunnel: CancelTunnel
  private let stateQueue = DispatchQueue(label: "com.bill.clashformac.packet-tunnel-state")
  private var engine: (any PacketEngine)?
  private var engineStarted = false
  private var configuration: SensitiveDataBuffer?
  private var engineLease: (any EngineLeaseHolding)?
  private var packetPump: (any PacketPumping)?
  private var lifecycle = Lifecycle.idle
  private var startCompletion: ProviderStartCompletion?
  private var currentSnapshot = EngineSnapshot.off
  private var sequence: UInt64 = 0

  private enum Lifecycle {
    case idle
    case starting(UUID)
    case active(UUID)
    case failedOwned(UUID)

    var sessionID: UUID? {
      switch self {
      case .starting(let sessionID), .active(let sessionID), .failedOwned(let sessionID):
        return sessionID
      case .idle:
        return nil
      }
    }
  }

  init(
    engineFactory: any PacketEngineFactory,
    dependencies: PacketTunnelSessionDependencies,
    cancelTunnel: @escaping CancelTunnel
  ) {
    self.engineFactory = engineFactory
    self.dependencies = dependencies
    self.cancelTunnel = cancelTunnel
  }

  func start(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialMaterial: CredentialMaterial = .empty,
    completionHandler: @escaping @Sendable (Error?) -> Void
  ) {
    let completion = ProviderStartCompletion(completionHandler)
    stateQueue.async { [self] in
      beginStart(
        descriptor: descriptor,
        configuration: configuration,
        credentialMaterial: credentialMaterial,
        completion: completion
      )
    }
  }

  func stop(completionHandler: @escaping @Sendable (PacketTunnelStopResult) -> Void) {
    stateQueue.async { [self] in
      performStop(completionHandler: completionHandler)
    }
  }

  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    stateQueue.async { [self] in
      if case .active(let sessionID) = lifecycle, let engine {
        do {
          try engine.healthCheck()
        } catch {
          failSession(
            sessionID,
            error: .engineStart("Runtime health check failed: \(error.localizedDescription)"),
            cancelTunnel: true
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
    descriptor requestedDescriptor: ConfigurationDescriptor,
    configuration configurationTemplate: Data,
    credentialMaterial initialCredentialMaterial: CredentialMaterial,
    completion: ProviderStartCompletion
  ) {
    var credentialMaterial = initialCredentialMaterial
    defer { credentialMaterial.erase() }
    guard case .idle = lifecycle else {
      completion.finish(PacketTunnelProviderError.lifecycleConflict)
      return
    }

    let sessionID = UUID()
    lifecycle = .starting(sessionID)
    startCompletion = completion

    var acquiredLease: (any EngineLeaseHolding)?
    var preparedPump: (any PacketPumping)?
    do {
      let prepared: PreparedTunnelConfiguration
      do {
        prepared = try dependencies.prepareConfiguration(
          requestedDescriptor,
          configurationTemplate,
          credentialMaterial
        )
      } catch {
        throw PacketTunnelProviderError.configuration(error.localizedDescription)
      }
      let descriptor = prepared.descriptor
      guard descriptor.slot == .tunnel else {
        throw PacketTunnelProviderError.invalidConfigurationSlot
      }
      guard descriptor == requestedDescriptor else {
        throw PacketTunnelProviderError.malformedProviderConfiguration
      }
      acquiredLease = prepared.lease
      var resolvedConfiguration: Data
      do {
        resolvedConfiguration = try dependencies.resolveConfiguration(
          prepared.configuration,
          descriptor,
          credentialMaterial
        )
      } catch {
        throw PacketTunnelProviderError.configuration(error.localizedDescription)
      }
      let sensitiveConfiguration = SensitiveDataBuffer(copying: resolvedConfiguration)
      resolvedConfiguration.resetBytes(
        in: resolvedConfiguration.startIndex..<resolvedConfiguration.endIndex
      )
      resolvedConfiguration.removeAll(keepingCapacity: false)
      let engine: any PacketEngine
      do {
        engine = try engineFactory.makeEngine()
      } catch {
        throw PacketTunnelProviderError.engineCreation(error.localizedDescription)
      }
      do {
        preparedPump = try dependencies.makePump(descriptor) { [weak self] error in
          self?.packetPumpFailed(error, sessionID: sessionID)
        }
      } catch {
        throw PacketTunnelProviderError.packetPumpSetup(error.localizedDescription)
      }
      guard let pump = preparedPump else {
        throw PacketTunnelProviderError.packetPumpSetup("Packet pump was not created.")
      }
      self.engine = engine
      engineStarted = false
      self.configuration = sensitiveConfiguration
      engineLease = acquiredLease
      packetPump = pump
      acquiredLease = nil
      preparedPump = nil
      transition(kind: .tunnelStarting, configuration: descriptor)

      dependencies.applyNetworkSettings(descriptor) { [weak self] error in
        self?.stateQueue.async { [weak self] in
          self?.networkSettingsCompleted(
            for: sessionID,
            descriptor: descriptor,
            error: error
          )
        }
      }
    } catch {
      preparedPump?.stop()
      do {
        try acquiredLease?.release()
      } catch {
        // The global authority may still own the slot even though no engine
        // started. Preserve the exact lease locally so stop() can retry the
        // release barrier; reporting Off here would create false availability.
        engineLease = acquiredLease
        acquiredLease = nil
        let providerError = PacketTunnelProviderError.configuration(
          "Global engine lease rollback failed: \(error.localizedDescription)"
        )
        if isStarting(sessionID) {
          lifecycle = .failedOwned(sessionID)
          startCompletion = nil
          transitionToFailure(providerError)
        }
        completion.finish(providerError)
        return
      }
      let providerError =
        error as? PacketTunnelProviderError
        ?? PacketTunnelProviderError.engineStart(String(describing: error))
      if isStarting(sessionID) {
        lifecycle = .idle
        startCompletion = nil
        transitionToFailure(providerError)
      }
      completion.finish(providerError)
    }
  }

  private func networkSettingsCompleted(
    for sessionID: UUID,
    descriptor: ConfigurationDescriptor,
    error: Error?
  ) {
    guard isStarting(sessionID) else {
      return
    }
    if let error {
      failSession(
        sessionID,
        error: .networkSettings(error.localizedDescription),
        cancelTunnel: false
      )
      return
    }
    do {
      guard let engine else {
        throw PacketTunnelProviderError.engineCreation("Packet engine ownership was lost.")
      }
      guard let configuration else {
        throw PacketTunnelProviderError.configuration("Staged configuration ownership was lost.")
      }
      guard let packetPump else {
        throw PacketTunnelProviderError.packetPumpSetup("Packet pump ownership was lost.")
      }
      let engineFileDescriptor: Int32
      do {
        engineFileDescriptor = try packetPump.takeEngineFileDescriptor()
      } catch {
        throw PacketTunnelProviderError.packetPumpSetup(error.localizedDescription)
      }
      do {
        // start() owns the descriptor even when it throws. Mark the engine as
        // owned before entering it so failure cleanup always calls stop() and
        // retains the machine lease if that stop barrier cannot be proven.
        engineStarted = true
        try configuration.withErasingData { configurationData in
          try engine.start(
            configuration: configurationData,
            packetFileDescriptor: engineFileDescriptor
          )
        }
        self.configuration = nil
      } catch let error as PacketEngineError {
        if case .controllerEndpointConflict(let port) = error {
          throw PacketTunnelProviderError.controllerEndpointConflict(port: port)
        }
        throw PacketTunnelProviderError.engineStart(error.localizedDescription)
      } catch {
        throw PacketTunnelProviderError.engineStart(error.localizedDescription)
      }
      do {
        try dependencies.recordAcceptance(descriptor)
      } catch {
        throw PacketTunnelProviderError.configuration(
          "Configuration replay protection rejected the generation."
        )
      }
      try packetPump.start()
      lifecycle = .active(sessionID)
      transition(kind: .tunnelActive, configuration: descriptor)
      let completion = startCompletion
      startCompletion = nil
      completion?.finish(nil)
    } catch let error as PacketTunnelProviderError {
      failSession(sessionID, error: error, cancelTunnel: false)
    } catch let error as PacketPumpError {
      failSession(sessionID, error: .packetPump(error), cancelTunnel: false)
    } catch {
      failSession(
        sessionID,
        error: .packetPumpSetup(error.localizedDescription),
        cancelTunnel: false
      )
    }
  }

  private func performStop(
    completionHandler: @escaping @Sendable (PacketTunnelStopResult) -> Void
  ) {
    let hadOwnedRuntime = engine != nil || packetPump != nil || engineLease != nil
    let pendingStart = startCompletion
    startCompletion = nil
    if hadOwnedRuntime || pendingStart != nil,
      let descriptor = currentSnapshot.configuration
    {
      transition(kind: .tunnelStopping, configuration: descriptor)
    }

    pendingStart?.finish(PacketTunnelProviderError.startupCancelled)
    let stopError = releaseOwnedRuntime(originalError: nil)
    if let stopError {
      lifecycle = .failedOwned(lifecycle.sessionID ?? UUID())
      transitionToFailure(stopError)
      completionHandler(.failure(.localRuntime(stopError)))
    } else {
      precondition(
        packetPump == nil && engine == nil && !engineStarted && configuration == nil
          && engineLease == nil,
        "A successful packet-tunnel stop must release every provider-owned resource."
      )
      lifecycle = .idle
      transitionToOff()
      completionHandler(.success(PacketTunnelStopProof()))
    }
  }

  private func packetPumpFailed(_ error: PacketPumpError, sessionID: UUID) {
    stateQueue.async { [weak self] in
      guard let self, ownsSession(sessionID) else {
        return
      }
      failSession(
        sessionID,
        error: .packetPump(error),
        cancelTunnel: true
      )
    }
  }

  private func failSession(
    _ sessionID: UUID,
    error: PacketTunnelProviderError,
    cancelTunnel: Bool
  ) {
    guard ownsSession(sessionID) else {
      return
    }
    let completion = startCompletion
    startCompletion = nil
    let terminalError = releaseOwnedRuntime(originalError: error) ?? error
    if engine != nil || engineLease != nil {
      lifecycle = .failedOwned(sessionID)
    } else {
      lifecycle = .idle
    }
    transitionToFailure(terminalError)
    completion?.finish(terminalError)
    if cancelTunnel {
      self.cancelTunnel(terminalError)
    }
  }

  private func releaseOwnedRuntime(
    originalError: PacketTunnelProviderError?
  ) -> PacketTunnelProviderError? {
    if let packetPump {
      packetPump.stop()
      self.packetPump = nil
    }
    configuration?.erase()
    configuration = nil
    if let engine, engineStarted {
      do {
        try engine.stop()
      } catch let engineStopError {
        do {
          try engineLease?.markStopFailed()
        } catch let ownershipError {
          let context = originalError.map { "; original error: \($0)" } ?? ""
          return .engineStop(
            "\(engineStopError.localizedDescription); failed to retain global ownership: "
              + "\(ownershipError.localizedDescription)\(context)"
          )
        }
        let context = originalError.map { "; original error: \($0)" } ?? ""
        return .engineStop("\(engineStopError.localizedDescription)\(context)")
      }
      self.engine = nil
      engineStarted = false
    } else if engine != nil {
      self.engine = nil
      engineStarted = false
    }
    if let engineLease {
      do {
        try engineLease.release()
        self.engineLease = nil
      } catch {
        let context = originalError.map { "; original error: \($0)" } ?? ""
        return .configuration(
          "Global engine lease release failed: \(error.localizedDescription)\(context)"
        )
      }
    }
    return originalError
  }

  private func transition(kind: EngineStateKind, configuration: ConfigurationDescriptor) {
    sequence &+= 1
    switch kind {
    case .tunnelStarting:
      currentSnapshot = .tunnelStarting(configuration: configuration, sequence: sequence)
    case .tunnelActive:
      currentSnapshot = .tunnelActive(configuration: configuration, sequence: sequence)
    case .tunnelStopping:
      currentSnapshot = .tunnelStopping(configuration: configuration, sequence: sequence)
    default:
      preconditionFailure("Unsupported provider lifecycle transition: \(kind)")
    }
  }

  private func transitionToFailure(_ error: PacketTunnelProviderError) {
    sequence &+= 1
    let previousConfiguration = currentSnapshot.configuration
    currentSnapshot = .tunnelFailed(
      error.engineFailure,
      configuration: previousConfiguration,
      sequence: sequence
    )
  }

  private func transitionToOff() {
    sequence &+= 1
    currentSnapshot = .off(sequence: sequence)
  }

  private func isStarting(_ sessionID: UUID) -> Bool {
    guard case .starting(let activeSessionID) = lifecycle else {
      return false
    }
    return activeSessionID == sessionID
  }

  private func ownsSession(_ sessionID: UUID) -> Bool {
    switch lifecycle {
    case .starting(let activeSessionID), .active(let activeSessionID):
      return activeSessionID == sessionID
    case .idle, .failedOwned:
      return false
    }
  }
}
