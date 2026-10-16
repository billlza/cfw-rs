import Foundation

/// Each runtime owns only the interfaces registered by its embedded engine.
/// Callers serialize this value with the same lock as the monitor's lifetime.
struct LibboxInterfaceMonitorPolicy: Sendable {
  private(set) var sessionID: UUID?
  private var ownedInterfaces: Set<String> = []

  mutating func startSession() -> UUID {
    let sessionID = UUID()
    self.sessionID = sessionID
    return sessionID
  }

  mutating func stopSession() {
    sessionID = nil
  }

  mutating func register(_ name: String) {
    ownedInterfaces.insert(name)
  }

  func isCurrentSession(_ sessionID: UUID) -> Bool {
    self.sessionID == sessionID
  }

  func eligibleInterfaces<Interface>(
    _ interfaces: [Interface], named name: (Interface) -> String
  ) -> [Interface] {
    interfaces.filter { !ownedInterfaces.contains(name($0)) }
  }
}

/// How long a libbox start waits for the default-interface monitor's first
/// path. libbox cannot interrupt this wait.
enum LibboxInterfaceMonitorTiming {
  static let firstPathWait: Duration = .seconds(5)
}

#if canImport(Libbox) && canImport(CFWLibboxObjC)
  import CFWLibboxObjC
  import CFWSharedProtocol
  import Darwin
  import Libbox
  import Network
  import OSLog
  import Synchronization

  private final class OwnedPacketDescriptor: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int32

    init(_ value: Int32) {
      self.value = value
    }

    deinit {
      closeIfOwned()
    }

    func take() throws -> Int32 {
      try lock.withLock {
        guard value >= 0 else {
          throw LibboxRuntimeError.packetDescriptorAlreadyTransferred
        }
        let descriptor = value
        value = -1
        return descriptor
      }
    }

    func closeIfOwned() {
      let descriptor = lock.withLock { () -> Int32 in
        let descriptor = value
        value = -1
        return descriptor
      }
      if descriptor >= 0 {
        Darwin.close(descriptor)
      }
    }

    var wasTransferred: Bool {
      lock.withLock { value < 0 }
    }
  }

  private final class InterfaceListenerBox: @unchecked Sendable {
    let listener: any LibboxInterfaceUpdateListenerProtocol

    init(_ listener: any LibboxInterfaceUpdateListenerProtocol) {
      self.listener = listener
    }
  }

  /// Carries the command server to the threads that start and close libbox.
  /// gomobile objects may be called from any thread; libbox serializes its own
  /// lifecycle.
  private final class CommandServerBox: @unchecked Sendable {
    let server: LibboxCommandServer

    init(_ server: LibboxCommandServer) {
      self.server = server
    }
  }

  /// The endpoint conflict a start reported, carried back from its thread.
  private struct ReportedEndpointConflict: Sendable {
    let kind: Int32
    let port: Int32
  }

  private final class NetworkInterfaceIterator: NSObject,
    LibboxNetworkInterfaceIteratorProtocol
  {
    private var iterator: IndexingIterator<[LibboxNetworkInterface]>
    private var nextValue: LibboxNetworkInterface?

    init(_ values: [LibboxNetworkInterface]) {
      iterator = values.makeIterator()
    }

    func hasNext() -> Bool {
      nextValue = iterator.next()
      return nextValue != nil
    }

    func next() -> LibboxNetworkInterface? {
      nextValue
    }
  }

  private final class LibboxPlatformCore: NSObject, CFWLibboxPlatformDelegate,
    @unchecked Sendable
  {
    private static let firstPathTimeout =
      LibboxInterfaceMonitorTiming.firstPathWait.dispatchTimeInterval
    private let descriptor: OwnedPacketDescriptor?
    private let monitorLock = NSLock()
    private var monitor: NWPathMonitor?
    private var monitorQueue: DispatchQueue?
    private var monitorListener: InterfaceListenerBox?
    private var interfacePolicy = LibboxInterfaceMonitorPolicy()
    private let monitorClose: (@Sendable () throws -> Void)?

    init(
      role: LibboxRuntimeRole, packetFileDescriptor: Int32?,
      monitorClose: (@Sendable () throws -> Void)?
    ) throws {
      self.monitorClose = monitorClose
      switch (role, packetFileDescriptor) {
      case (.packetTunnel, .some(let descriptor)) where descriptor >= 0:
        self.descriptor = OwnedPacketDescriptor(descriptor)
      case (.packetTunnel, _):
        throw LibboxRuntimeError.missingPacketDescriptor
      case (.systemProxy, .none):
        descriptor = nil
      case (.systemProxy, .some(let descriptor)):
        if descriptor >= 0 {
          Darwin.close(descriptor)
        }
        throw LibboxRuntimeError.unexpectedPacketDescriptor
      }
      super.init()
    }

    deinit {
      stopMonitor()
      descriptor?.closeIfOwned()
    }

    func takeRawPacketDescriptor(_ output: UnsafeMutablePointer<Int32>?) throws {
      guard let output else {
        throw LibboxRuntimeError.missingPacketDescriptor
      }
      guard let descriptor else {
        throw LibboxRuntimeError.missingPacketDescriptor
      }
      output.pointee = try descriptor.take()
    }

    func startDefaultInterfaceMonitor(
      _ listener: (any LibboxInterfaceUpdateListenerProtocol)?
    ) throws {
      guard let listener else {
        throw LibboxRuntimeError.networkMonitorUnavailable
      }
      let listenerBox = InterfaceListenerBox(listener)
      let monitor = NWPathMonitor()
      // The engine start blocks below until this queue delivers the first path.
      // It runs at the QoS of a start the user requested; a lower queue would
      // make the start wait on lower-priority work (a priority inversion).
      let queue = DispatchQueue(
        label: "com.bill.clashformac.libbox-network-monitor",
        qos: .userInitiated
      )
      let firstPath = DispatchSemaphore(value: 0)
      let waitingForFirstPath = Mutex(true)
      let sessionID = try monitorLock.withLock {
        guard self.monitor == nil else {
          throw LibboxRuntimeError.networkMonitorAlreadyStarted
        }
        self.monitor = monitor
        monitorQueue = queue
        monitorListener = listenerBox
        return interfacePolicy.startSession()
      }
      monitor.pathUpdateHandler = { [weak self] path in
        self?.publish(path, sessionID: sessionID)
        let shouldSignal = waitingForFirstPath.withLock { waiting -> Bool in
          guard waiting else {
            return false
          }
          waiting = false
          return true
        }
        if shouldSignal {
          firstPath.signal()
        }
      }
      monitor.start(queue: queue)
      guard firstPath.wait(timeout: .now() + Self.firstPathTimeout) == .success else {
        stopMonitor()
        throw LibboxRuntimeError.networkMonitorTimedOut
      }
    }

    func closeDefaultInterfaceMonitor(
      _ listener: (any LibboxInterfaceUpdateListenerProtocol)?
    ) throws {
      _ = listener
      // libbox closes the monitor with every instance it closes, also when the
      // start ended before it started the monitor, or after the first path
      // never arrived and the start stopped it. Nothing runs then; failing the
      // close would leave libbox holding an instance it cannot close again.
      stopMonitor()
      try monitorClose?()
    }

    func getInterfaces() throws -> any LibboxNetworkInterfaceIteratorProtocol {
      guard
        let (path, policy) = monitorLock.withLock({
          monitor.map { ($0.currentPath, interfacePolicy) }
        })
      else {
        throw LibboxRuntimeError.networkMonitorUnavailable
      }
      guard path.status != .unsatisfied else {
        return NetworkInterfaceIterator([])
      }
      let interfaces = policy.eligibleInterfaces(path.availableInterfaces, named: \.name).map {
        networkInterface in
        let result = LibboxNetworkInterface()
        result.name = networkInterface.name
        result.index = Int32(networkInterface.index)
        switch networkInterface.type {
        case .wifi:
          result.type = LibboxInterfaceTypeWIFI
        case .cellular:
          result.type = LibboxInterfaceTypeCellular
        case .wiredEthernet:
          result.type = LibboxInterfaceTypeEthernet
        default:
          result.type = LibboxInterfaceTypeOther
        }
        return result
      }
      return NetworkInterfaceIterator(interfaces)
    }

    func registerMyInterface(_ name: String) {
      let publication = monitorLock.withLock { () -> (DispatchQueue, UUID)? in
        interfacePolicy.register(name)
        guard let queue = monitorQueue, let sessionID = interfacePolicy.sessionID else {
          return nil
        }
        return (queue, sessionID)
      }
      guard let (queue, sessionID) = publication else {
        return
      }
      // OpenInterface calls this from Go. Re-entering its listener synchronously
      // can deadlock its network locks; serialize the refresh with path updates.
      queue.async { [weak self] in
        self?.publishCurrentPath(sessionID: sessionID)
      }
    }

    func clearDNSCache() {
      // libbox owns the only DNS cache in this process; there is no additional
      // platform cache to flush through a public Network Extension API.
    }

    var descriptorWasTransferred: Bool {
      descriptor?.wasTransferred ?? true
    }

    func closeUntransferredDescriptor() {
      descriptor?.closeIfOwned()
    }

    private func stopMonitor() {
      let monitor = monitorLock.withLock { () -> NWPathMonitor? in
        let monitor = self.monitor
        self.monitor = nil
        monitorQueue = nil
        monitorListener = nil
        interfacePolicy.stopSession()
        return monitor
      }
      monitor?.cancel()
    }

    private func publishCurrentPath(sessionID: UUID) {
      guard
        let path = monitorLock.withLock({
          interfacePolicy.isCurrentSession(sessionID) ? monitor?.currentPath : nil
        })
      else {
        return
      }
      publish(path, sessionID: sessionID)
    }

    private func publish(_ path: NWPath, sessionID: UUID) {
      guard
        let (listenerBox, policy) = monitorLock.withLock({
          interfacePolicy.isCurrentSession(sessionID)
            ? monitorListener.map { ($0, interfacePolicy) } : nil
        })
      else {
        return
      }
      let listener = listenerBox.listener
      guard path.status != .unsatisfied,
        let interface = policy.eligibleInterfaces(path.availableInterfaces, named: \.name).first
      else {
        listener.updateDefaultInterface(
          "",
          interfaceIndex: -1,
          isExpensive: false,
          isConstrained: false
        )
        return
      }
      listener.updateDefaultInterface(
        interface.name,
        interfaceIndex: Int32(interface.index),
        isExpensive: path.isExpensive,
        isConstrained: path.isConstrained
      )
    }
  }

  private final class LibboxPlatformContext: @unchecked Sendable {
    let core: LibboxPlatformCore
    let adapter: CFWLibboxPlatformAdapter
    private let role: LibboxRuntimeRole

    init(
      role: LibboxRuntimeRole, packetFileDescriptor: Int32?,
      processPolicy: LibboxProcessLookupPolicy,
      monitorClose: (@Sendable () throws -> Void)?
    ) throws {
      self.role = role
      core = try LibboxPlatformCore(
        role: role,
        packetFileDescriptor: packetFileDescriptor,
        monitorClose: monitorClose
      )
      adapter = CFWLibboxPlatformAdapter(
        packetTunnel: role == .packetTunnel,
        delegate: core,
        processNames: processPolicy.names,
        processPaths: processPolicy.paths
      )
    }

    func assertDescriptorTransferred() throws {
      guard role != .packetTunnel || core.descriptorWasTransferred else {
        throw LibboxRuntimeError.missingPacketDescriptor
      }
    }

    func closeUntransferredDescriptor() {
      core.closeUntransferredDescriptor()
    }
  }

  private enum LibboxSetupCoordinator {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var configuredDirectories: LibboxRuntimeDirectories?

    static func configure(_ directories: LibboxRuntimeDirectories) throws {
      try lock.withLock {
        if let configuredDirectories {
          guard configuredDirectories == directories else {
            throw LibboxRuntimeError.setupConflict
          }
          try directories.validate()
          return
        }
        try directories.validate()
        let options = LibboxSetupOptions()
        options.basePath = directories.base.path
        options.workingPath = directories.working.path
        options.tempPath = directories.temporary.path
        options.logMaxLines = 0
        options.debug = false
        var setupError: NSError?
        LibboxSetup(options, &setupError)
        if let setupError {
          throw LibboxRuntimeError.setupFailed(LibboxDiagnostic(setupError.localizedDescription))
        }
        try directories.validate()
        configuredDirectories = directories
      }
    }
  }

  public final class SourceBuiltLibboxServiceRuntime: LibboxServiceRuntime,
    @unchecked Sendable
  {
    private static let logger = Logger(
      subsystem: "com.bill.clashformac",
      category: "libbox-runtime"
    )

    private enum State {
      case idle
      case starting
      case active(LibboxCommandServer, LibboxPlatformContext)
      /// libbox could not close the instance. The server and platform stay
      /// referenced so nothing libbox may still use is freed under it.
      case spent(LibboxInstanceUnclosable, LibboxCommandServer, LibboxPlatformContext)
    }

    private let role: LibboxRuntimeRole
    private let directories: LibboxRuntimeDirectories
    private let interfaceMonitorClose: (@Sendable () throws -> Void)?
    private let lock = NSLock()
    private var state = State.idle

    public convenience init(
      role: LibboxRuntimeRole, directories: LibboxRuntimeDirectories
    ) throws {
      try self.init(role: role, directories: directories, interfaceMonitorClose: nil)
    }

    /// Every close of libbox's network monitor calls `interfaceMonitorClose`
    /// when one is given, once the monitor stopped. One that throws makes libbox
    /// fail to close an instance the way a real close failure does; one that
    /// waits makes the close not return. Only tests pass one.
    init(
      role: LibboxRuntimeRole, directories: LibboxRuntimeDirectories,
      interfaceMonitorClose: (@Sendable () throws -> Void)?
    ) throws {
      self.role = role
      self.directories = directories
      self.interfaceMonitorClose = interfaceMonitorClose
      try directories.validate()
    }

    deinit {
      do {
        try stop()
      } catch {
        // Owners stop the runtime themselves and end their process when libbox
        // cannot close it. This deinitializer is only the last resource
        // boundary, so report a non-sensitive fault instead of discarding it.
        Self.logger.fault("libbox runtime final cleanup failed")
      }
    }

    public func start(
      configuration: Data, packetFileDescriptor: Int32?, deadline: EngineStartDeadline
    ) throws {
      let configurationText: String
      let expectedReceipt: LibboxRuntimeStartReceipt
      do {
        configurationText = try LibboxConfigurationDocument.text(from: configuration)
        expectedReceipt = try LibboxRuntimeStartReceipt.parse(
          configuration: configuration,
          role: role
        )
      } catch {
        if let packetFileDescriptor, packetFileDescriptor >= 0 {
          Darwin.close(packetFileDescriptor)
        }
        throw error
      }
      do {
        try lock.withLock {
          switch state {
          case .idle:
            state = .starting
          case .spent(let failure, _, _):
            throw failure
          case .starting, .active:
            throw LibboxRuntimeError.alreadyStarted
          }
        }
      } catch {
        if let packetFileDescriptor, packetFileDescriptor >= 0 {
          Darwin.close(packetFileDescriptor)
        }
        throw error
      }

      let platform: LibboxPlatformContext
      do {
        platform = try LibboxPlatformContext(
          role: role,
          packetFileDescriptor: packetFileDescriptor,
          processPolicy: expectedReceipt.processPolicy,
          monitorClose: interfaceMonitorClose
        )
      } catch {
        lock.withLock { state = .idle }
        throw error
      }
      var server: LibboxCommandServer?
      var startInterruption: Result<Void, LibboxInstanceUnclosable>?
      do {
        try LibboxSetupCoordinator.configure(directories)
        var creationError: NSError?
        server = LibboxNewCommandServer(
          platform.adapter,
          platform.adapter,
          &creationError
        )
        if let creationError {
          throw LibboxRuntimeError.serverCreationFailed(
            LibboxDiagnostic(creationError.localizedDescription)
          )
        }
        guard let server else {
          throw LibboxRuntimeError.serverCreationFailed(
            LibboxDiagnostic("libbox returned no server and no error")
          )
        }
        do {
          let target = CommandServerBox(server)
          let outcome = LibboxStartWatchdog().run(
            deadline: deadline,
            // CloseService interrupts the start, waits for it to return, then
            // closes the service, reporting idle once that close succeeded.
            interrupt: { () throws(LibboxInstanceUnclosable) in
              do {
                try target.server.closeService()
              } catch {
                throw LibboxInstanceUnclosable(closeFailure: error.localizedDescription)
              }
            },
            start: { () throws -> ReportedEndpointConflict? in
              let options = LibboxOverrideOptions()
              options.autoRedirect = false
              var reportedConflict: LibboxRuntimeStartConflict?
              try CFWLibboxPlatformAdapter.startOrReloadService(
                target.server,
                configuration: configurationText,
                options: options,
                reportedConflict: &reportedConflict)
              return reportedConflict.map {
                ReportedEndpointConflict(kind: $0.kind, port: $0.port)
              }
            })
          switch outcome {
          case .notStarted:
            Self.logger.error("libbox start skipped: the start deadline left too little time")
          case .interrupted:
            Self.logger.error("libbox start interrupted at the start deadline")
          case .abandoned:
            Self.logger.error(
              "libbox start abandoned: it was still inside libbox at the interrupt limit")
          case .completed:
            break
          }
          let verdict: LibboxStartVerdict<ReportedEndpointConflict> = outcome.verdict()
          startInterruption = verdict.interruption
          if let reportedConflict = try verdict.start.get() {
            let conflict = try LibboxRuntimeEndpointConflict.validated(
              kind: reportedConflict.kind,
              port: reportedConflict.port,
              mixedKind: LibboxRuntimeEndpointConflictMixed,
              controllerKind: LibboxRuntimeEndpointConflictController,
              receipt: expectedReceipt,
              runtimeRole: role
            )
            throw LibboxRuntimeError.endpointConflict(
              role: conflict.role,
              port: conflict.port
            )
          }
        } catch let error as LibboxRuntimeError {
          throw error
        } catch {
          throw LibboxRuntimeError.serviceStartFailed(LibboxDiagnostic(error.localizedDescription))
        }
        try platform.assertDescriptorTransferred()
        try Self.requireStarted(server)
        lock.withLock { state = .active(server, platform) }
      } catch {
        let primary = error
        guard let server else {
          platform.closeUntransferredDescriptor()
          lock.withLock { state = .idle }
          throw primary
        }
        do throws(LibboxInstanceUnclosable) {
          // A fired interrupt ran CloseService, which fails only when libbox
          // kept an instance it could not close: CloseService's own close
          // failed, or the interrupted start's had. libbox closes an instance
          // once, so asking again could not succeed. An abandoned start may
          // still be inside libbox, so nothing may reach libbox again.
          if case .failure(let unclosable) = startInterruption {
            throw unclosable
          }
          try Self.closeServiceIfOwned(CommandServerBox(server))
        } catch {
          Self.logger.fault(
            "libbox could not close a service instance after its start \(Self.startFailureKind(primary), privacy: .public): \(error.cause.kind, privacy: .public)"
          )
          lock.withLock { state = .spent(error, server, platform) }
          throw error
        }
        server.close()
        platform.closeUntransferredDescriptor()
        lock.withLock { state = .idle }
        throw primary
      }
    }

    /// How a failed start ended, without libbox's text, which can name the
    /// profile's servers.
    private static func startFailureKind(_ error: any Error) -> String {
      switch error as? LibboxRuntimeError {
      case .serviceStartTimedOut?:
        "timed out"
      case .endpointConflict(let role, let port)?:
        "found its \(role.rawValue) port \(port) in use"
      default:
        "failed"
      }
    }

    public func stop() throws(LibboxInstanceUnclosable) {
      let server: LibboxCommandServer
      let platform: LibboxPlatformContext
      switch lock.withLock({ state }) {
      case .idle:
        return
      case .starting:
        preconditionFailure("A libbox runtime was stopped while its start was running.")
      case .spent(let failure, _, _):
        throw failure
      case .active(let activeServer, let activePlatform):
        (server, platform) = (activeServer, activePlatform)
      }
      do {
        try Self.closeServiceIfOwned(CommandServerBox(server))
      } catch {
        Self.logger.fault(
          "libbox could not close a running service instance: \(error.cause.kind, privacy: .public)"
        )
        lock.withLock { state = .spent(error, server, platform) }
        throw error
      }
      server.close()
      platform.closeUntransferredDescriptor()
      lock.withLock { state = .idle }
    }

    public func healthCheck() throws {
      let server: LibboxCommandServer = try lock.withLock {
        guard case .active(let server, _) = state else {
          throw LibboxRuntimeError.serviceNotRunning(
            state: -1, message: LibboxDiagnostic("not active"))
        }
        return server
      }
      try Self.requireStarted(server)
    }

    public func resetNetwork() {
      let server: LibboxCommandServer? = lock.withLock {
        guard case .active(let server, _) = state else {
          return nil
        }
        return server
      }
      server?.resetNetwork()
    }

    private static func requireStarted(_ server: LibboxCommandServer) throws {
      guard let status = server.runtimeStatus() else {
        throw LibboxRuntimeError.serviceNotRunning(
          state: -1,
          message: LibboxDiagnostic("missing runtime status")
        )
      }
      guard status.state == LibboxRuntimeStateStarted else {
        throw LibboxRuntimeError.serviceNotRunning(
          state: status.state,
          message: LibboxDiagnostic(status.errorMessage)
        )
      }
    }

    /// Closes the service unless libbox reports it idle. Every failure means
    /// libbox could not close the instance, which it closes only once; a close
    /// that does not return within `EngineStopBudget.libboxClose` counts alike.
    private static func closeServiceIfOwned(
      _ target: CommandServerBox
    ) throws(LibboxInstanceUnclosable) {
      guard let status = target.server.runtimeStatus() else {
        throw LibboxInstanceUnclosable(closeFailure: "libbox reported no runtime status")
      }
      if status.state == LibboxRuntimeStateIdle {
        return
      }
      switch LibboxBoundedClose().run({ try target.server.closeService() }) {
      case .closed:
        break
      case .failed(let diagnostic):
        throw LibboxInstanceUnclosable(.closeFailed(diagnostic))
      case .didNotReturn:
        throw LibboxInstanceUnclosable(.closeDidNotReturn)
      }
      guard let stopped = target.server.runtimeStatus(),
        stopped.state == LibboxRuntimeStateIdle
      else {
        throw LibboxInstanceUnclosable(closeFailure: "libbox did not reach idle after close")
      }
    }
  }
#endif
