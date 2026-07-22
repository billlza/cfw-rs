#if canImport(Libbox) && canImport(CFWLibboxObjC)
  import CFWLibboxObjC
  import CFWSharedProtocol
  import Darwin
  import Foundation
  import Libbox
  import Network
  import OSLog

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
    private static let initialPathTimeout: DispatchTimeInterval = .seconds(5)
    private let descriptor: OwnedPacketDescriptor?
    private let monitorLock = NSLock()
    private var monitor: NWPathMonitor?
    private var monitorQueue: DispatchQueue?

    init(role: LibboxRuntimeRole, packetFileDescriptor: Int32?) throws {
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
      let queue = DispatchQueue(
        label: "com.bill.clashformac.libbox-network-monitor",
        qos: .utility
      )
      let firstPath = DispatchSemaphore(value: 0)
      let firstPathLock = NSLock()
      var waitingForFirstPath = true
      try monitorLock.withLock {
        guard self.monitor == nil else {
          throw LibboxRuntimeError.networkMonitorAlreadyStarted
        }
        self.monitor = monitor
        monitorQueue = queue
      }
      monitor.pathUpdateHandler = { path in
        Self.publish(path, to: listenerBox.listener)
        let shouldSignal = firstPathLock.withLock { () -> Bool in
          guard waitingForFirstPath else {
            return false
          }
          waitingForFirstPath = false
          return true
        }
        if shouldSignal {
          firstPath.signal()
        }
      }
      monitor.start(queue: queue)
      guard firstPath.wait(timeout: .now() + Self.initialPathTimeout) == .success else {
        stopMonitor()
        throw LibboxRuntimeError.networkMonitorTimedOut
      }
    }

    func closeDefaultInterfaceMonitor(
      _ listener: (any LibboxInterfaceUpdateListenerProtocol)?
    ) throws {
      _ = listener
      guard monitorLock.withLock({ monitor != nil }) else {
        throw LibboxRuntimeError.networkMonitorUnavailable
      }
      stopMonitor()
    }

    func getInterfaces() throws -> (any LibboxNetworkInterfaceIteratorProtocol)? {
      guard let path = monitorLock.withLock({ monitor?.currentPath }) else {
        throw LibboxRuntimeError.networkMonitorUnavailable
      }
      guard path.status != .unsatisfied else {
        return NetworkInterfaceIterator([])
      }
      let interfaces = path.availableInterfaces.map { networkInterface in
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
        return monitor
      }
      monitor?.cancel()
    }

    private static func publish(
      _ path: NWPath,
      to listener: any LibboxInterfaceUpdateListenerProtocol
    ) {
      guard path.status != .unsatisfied,
        let interface = path.availableInterfaces.first
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

    init(role: LibboxRuntimeRole, packetFileDescriptor: Int32?) throws {
      self.role = role
      core = try LibboxPlatformCore(
        role: role,
        packetFileDescriptor: packetFileDescriptor
      )
      adapter = CFWLibboxPlatformAdapter(
        packetTunnel: role == .packetTunnel,
        delegate: core
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
          throw LibboxRuntimeError.setupFailed(setupError.localizedDescription)
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
      case failedOwned(LibboxCommandServer, LibboxPlatformContext)
    }

    private let role: LibboxRuntimeRole
    private let directories: LibboxRuntimeDirectories
    private let lock = NSLock()
    private var state = State.idle

    public init(role: LibboxRuntimeRole, directories: LibboxRuntimeDirectories) throws {
      self.role = role
      self.directories = directories
      try directories.validate()
    }

    deinit {
      do {
        try stop()
      } catch {
        // Lifecycle owners perform the authoritative retry while the runtime
        // is reachable. This deinitializer is only the last resource boundary,
        // so report a non-sensitive fault instead of silently discarding it.
        Self.logger.fault("libbox runtime final cleanup failed")
      }
    }

    public func start(configuration: Data, packetFileDescriptor: Int32?) throws {
      let configurationText: String
      do {
        configurationText = try LibboxConfigurationDocument.text(from: configuration)
      } catch {
        if let packetFileDescriptor, packetFileDescriptor >= 0 {
          Darwin.close(packetFileDescriptor)
        }
        throw error
      }
      do {
        try lock.withLock {
          guard case .idle = state else {
            throw LibboxRuntimeError.alreadyStarted
          }
          state = .starting
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
          packetFileDescriptor: packetFileDescriptor
        )
      } catch {
        lock.withLock { state = .idle }
        throw error
      }
      var server: LibboxCommandServer?
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
            creationError.localizedDescription
          )
        }
        guard let server else {
          throw LibboxRuntimeError.serverCreationFailed(
            "libbox returned no server and no error"
          )
        }
        let options = LibboxOverrideOptions()
        options.autoRedirect = false
        do {
          try server.startOrReloadService(configurationText, options: options)
        } catch {
          throw LibboxRuntimeError.serviceStartFailed(error.localizedDescription)
        }
        try platform.assertDescriptorTransferred()
        try Self.requireStarted(server)
        lock.withLock { state = .active(server, platform) }
      } catch {
        let primary = error
        if let server {
          do {
            try Self.closeServiceIfOwned(server)
            server.close()
            platform.closeUntransferredDescriptor()
            lock.withLock { state = .idle }
          } catch {
            lock.withLock { state = .failedOwned(server, platform) }
            throw LibboxRuntimeError.serviceStartCleanupFailed(
              start: primary.localizedDescription,
              cleanup: error.localizedDescription
            )
          }
        } else {
          platform.closeUntransferredDescriptor()
          lock.withLock { state = .idle }
        }
        throw primary
      }
    }

    public func stop() throws {
      let owned: (LibboxCommandServer, LibboxPlatformContext)? = try lock.withLock {
        switch state {
        case .idle:
          return nil
        case .starting:
          throw LibboxRuntimeError.serviceStopFailed(
            "startup is still in progress"
          )
        case .active(let server, let platform),
          .failedOwned(let server, let platform):
          return (server, platform)
        }
      }
      guard let (server, platform) = owned else {
        return
      }
      do {
        try Self.closeServiceIfOwned(server)
      } catch {
        lock.withLock { state = .failedOwned(server, platform) }
        throw LibboxRuntimeError.serviceStopFailed(error.localizedDescription)
      }
      server.close()
      platform.closeUntransferredDescriptor()
      lock.withLock { state = .idle }
    }

    public func healthCheck() throws {
      let server: LibboxCommandServer = try lock.withLock {
        guard case .active(let server, _) = state else {
          throw LibboxRuntimeError.serviceNotRunning(state: -1, message: "not active")
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
          message: "missing runtime status"
        )
      }
      guard status.state == LibboxRuntimeStateStarted else {
        throw LibboxRuntimeError.serviceNotRunning(
          state: status.state,
          message: status.errorMessage
        )
      }
    }

    private static func closeServiceIfOwned(_ server: LibboxCommandServer) throws {
      guard let status = server.runtimeStatus() else {
        throw LibboxRuntimeError.serviceStopFailed("missing runtime status")
      }
      if status.state == LibboxRuntimeStateIdle {
        return
      }
      try server.closeService()
      guard let stopped = server.runtimeStatus(), stopped.state == LibboxRuntimeStateIdle else {
        throw LibboxRuntimeError.serviceStopFailed(
          "libbox did not reach idle after close"
        )
      }
    }
  }
#endif
