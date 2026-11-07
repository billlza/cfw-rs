import Foundation

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
  final class CommandServerBox: @unchecked Sendable {
    let server: LibboxCommandServer

    init(_ server: LibboxCommandServer) {
      self.server = server
    }
  }

  /// The endpoint conflict a start reported, carried back from its thread.
  struct ReportedEndpointConflict: Sendable {
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

  final class LibboxPlatformCore: NSObject, CFWLibboxPlatformDelegate,
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

  final class LibboxPlatformContext: @unchecked Sendable {
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

  enum LibboxSetupCoordinator {
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

#endif
