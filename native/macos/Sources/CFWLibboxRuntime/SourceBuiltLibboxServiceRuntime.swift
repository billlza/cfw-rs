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
