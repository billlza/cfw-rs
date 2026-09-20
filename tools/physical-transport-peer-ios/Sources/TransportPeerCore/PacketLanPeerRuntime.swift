import Foundation
@preconcurrency import Network

@MainActor
public final class PacketLanPeerRuntime {
  public typealias StateHandler = @MainActor (String) -> Void

  private enum Phase {
    case initialized
    case running
    case stoppingClosed
    case stoppingFailed
    case finished
  }

  private let session: PacketLanPeerSession
  private let paths: PacketLanPeerPaths
  private let processID: Int32
  private let stateHandler: StateHandler
  private var phase = Phase.initialized
  private var listener: NWListener?
  private var activeConnection: NWConnection?
  private var connectionDeadline: DispatchWorkItem?
  private var sessionDeadline: DispatchWorkItem?
  private var shutdownDeadline: DispatchWorkItem?
  private var readyReceipt: PacketLanReadyReceipt?
  private var readySHA256: String?
  private var completionTracker: PacketLanCompletionTracker?
  private var failurePhase = PacketLanFailurePhase.none
  private var failureReason = PacketLanFailureReason.none

  public init(
    session: PacketLanPeerSession,
    paths: PacketLanPeerPaths,
    processID: Int32,
    stateHandler: @escaping StateHandler
  ) {
    self.session = session
    self.paths = paths
    self.processID = processID
    self.stateHandler = stateHandler
  }

  public func start(now: Date = Date()) throws {
    guard phase == .initialized, listener == nil else {
      throw PeerContractError.malformed("packet LAN runtime start state")
    }
    let sessionWindow = try session.validate(now: now)
    guard let port = NWEndpoint.Port(rawValue: PacketLanPeerContract.listenerPort) else {
      throw PeerContractError.malformed("packet LAN listener port")
    }
    let listener = try NWListener(using: plainIPv4WiFiParameters(), on: port)
    listener.newConnectionLimit = PacketLanStage.allCases.count + 1
    listener.newConnectionHandler = { [weak self] connection in
      Task { @MainActor in
        self?.accept(connection)
      }
    }
    listener.stateUpdateHandler = { [weak self] state in
      Task { @MainActor in
        self?.handleListenerState(state)
      }
    }
    let sessionDeadline = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        self?.beginFailure(
          phase: .sessionDeadline,
          reason: .sessionDeadlineExpired
        )
      }
    }
    self.sessionDeadline = sessionDeadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + sessionWindow.expiresAt.timeIntervalSince(now),
      execute: sessionDeadline
    )
    self.listener = listener
    phase = .running
    listener.start(queue: .main)
    stateHandler("packet_lan_starting")
  }

  public func stop() {
    beginFailure(
      phase: .applicationLifecycle,
      reason: .applicationLifecycleRequested
    )
  }

  private func handleListenerState(_ state: NWListener.State) {
    switch state {
    case .ready:
      guard phase == .running, readyReceipt == nil else {
        beginFailure(phase: .listenerRuntime, reason: .listenerRuntimeFailed)
        return
      }
      do {
        let now = Date()
        let network = try PeerNetworkIdentity.currentWiFiIPv4()
        let ready = PacketLanReadyReceipt(
          schemaVersion: PacketLanPeerContract.schemaVersion,
          document: PacketLanPeerContract.readyDocument,
          evidenceRole: PacketLanPeerContract.evidenceRole,
          claimEligible: false,
          sessionID: session.sessionID,
          bundleIdentifier: PeerContract.bundleIdentifier,
          processID: processID,
          startedAt: PeerSession.timestamp(now),
          expiresAt: session.expiresAt,
          network: network,
          listener: .fixed,
          sessionFileRemoved: true
        )
        try ready.validate(session: session)
        let readySHA256 = try paths.writeReady(ready, session: session)
        completionTracker = try PacketLanCompletionTracker(
          session: session,
          localIPv4: network.ipv4
        )
        readyReceipt = ready
        self.readySHA256 = readySHA256
        stateHandler("packet_lan_ready")
      } catch {
        beginFailure(phase: .listenerRuntime, reason: .listenerRuntimeFailed)
      }
    case .waiting:
      guard phase == .running else { return }
      stateHandler("packet_lan_waiting_for_local_network_access")
    case .failed:
      beginFailure(phase: .listenerRuntime, reason: .listenerRuntimeFailed)
    case .cancelled:
      switch phase {
      case .stoppingClosed, .stoppingFailed:
        finalizeAfterListenerCancellation()
      case .running:
        failurePhase = .listenerRuntime
        failureReason = .listenerRuntimeFailed
        phase = .stoppingFailed
        finalizeAfterListenerCancellation()
      case .initialized, .finished:
        break
      }
    case .setup:
      break
    @unknown default:
      beginFailure(phase: .listenerRuntime, reason: .listenerRuntimeFailed)
    }
  }

  private func accept(_ connection: NWConnection) {
    guard phase == .running else {
      connection.forceCancel()
      if phase == .stoppingClosed {
        beginFailure(phase: .connectionAdmission, reason: .extraConnection)
      }
      return
    }
    guard readyReceipt != nil, completionTracker != nil else {
      connection.forceCancel()
      beginFailure(phase: .connectionAdmission, reason: .connectionOverlap)
      return
    }
    guard activeConnection == nil else {
      connection.forceCancel()
      beginFailure(phase: .connectionAdmission, reason: .connectionOverlap)
      return
    }
    guard completionTracker!.connections.count < PacketLanStage.allCases.count else {
      connection.forceCancel()
      beginFailure(phase: .connectionAdmission, reason: .extraConnection)
      return
    }
    activeConnection = connection
    scheduleConnectionDeadline(for: connection)
    connection.stateUpdateHandler = { [weak self, weak connection] state in
      Task { @MainActor in
        guard let self, let connection, self.isActive(connection) else { return }
        switch state {
        case .ready:
          self.receive(connection, buffer: Data())
        case .failed, .cancelled:
          self.clearActiveConnection(connection)
          self.beginFailure(
            phase: .payloadDelivery,
            reason: .connectionTerminated
          )
        default:
          break
        }
      }
    }
    connection.start(queue: .main)
  }

  private func receive(_ connection: NWConnection, buffer: Data) {
    guard isActive(connection), buffer.count <= PacketLanPeerContract.tokenBytes else {
      clearActiveConnection(connection)
      beginFailure(phase: .payloadDelivery, reason: .payloadInvalid)
      return
    }
    connection.receive(
      minimumIncompleteLength: 1,
      maximumLength: PacketLanPeerContract.tokenBytes + 1 - buffer.count
    ) { [weak self, weak connection] content, _, complete, error in
      Task { @MainActor in
        guard let self, let connection, self.isActive(connection) else { return }
        var next = buffer
        if let content {
          next.append(content)
        }
        guard error == nil, next.count <= PacketLanPeerContract.tokenBytes else {
          self.clearActiveConnection(connection)
          self.beginFailure(phase: .payloadDelivery, reason: .payloadInvalid)
          return
        }
        guard complete else {
          self.receive(connection, buffer: next)
          return
        }
        guard let peer = self.peerEndpoint(connection) else {
          self.clearActiveConnection(connection)
          self.beginFailure(
            phase: .payloadDelivery,
            reason: .clientEndpointInvalid
          )
          return
        }
        guard var tracker = self.completionTracker else {
          self.clearActiveConnection(connection)
          self.beginFailure(phase: .payloadDelivery, reason: .payloadInvalid)
          return
        }
        let decision = tracker.record(
          payload: next,
          eofObserved: true,
          peerIPv4: peer.address,
          peerPort: peer.port
        )
        self.completionTracker = tracker
        self.clearActiveConnection(connection)
        switch decision {
        case .continueRunning:
          self.stateHandler("packet_lan_stage_received")
        case .close:
          self.beginClosed()
        case .fail(let reason):
          self.beginFailure(phase: .payloadDelivery, reason: reason)
        }
      }
    }
  }

  private func peerEndpoint(_ connection: NWConnection) -> (address: String, port: UInt16)? {
    guard case .hostPort(let host, let port) = connection.endpoint else {
      return nil
    }
    switch host {
    case .ipv4(let address):
      return (address.debugDescription, port.rawValue)
    default:
      return nil
    }
  }

  private func scheduleConnectionDeadline(for connection: NWConnection) {
    connectionDeadline?.cancel()
    let deadline = DispatchWorkItem { [weak self, weak connection] in
      Task { @MainActor in
        guard let self, let connection, self.isActive(connection) else { return }
        self.clearActiveConnection(connection)
        self.beginFailure(
          phase: .payloadDelivery,
          reason: .connectionDeadlineExpired
        )
      }
    }
    connectionDeadline = deadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + PacketLanPeerContract.connectionDeadlineSeconds,
      execute: deadline
    )
  }

  private func isActive(_ connection: NWConnection) -> Bool {
    activeConnection.map({ ObjectIdentifier($0) }) == ObjectIdentifier(connection)
  }

  private func clearActiveConnection(_ connection: NWConnection) {
    guard isActive(connection) else { return }
    connectionDeadline?.cancel()
    connectionDeadline = nil
    connection.stateUpdateHandler = nil
    connection.cancel()
    activeConnection = nil
  }

  private func beginClosed() {
    guard phase == .running,
      activeConnection == nil,
      completionTracker?.connections.count == PacketLanStage.allCases.count
    else {
      beginFailure(phase: .payloadDelivery, reason: .payloadInvalid)
      return
    }
    phase = .stoppingClosed
    beginListenerCancellation()
  }

  private func beginFailure(
    phase failurePhase: PacketLanFailurePhase,
    reason failureReason: PacketLanFailureReason
  ) {
    guard phase != .finished, phase != .stoppingFailed else { return }
    self.failurePhase = failurePhase
    self.failureReason = failureReason
    phase = .stoppingFailed
    if let activeConnection {
      clearActiveConnection(activeConnection)
    }
    beginListenerCancellation()
  }

  private func beginListenerCancellation() {
    sessionDeadline?.cancel()
    sessionDeadline = nil
    listener?.cancel()
    shutdownDeadline?.cancel()
    let shutdownDeadline = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        guard let self, self.phase != .finished else { return }
        self.failurePhase = .listenerShutdown
        self.failureReason = .listenerShutdownFailed
        self.phase = .finished
        self.stateHandler("packet_lan_failed: listener shutdown")
      }
    }
    self.shutdownDeadline = shutdownDeadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + PacketLanPeerContract.connectionDeadlineSeconds,
      execute: shutdownDeadline
    )
  }

  private func finalizeAfterListenerCancellation(now: Date = Date()) {
    guard phase == .stoppingClosed || phase == .stoppingFailed else { return }
    shutdownDeadline?.cancel()
    shutdownDeadline = nil
    sessionDeadline?.cancel()
    sessionDeadline = nil
    listener = nil
    guard let ready = readyReceipt,
      let readySHA256,
      let tracker = completionTracker
    else {
      phase = .finished
      stateHandler("packet_lan_failed: no ready receipt")
      return
    }
    if (try? PeerNetworkIdentity.currentWiFiIPv4()) != ready.network {
      phase = .stoppingFailed
      failurePhase = .listenerRuntime
      failureReason = .networkIdentityChanged
    }
    let closed = phase == .stoppingClosed
    let result = PacketLanResultReceipt(
      schemaVersion: PacketLanPeerContract.schemaVersion,
      document: PacketLanPeerContract.resultDocument,
      evidenceRole: PacketLanPeerContract.evidenceRole,
      claimEligible: false,
      sessionID: session.sessionID,
      readySHA256: readySHA256,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: processID,
      completedAt: PeerSession.timestamp(now),
      status: closed ? .closed : .failed,
      failurePhase: closed ? .none : failurePhase,
      failureReason: closed ? .none : failureReason,
      network: ready.network,
      listener: .fixed,
      listenerClosed: true,
      sessionFileRemoved: true,
      connections: tracker.connections
    )
    do {
      try paths.writeResult(result, session: session, ready: ready)
      phase = .finished
      stateHandler(closed ? "packet_lan_closed" : "packet_lan_failed")
    } catch {
      phase = .finished
      stateHandler("packet_lan_failed: result receipt")
    }
  }
}
