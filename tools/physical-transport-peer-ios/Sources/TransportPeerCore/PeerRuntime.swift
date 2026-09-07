import Foundation
@preconcurrency import Network
import Security

private struct PeerEchoRuntimeState {
  var tracker: PeerEchoDeliveryTracker
  let payload: Data
  let bytesSent: Int
}

private struct PeerConnectionDeadline {
  let ticket: PeerConnectionDeadlineTicket
  let workItem: DispatchWorkItem
}

private struct PeerActiveConnectionRecord {
  let connection: NWConnection
  let service: PeerService
  let admissionSequence: Int
  var phase: PeerPhaseReached
  var quicStreamIdentifier: UInt64?
}

private struct PeerAdmissionOverlapObservation {
  let blockingService: PeerFailedService
  let blockingPhase: PeerPhaseReached
  let blockingAdmissionSequence: Int
  let incomingAdmissionSequence: Int
  let incomingMatchesBlockerObject: Bool
  let blockingQUICStreamIdentifier: UInt64?
}

private struct PeerPendingQUICResolution {
  let connection: NWConnection
  let payload: Data
  let bytesSent: Int
  let security: PeerSecurityObservation
  let evidenceDisposition: PeerEvidenceDisposition
  let deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion
}

@MainActor
public final class PeerRuntime {
  public typealias StateHandler = @MainActor (String) -> Void

  private let session: PeerSession
  private let paths: PeerPaths
  private let identity: PeerIdentity
  private let processID: Int32
  private let stateHandler: StateHandler
  private var listeners: [PeerService: NWListener] = [:]
  private var quicConnectionGroup: NWConnectionGroup?
  private var quicMultiplexTracker = PeerQUICMultiplexTracker()
  private var readyServices: Set<PeerService> = []
  private var activeConnections: [ObjectIdentifier: PeerActiveConnectionRecord] = [:]
  private var deadlines: [ObjectIdentifier: PeerConnectionDeadline] = [:]
  private var deadlineSchedules: [ObjectIdentifier: PeerConnectionDeadlineSchedule] = [:]
  private var echoDeliveries: [ObjectIdentifier: PeerEchoRuntimeState] = [:]
  private var securityObservations: [ObjectIdentifier: PeerSecurityObservation] = [:]
  private var completionTracker = PeerCompletionTracker()
  private var connectionAttempts = 0
  private var admissionEventSequence = 0
  private var admissionOverlapObservation: PeerAdmissionOverlapObservation?
  private var stopping = false
  private var finalized = false
  private var requestedStatus = PeerResultStatus.failed
  private var requestedFailurePhase = PeerFailurePhase.none
  private var requestedFailedService = PeerFailedService.runtime
  private var requestedFailureReason = PeerFailureReason.applicationLifecycleRequested
  private var requestedPhaseReached = PeerPhaseReached.applicationStarted
  private var phaseReached = PeerPhaseReached.applicationStarted
  private var networkShutdownTracker: PeerNetworkShutdownTracker?
  private var readyPublished = false
  private var sessionDeadline: DispatchWorkItem?
  private var shutdownDeadline: DispatchWorkItem?
  private var quicEstablishmentDeadline: DispatchWorkItem?
  private var quicDrainDeadline: DispatchWorkItem?
  private var pendingQUICResolution: PeerPendingQUICResolution?

  public init(
    session: PeerSession,
    paths: PeerPaths,
    identity: PeerIdentity,
    processID: Int32,
    stateHandler: @escaping StateHandler
  ) {
    self.session = session
    self.paths = paths
    self.identity = identity
    self.processID = processID
    self.stateHandler = stateHandler
  }

  public func start(now: Date = Date()) throws {
    guard !stopping, !finalized, listeners.isEmpty, quicConnectionGroup == nil else {
      throw PeerContractError.malformed("runtime start state")
    }
    let sessionWindow = try session.validate(now: now)
    let sessionDeadline = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        self?.fail(
          failurePhase: .sessionDeadline,
          failedService: .runtime,
          reason: .sessionDeadlineExpired
        )
      }
    }
    self.sessionDeadline = sessionDeadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + sessionWindow.expiresAt.timeIntervalSince(now),
      execute: sessionDeadline
    )
    markPhaseReached(.listenerSetup)
    let configurations: [(PeerService, UInt16, NWParameters)] = try [
      (.tcpSink, PeerContract.tcpSinkPort, plainTCPParameters()),
      (.tls13Echo, PeerContract.tlsEchoPort, tlsParameters()),
      (.quicEcho, PeerContract.quicEchoPort, quicParameters()),
    ]
    do {
      for (service, rawPort, parameters) in configurations {
        guard let port = NWEndpoint.Port(rawValue: rawPort) else {
          throw PeerContractError.malformed("listener port")
        }
        let listener = try NWListener(using: parameters, on: port)
        listener.stateUpdateHandler = { [weak self] state in
          Task { @MainActor in
            self?.handleListenerState(state, service: service)
          }
        }
        if service == .quicEcho {
          listener.newConnectionLimit = PeerContract.observableQUICConnectionGroupLimit
          listener.newConnectionGroupHandler = { [weak self] group in
            MainActor.assumeIsolated {
              self?.acceptQUICConnectionGroup(group)
            }
          }
        } else {
          listener.newConnectionLimit = PeerContract.maximumConnections
          listener.newConnectionHandler = { [weak self] connection in
            Task { @MainActor in
              self?.accept(connection, service: service)
            }
          }
        }
        listeners[service] = listener
        listener.start(queue: .main)
      }
    } catch {
      fail(
        failurePhase: .listenerSetup,
        failedService: .runtime,
        reason: .listenerSetupFailed,
        now: now
      )
      throw error
    }
    stateHandler("starting")
  }

  public func stop(
    failurePhase: PeerFailurePhase = .applicationLifecycle,
    now: Date = Date()
  ) {
    let reason: PeerFailureReason =
      failurePhase == .sessionDeadline
      ? .sessionDeadlineExpired
      : .applicationLifecycleRequested
    fail(
      failurePhase: failurePhase,
      failedService: .runtime,
      reason: reason,
      now: now
    )
  }

  private func stopResolved(status: PeerResultStatus, now: Date = Date()) {
    beginStop(
      status: status,
      failurePhase: .none,
      failedService: .none,
      failureReason: .none,
      failurePhaseReached: .completed,
      now: now
    )
  }

  private func fail(
    failurePhase: PeerFailurePhase,
    failedService: PeerFailedService,
    reason: PeerFailureReason,
    phaseReached failurePhaseReached: PeerPhaseReached? = nil,
    now: Date = Date()
  ) {
    beginStop(
      status: .failed,
      failurePhase: failurePhase,
      failedService: failedService,
      failureReason: reason,
      failurePhaseReached: failurePhaseReached ?? phaseReached,
      now: now
    )
  }

  private func beginStop(
    status: PeerResultStatus,
    failurePhase: PeerFailurePhase,
    failedService: PeerFailedService,
    failureReason: PeerFailureReason,
    failurePhaseReached: PeerPhaseReached,
    now: Date
  ) {
    guard !finalized else { return }
    let requestedResolutionIsValid =
      status != .failed
      && failurePhase == .none
      && completionTracker.resolvedStatus == status
    let effectiveStatus = requestedResolutionIsValid ? status : .failed
    let effectiveFailurePhase =
      effectiveStatus == .failed
      ? (failurePhase == .none ? .completionValidation : failurePhase)
      : .none
    let effectiveFailedService =
      effectiveStatus == .failed
      ? (failedService == .none ? .runtime : failedService)
      : .none
    let effectiveFailureReason =
      effectiveStatus == .failed
      ? (failureReason == .none ? .completionEvidenceInvalid : failureReason)
      : .none
    let effectivePhaseReached =
      effectiveStatus == .failed ? failurePhaseReached : .completed
    if stopping {
      if effectiveStatus == .failed, requestedStatus != .failed {
        requestedStatus = .failed
        requestedFailurePhase = effectiveFailurePhase
        requestedFailedService = effectiveFailedService
        requestedFailureReason = effectiveFailureReason
        requestedPhaseReached = effectivePhaseReached
      }
      return
    }
    stopping = true
    requestedStatus = effectiveStatus
    requestedFailurePhase = effectiveFailurePhase
    requestedFailedService = effectiveFailedService
    requestedFailureReason = effectiveFailureReason
    requestedPhaseReached = effectivePhaseReached
    markPhaseReached(.listenerShutdown)
    sessionDeadline?.cancel()
    sessionDeadline = nil
    quicEstablishmentDeadline?.cancel()
    quicEstablishmentDeadline = nil
    quicDrainDeadline?.cancel()
    quicDrainDeadline = nil
    pendingQUICResolution = nil
    for deadline in deadlines.values {
      deadline.workItem.cancel()
    }
    deadlines.removeAll()
    deadlineSchedules.removeAll()
    for record in activeConnections.values {
      record.connection.stateUpdateHandler = nil
      record.connection.cancel()
    }
    activeConnections.removeAll()
    echoDeliveries.removeAll()
    securityObservations.removeAll()
    var expectedResources = Set(
      listeners.keys.map(PeerNetworkShutdownResource.listener)
    )
    if quicConnectionGroup != nil {
      expectedResources.insert(.quicConnectionGroup)
    }
    networkShutdownTracker = PeerNetworkShutdownTracker(
      expectedResources: expectedResources
    )
    quicConnectionGroup?.newConnectionHandler = nil
    quicConnectionGroup?.cancel()
    for listener in listeners.values {
      listener.cancel()
    }
    if expectedResources.isEmpty {
      finalizeResult(listenersClosed: true, now: now)
      return
    }
    let shutdownDeadline = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        guard let self, !self.finalized else { return }
        self.finalizeResult(listenersClosed: false, now: Date())
      }
    }
    self.shutdownDeadline = shutdownDeadline
    DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: shutdownDeadline)
  }

  private func finalizeResult(listenersClosed: Bool, now: Date) {
    guard !finalized else { return }
    finalized = true
    shutdownDeadline?.cancel()
    shutdownDeadline = nil
    listeners.removeAll()
    quicConnectionGroup = nil
    networkShutdownTracker = nil
    let finalStatus = finalStatus(listenersClosed: listenersClosed)
    let failureMetadata = finalFailureMetadata(
      status: finalStatus,
      listenersClosed: listenersClosed
    )
    let overlapObservation =
      failureMetadata.reason == .connectionAdmissionOverlap
      ? admissionOverlapObservation : nil
    let receipt = ResultReceipt(
      schemaVersion: PeerContract.resultSchemaVersion,
      document: PeerContract.resultDocument,
      evidenceRole: PeerContract.resultEvidenceRole,
      claimEligible: false,
      sessionID: session.sessionID,
      certificateSHA256: session.certificateSHA256,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: processID,
      completedAt: PeerSession.timestamp(now),
      status: finalStatus,
      failurePhase: failureMetadata.phase,
      failedService: failureMetadata.service,
      failureReason: failureMetadata.reason,
      phaseReached: failureMetadata.phaseReached,
      blockingService: overlapObservation?.blockingService,
      blockingPhase: overlapObservation?.blockingPhase,
      blockingAdmissionSequence: overlapObservation?.blockingAdmissionSequence,
      incomingAdmissionSequence: overlapObservation?.incomingAdmissionSequence,
      incomingMatchesBlockerObject: overlapObservation?.incomingMatchesBlockerObject,
      blockingQUICStreamIdentifier: overlapObservation?.blockingQUICStreamIdentifier,
      listenersClosed: listenersClosed,
      identityFilesRemoved: identity.sourceFilesRemoved,
      connections: completionTracker.outcomes
    )
    do {
      try receipt.validate()
      try paths.writeResult(receipt)
      stateHandler(receipt.status.rawValue)
    } catch {
      stateHandler("failed: result receipt")
    }
  }

  private func finalStatus(listenersClosed: Bool) -> PeerResultStatus {
    guard listenersClosed else { return .failed }
    guard identity.sourceFilesRemoved else { return .failed }
    return requestedStatus
  }

  private func finalFailureMetadata(
    status: PeerResultStatus,
    listenersClosed: Bool
  ) -> (
    phase: PeerFailurePhase,
    service: PeerFailedService,
    reason: PeerFailureReason,
    phaseReached: PeerPhaseReached
  ) {
    guard listenersClosed else {
      return (
        .listenerShutdown,
        .runtime,
        .listenerShutdownDeadline,
        .listenerShutdown
      )
    }
    guard identity.sourceFilesRemoved else {
      return (
        .identityCleanup,
        .runtime,
        .identityCleanupFailed,
        .identityCleanup
      )
    }
    guard status == .failed else {
      return (.none, .none, .none, .completed)
    }
    return (
      requestedFailurePhase,
      requestedFailedService,
      requestedFailureReason,
      requestedPhaseReached
    )
  }

  private func handleListenerState(_ state: NWListener.State, service: PeerService) {
    if case .cancelled = state, stopping {
      observeNetworkResourceCancellation(.listener(service))
      return
    }
    guard !stopping, !finalized else { return }
    switch state {
    case .ready:
      readyServices.insert(service)
      publishReadyIfComplete()
    case .failed:
      stateHandler("failed: \(service.rawValue) listener")
      fail(
        failurePhase: .listenerRuntime,
        failedService: service.failedService,
        reason: .listenerRuntimeFailed
      )
    case .waiting(let error):
      stateHandler("waiting: \(service.rawValue): \(error)")
    case .cancelled:
      stateHandler("failed: unexpected listener cancellation")
      fail(
        failurePhase: .listenerRuntime,
        failedService: service.failedService,
        reason: .unexpectedListenerCancellation
      )
    case .setup:
      break
    @unknown default:
      stateHandler("failed: unknown listener state")
      fail(
        failurePhase: .listenerRuntime,
        failedService: service.failedService,
        reason: .listenerRuntimeFailed
      )
    }
  }

  private func observeNetworkResourceCancellation(
    _ resource: PeerNetworkShutdownResource
  ) {
    if networkShutdownTracker?.observeCancellation(for: resource) == true {
      finalizeResult(listenersClosed: true, now: Date())
    }
  }

  private func publishReadyIfComplete(now: Date = Date()) {
    guard !stopping, !finalized, !readyPublished,
      readyServices == Set(PeerService.allCases)
    else { return }
    markPhaseReached(.listenersReady)
    let network: PeerNetworkReceipt
    do {
      network = try PeerNetworkIdentity.currentWiFiIPv4()
    } catch {
      stateHandler("failed: Wi-Fi IPv4 identity")
      fail(
        failurePhase: .readyPublication,
        failedService: .runtime,
        reason: .readyPublicationFailed,
        now: now
      )
      return
    }
    let receipt = ReadyReceipt(
      schemaVersion: PeerContract.schemaVersion,
      document: PeerContract.readyDocument,
      sessionID: session.sessionID,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: processID,
      startedAt: PeerSession.timestamp(now),
      expiresAt: session.expiresAt,
      certificateSHA256: session.certificateSHA256,
      network: network,
      listeners: .fixed
    )
    do {
      try paths.writeReady(receipt)
      readyPublished = true
      stateHandler("ready")
    } catch {
      stateHandler("failed: ready receipt")
      fail(
        failurePhase: .readyPublication,
        failedService: .runtime,
        reason: .readyPublicationFailed,
        now: now
      )
    }
  }

  private func acceptQUICConnectionGroup(_ group: NWConnectionGroup) {
    guard !stopping, !finalized,
      connectionAttempts < PeerContract.maximumConnections
    else {
      group.cancel()
      return
    }
    admissionEventSequence += 1
    let incomingAdmissionSequence = admissionEventSequence
    let currentGroupMatches =
      quicConnectionGroup.map {
        ObjectIdentifier($0) == ObjectIdentifier(group)
      } ?? false
    guard activeConnections.isEmpty,
      quicConnectionGroup == nil,
      quicMultiplexTracker.admitTunnel(
        admissionSequence: incomingAdmissionSequence
      )
    else {
      recordAdmissionOverlap(
        incomingAdmissionSequence: incomingAdmissionSequence,
        incomingMatchesBlockerObject: currentGroupMatches
      )
      group.cancel()
      stateHandler("failed: QUIC tunnel admission overlaps a live connection")
      fail(
        failurePhase: .connectionAdmission,
        failedService: .quicEcho,
        reason: .connectionAdmissionOverlap
      )
      return
    }

    connectionAttempts += 1
    quicConnectionGroup = group
    scheduleQUICEstablishmentDeadline(for: group)
    group.stateUpdateHandler = { [weak self, weak group] state in
      MainActor.assumeIsolated {
        guard let self, let group else { return }
        self.handleQUICConnectionGroupState(state, group: group)
      }
    }
    group.newConnectionHandler = { [weak self, weak group] connection in
      MainActor.assumeIsolated {
        guard let self, let group else {
          connection.forceCancel()
          return
        }
        self.acceptQUICStream(connection, from: group)
      }
    }
    group.start(queue: .main)
  }

  private func handleQUICConnectionGroupState(
    _ state: NWConnectionGroup.State,
    group: NWConnectionGroup
  ) {
    let isCurrentGroup =
      quicConnectionGroup.map {
        ObjectIdentifier($0) == ObjectIdentifier(group)
      } ?? false
    if case .cancelled = state, stopping {
      if isCurrentGroup {
        group.newConnectionHandler = nil
        group.stateUpdateHandler = nil
        quicConnectionGroup = nil
      }
      observeNetworkResourceCancellation(.quicConnectionGroup)
      return
    }
    guard !stopping, !finalized, isCurrentGroup else { return }
    switch state {
    case .setup, .ready:
      break
    case .waiting(let error):
      stateHandler("waiting: quic_echo tunnel: \(error)")
    case .failed:
      if quicMultiplexTracker.phase == .streamDraining,
        let pendingQUICResolution
      {
        beginQUICGroupCancellationAfterStreamTerminal(
          pendingQUICResolution.connection,
          group: group
        )
        return
      }
      stateHandler("failed: quic_echo tunnel")
      fail(
        failurePhase: .listenerRuntime,
        failedService: .quicEcho,
        reason: .listenerRuntimeFailed
      )
    case .cancelled:
      guard quicMultiplexTracker.observeTunnelCancelled() else {
        stateHandler("failed: unexpected QUIC tunnel cancellation")
        fail(
          failurePhase: .listenerRuntime,
          failedService: .quicEcho,
          reason: .unexpectedListenerCancellation
        )
        return
      }
      quicDrainDeadline?.cancel()
      quicDrainDeadline = nil
      group.newConnectionHandler = nil
      group.stateUpdateHandler = nil
      quicConnectionGroup = nil
      completePendingQUICResolution()
    @unknown default:
      stateHandler("failed: unknown QUIC tunnel state")
      fail(
        failurePhase: .listenerRuntime,
        failedService: .quicEcho,
        reason: .listenerRuntimeFailed
      )
    }
  }

  private func acceptQUICStream(
    _ connection: NWConnection,
    from group: NWConnectionGroup
  ) {
    let isCurrentGroup =
      quicConnectionGroup.map {
        ObjectIdentifier($0) == ObjectIdentifier(group)
      } ?? false
    guard !stopping, !finalized, isCurrentGroup else {
      connection.forceCancel()
      return
    }
    guard quicMultiplexTracker.admitStream(),
      let tunnelAdmissionSequence = quicMultiplexTracker.tunnelAdmissionSequence
    else {
      admissionEventSequence += 1
      let incomingAdmissionSequence = admissionEventSequence
      let incomingMatchesBlocker = activeConnections[ObjectIdentifier(connection)] != nil
      recordAdmissionOverlap(
        incomingAdmissionSequence: incomingAdmissionSequence,
        incomingMatchesBlockerObject: incomingMatchesBlocker
      )
      connection.forceCancel()
      stateHandler("failed: QUIC stream admission overlaps the tunnel contract")
      fail(
        failurePhase: .connectionAdmission,
        failedService: .quicEcho,
        reason: .connectionAdmissionOverlap
      )
      return
    }
    accept(
      connection,
      service: .quicEcho,
      inheritedAdmissionSequence: tunnelAdmissionSequence
    )
  }

  private func recordAdmissionOverlap(
    incomingAdmissionSequence: Int,
    incomingMatchesBlockerObject: Bool
  ) {
    if let blocker = activeConnections.values.min(by: {
      $0.admissionSequence < $1.admissionSequence
    }) {
      admissionOverlapObservation = PeerAdmissionOverlapObservation(
        blockingService: blocker.service.failedService,
        blockingPhase: blocker.phase,
        blockingAdmissionSequence: blocker.admissionSequence,
        incomingAdmissionSequence: incomingAdmissionSequence,
        incomingMatchesBlockerObject: incomingMatchesBlockerObject,
        blockingQUICStreamIdentifier: blocker.quicStreamIdentifier
      )
      return
    }
    guard let tunnelAdmissionSequence = quicMultiplexTracker.tunnelAdmissionSequence else {
      return
    }
    admissionOverlapObservation = PeerAdmissionOverlapObservation(
      blockingService: .quicEcho,
      blockingPhase: quicMultiplexTracker.blockingPhase,
      blockingAdmissionSequence: tunnelAdmissionSequence,
      incomingAdmissionSequence: incomingAdmissionSequence,
      incomingMatchesBlockerObject: incomingMatchesBlockerObject,
      blockingQUICStreamIdentifier: quicMultiplexTracker.streamIdentifier
    )
  }

  private func scheduleQUICEstablishmentDeadline(for group: NWConnectionGroup) {
    quicEstablishmentDeadline?.cancel()
    let deadline = DispatchWorkItem { [weak self, weak group] in
      Task { @MainActor in
        guard let self, let group,
          self.quicConnectionGroup.map({ ObjectIdentifier($0) })
            == ObjectIdentifier(group),
          self.quicMultiplexTracker.streamIdentifier == nil
        else { return }
        self.fail(
          failurePhase: .listenerRuntime,
          failedService: .quicEcho,
          reason: .listenerRuntimeFailed
        )
      }
    }
    quicEstablishmentDeadline = deadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + PeerContract.quicEstablishmentDeadlineSeconds,
      execute: deadline
    )
  }

  private func accept(
    _ connection: NWConnection,
    service: PeerService,
    inheritedAdmissionSequence: Int? = nil
  ) {
    if inheritedAdmissionSequence == nil {
      admissionEventSequence += 1
    }
    let incomingAdmissionSequence = inheritedAdmissionSequence ?? admissionEventSequence
    let identifier = ObjectIdentifier(connection)
    guard !stopping, !finalized,
      inheritedAdmissionSequence != nil
        || connectionAttempts < PeerContract.maximumConnections,
      activeConnections.count < PeerContract.maximumConnections
    else {
      connection.cancel()
      return
    }
    if let reason = PeerConnectionAdmissionGuard.failureReason(
      activeConnectionCount: activeConnections.count
    ) {
      if let blocker = activeConnections.values.min(by: {
        $0.admissionSequence < $1.admissionSequence
      }) {
        admissionOverlapObservation = PeerAdmissionOverlapObservation(
          blockingService: blocker.service.failedService,
          blockingPhase: blocker.phase,
          blockingAdmissionSequence: blocker.admissionSequence,
          incomingAdmissionSequence: incomingAdmissionSequence,
          incomingMatchesBlockerObject: activeConnections[identifier] != nil,
          blockingQUICStreamIdentifier: blocker.quicStreamIdentifier
        )
      }
      connection.forceCancel()
      stateHandler("failed: connection admission overlaps a live connection")
      fail(
        failurePhase: .connectionAdmission,
        failedService: service.failedService,
        reason: reason
      )
      return
    }
    if inheritedAdmissionSequence == nil {
      connectionAttempts += 1
    }
    activeConnections[identifier] = PeerActiveConnectionRecord(
      connection: connection,
      service: service,
      admissionSequence: incomingAdmissionSequence,
      phase: .connectionAccepted,
      quicStreamIdentifier: nil
    )
    deadlineSchedules[identifier] = PeerConnectionDeadlineSchedule()
    markConnectionPhase(.connectionAccepted, connection: connection)
    renewConnectionDeadline(
      connection,
      service: service,
      phase: .preSecurityHandshake
    )
    connection.stateUpdateHandler = { [weak self, weak connection] state in
      Task { @MainActor in
        guard let self, let connection else { return }
        switch state {
        case .ready:
          guard self.activeConnections[identifier] != nil,
            self.echoDeliveries[identifier] == nil
          else { return }
          if let observation = self.expectedSecurityObservation(connection, service: service) {
            guard self.recordQUICStreamIdentifier(connection, service: service) else {
              self.stateHandler("failed: QUIC stream identity")
              self.fail(
                failurePhase: .listenerRuntime,
                failedService: .quicEcho,
                reason: .listenerRuntimeFailed
              )
              return
            }
            self.securityObservations[identifier] = observation
            self.markConnectionPhase(.securityReady, connection: connection)
            self.renewConnectionDeadline(
              connection,
              service: service,
              phase: .connectionProgress(trackerGeneration: nil)
            )
            self.receive(connection, service: service, buffer: Data())
          } else {
            if service == .quicEcho {
              self.stateHandler("failed: QUIC security metadata")
              self.fail(
                failurePhase: .listenerRuntime,
                failedService: .quicEcho,
                reason: .listenerRuntimeFailed
              )
            } else {
              self.finish(connection, service: service, payload: nil, bytesSent: 0)
            }
          }
        case .failed, .cancelled:
          // A state callback may already be queued when the handler is cleared.
          // Once delivery starts, only the outstanding post-ACK receive may
          // classify peer terminal or trailing-byte evidence.
          guard self.echoDeliveries[identifier] == nil else { return }
          if service == .quicEcho {
            self.stateHandler("failed: QUIC stream ended before completion")
            self.fail(
              failurePhase: .listenerRuntime,
              failedService: .quicEcho,
              reason: .listenerRuntimeFailed
            )
          } else {
            self.finish(connection, service: service, payload: nil, bytesSent: 0)
          }
        default:
          break
        }
      }
    }
    connection.start(queue: .main)
  }

  private func handleConnectionDeadline(
    _ connection: NWConnection,
    service: PeerService,
    ticket: PeerConnectionDeadlineTicket
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil,
      deadlines[identifier]?.ticket == ticket,
      deadlineSchedules[identifier]?.isCurrent(ticket) == true
    else { return }
    deadlines.removeValue(forKey: identifier)
    guard let trackerGeneration = ticket.trackerGeneration else {
      guard echoDeliveries[identifier] == nil else {
        fail(
          failurePhase: .deliveryEvidence,
          failedService: service.failedService,
          reason: .echoRuntimeStateConflict
        )
        return
      }
      finish(
        connection,
        service: service,
        payload: nil,
        bytesSent: 0,
        cancellationMode: ticket.phase.cancellationMode
      )
      return
    }
    guard var delivery = echoDeliveries[identifier] else {
      finish(connection, service: service, payload: nil, bytesSent: 0)
      return
    }
    let decision = delivery.tracker.observeDeadline(generation: trackerGeneration)
    echoDeliveries[identifier] = delivery
    handleEchoDeliveryDecision(
      decision,
      connection: connection,
      service: service,
      payload: delivery.payload,
      bytesSent: delivery.bytesSent
    )
  }

  private func renewConnectionDeadline(
    _ connection: NWConnection,
    service: PeerService,
    phase: PeerConnectionDeadlinePhase
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil,
      var schedule = deadlineSchedules[identifier]
    else { return }
    let ticket = schedule.renew(phase: phase)
    deadlineSchedules[identifier] = schedule
    deadlines.removeValue(forKey: identifier)?.workItem.cancel()
    let workItem = DispatchWorkItem { [weak self, weak connection] in
      Task { @MainActor in
        guard let self, let connection else { return }
        self.handleConnectionDeadline(
          connection,
          service: service,
          ticket: ticket
        )
      }
    }
    deadlines[identifier] = PeerConnectionDeadline(
      ticket: ticket,
      workItem: workItem
    )
    DispatchQueue.main.asyncAfter(
      deadline: .now() + ticket.phase.timeoutSeconds,
      execute: workItem
    )
  }

  private func receive(_ connection: NWConnection, service: PeerService, buffer: Data) {
    let maximum =
      service == .tcpSink
      ? PeerContract.maximumPayloadBytes + 1
      : PeerContract.maximumPayloadBytes + 3
    guard buffer.count < maximum else {
      finish(connection, service: service, payload: nil, bytesSent: 0)
      return
    }
    connection.receive(
      minimumIncompleteLength: 1,
      maximumLength: maximum - buffer.count
    ) { [weak self, weak connection] content, _, complete, error in
      Task { @MainActor in
        guard let self, let connection else { return }
        var next = buffer
        if let content {
          next.append(content)
        }
        if error != nil {
          self.finish(connection, service: service, payload: nil, bytesSent: 0)
          return
        }
        switch PeerStreamProtocol.evaluate(
          service: service,
          buffer: next,
          streamComplete: complete
        ) {
        case .readMore:
          self.receive(connection, service: service, buffer: next)
        case .reject:
          self.finish(connection, service: service, payload: nil, bytesSent: 0)
        case .complete(let payload, let response):
          self.markConnectionPhase(.payloadReceived, connection: connection)
          guard let response else {
            self.finish(connection, service: service, payload: payload, bytesSent: 0)
            return
          }
          let identifier = ObjectIdentifier(connection)
          guard self.echoDeliveries[identifier] == nil else {
            self.finish(connection, service: service, payload: nil, bytesSent: 0)
            return
          }
          let frameByteCount = response.count
          self.echoDeliveries[identifier] = PeerEchoRuntimeState(
            tracker: PeerEchoDeliveryTracker(),
            payload: payload,
            bytesSent: frameByteCount
          )
          connection.stateUpdateHandler = nil
          let callbackGeneration: UInt64 = 0
          self.renewConnectionDeadline(
            connection,
            service: service,
            phase: .connectionProgress(trackerGeneration: callbackGeneration)
          )
          let sendDisposition = PeerEchoSendPlan.echo
          connection.send(
            content: response,
            contentContext: sendDisposition.usesFinalContext
              ? .finalMessage : .defaultMessage,
            isComplete: sendDisposition.completesContext,
            completion: .contentProcessed { [weak self, weak connection] error in
              Task { @MainActor in
                guard let self, let connection else { return }
                self.handleEchoSendCompletion(
                  connection,
                  service: service,
                  payload: payload,
                  bytesSent: frameByteCount,
                  generation: callbackGeneration,
                  succeeded: error == nil
                )
              }
            }
          )
        }
      }
    }
  }

  private func handleEchoSendCompletion(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    generation: UInt64,
    succeeded: Bool
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil,
      var delivery = echoDeliveries[identifier]
    else { return }
    guard delivery.payload == payload, delivery.bytesSent == bytesSent else {
      stateHandler("failed: echo delivery runtime state")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: service.failedService,
        reason: .echoRuntimeStateConflict
      )
      return
    }
    let decision = delivery.tracker.observeEchoSendCompletion(
      generation: generation,
      succeeded: succeeded
    )
    echoDeliveries[identifier] = delivery
    handleEchoDeliveryDecision(
      decision,
      connection: connection,
      service: service,
      payload: payload,
      bytesSent: bytesSent
    )
  }

  private func waitForEchoDeliveryAcknowledgement(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    generation: UInt64
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil, echoDeliveries[identifier] != nil else {
      return
    }
    connection.receive(minimumIncompleteLength: 1, maximumLength: 2) {
      [weak self, weak connection] content, context, _, error in
      Task { @MainActor in
        guard let self, let connection else { return }
        self.handleEchoDeliveryAcknowledgement(
          connection,
          service: service,
          payload: payload,
          bytesSent: bytesSent,
          generation: generation,
          acknowledgement: content ?? Data(),
          failed: error != nil,
          finalContextObserved: PeerAcknowledgementFinalContextPolicy.observed(
            contextIsFinal: context?.isFinal == true
          )
        )
      }
    }
  }

  private func handleEchoDeliveryAcknowledgement(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    generation: UInt64,
    acknowledgement: Data,
    failed: Bool,
    finalContextObserved: Bool
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil,
      var delivery = echoDeliveries[identifier]
    else { return }
    guard delivery.payload == payload, delivery.bytesSent == bytesSent else {
      stateHandler("failed: echo delivery runtime state")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: service.failedService,
        reason: .echoRuntimeStateConflict
      )
      return
    }
    let decision = delivery.tracker.observeDeliveryAcknowledgement(
      generation: generation,
      acknowledgement,
      failed: failed,
      finalContextObserved: finalContextObserved
    )
    echoDeliveries[identifier] = delivery
    handleEchoDeliveryDecision(
      decision,
      connection: connection,
      service: service,
      payload: payload,
      bytesSent: bytesSent
    )
  }

  private func sendEchoDeliveryConfirmation(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    generation: UInt64
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil, echoDeliveries[identifier] != nil else {
      return
    }
    let sendDisposition =
      service == .quicEcho
      ? PeerEchoSendPlan.quicConfirmation : PeerEchoSendPlan.confirmation
    connection.send(
      content: PeerContract.deliveryConfirmation,
      contentContext: sendDisposition.usesFinalContext
        ? .finalMessage : .defaultMessage,
      isComplete: sendDisposition.completesContext,
      completion: .contentProcessed { [weak self, weak connection] error in
        Task { @MainActor in
          guard let self, let connection else { return }
          self.handleEchoDeliveryConfirmationCompletion(
            connection,
            service: service,
            payload: payload,
            bytesSent: bytesSent,
            generation: generation,
            succeeded: error == nil
          )
        }
      }
    )
  }

  private func handleEchoDeliveryConfirmationCompletion(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    generation: UInt64,
    succeeded: Bool
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil,
      var delivery = echoDeliveries[identifier]
    else { return }
    guard delivery.payload == payload, delivery.bytesSent == bytesSent else {
      stateHandler("failed: echo delivery runtime state")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: service.failedService,
        reason: .echoRuntimeStateConflict
      )
      return
    }
    let decision = delivery.tracker.observeDeliveryConfirmationCompletion(
      generation: generation,
      succeeded: succeeded
    )
    echoDeliveries[identifier] = delivery
    handleEchoDeliveryDecision(
      decision,
      connection: connection,
      service: service,
      payload: payload,
      bytesSent: bytesSent
    )
  }

  private func handleEchoDeliveryDecision(
    _ decision: PeerEchoDeliveryDecision,
    connection: NWConnection,
    service: PeerService,
    payload: Data,
    bytesSent: Int
  ) {
    let identifier = ObjectIdentifier(connection)
    switch decision {
    case .waitForDeliveryAcknowledgement(let generation):
      markConnectionPhase(.echoCompleted, connection: connection)
      connection.stateUpdateHandler = nil
      renewConnectionDeadline(
        connection,
        service: service,
        phase: .connectionProgress(trackerGeneration: generation)
      )
      waitForEchoDeliveryAcknowledgement(
        connection,
        service: service,
        payload: payload,
        bytesSent: bytesSent,
        generation: generation
      )
    case .sendDeliveryConfirmation(let generation):
      markConnectionPhase(.acknowledgementReceived, connection: connection)
      renewConnectionDeadline(
        connection,
        service: service,
        phase: .connectionProgress(trackerGeneration: generation)
      )
      markConnectionPhase(.deliveryConfirmationSubmitted, connection: connection)
      sendEchoDeliveryConfirmation(
        connection,
        service: service,
        payload: payload,
        bytesSent: bytesSent,
        generation: generation
      )
    case .ignore:
      break
    case .resolve(let disposition, let confirmationCompletion):
      markConnectionPhase(.deliveryEvidenceObserved, connection: connection)
      if let reason = PeerEchoResolutionGuard.failureReason(
        activeConnectionCount: activeConnections.count,
        targetIsActive: activeConnections[identifier] != nil
      ) {
        stateHandler("failed: echo delivery overlaps another connection")
        fail(
          failurePhase: .deliveryEvidence,
          failedService: service.failedService,
          reason: reason,
          phaseReached: .deliveryEvidenceObserved
        )
        return
      }
      finish(
        connection,
        service: service,
        payload: payload,
        bytesSent: bytesSent,
        evidenceDisposition: disposition,
        deliveryConfirmationCompletion: confirmationCompletion
      )
    case .fail(let reason, let failurePhaseReached):
      stateHandler("failed: echo delivery \(reason.rawValue)")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: service.failedService,
        reason: reason,
        phaseReached: failurePhaseReached
      )
    }
  }

  private func finish(
    _ connection: NWConnection,
    service: PeerService,
    payload: Data?,
    bytesSent: Int,
    evidenceDisposition: PeerEvidenceDisposition? = nil,
    deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion? = nil,
    cancellationMode: PeerConnectionCancellationMode = .graceful
  ) {
    let identifier = ObjectIdentifier(connection)
    guard activeConnections[identifier] != nil else { return }
    let security = securityObservations[identifier]
    if service == .quicEcho,
      cancellationMode == .graceful,
      let payload,
      let security,
      let evidenceDisposition,
      let deliveryConfirmationCompletion
    {
      beginQUICStreamDrain(
        connection,
        payload: payload,
        bytesSent: bytesSent,
        security: security,
        evidenceDisposition: evidenceDisposition,
        deliveryConfirmationCompletion: deliveryConfirmationCompletion
      )
      return
    }

    activeConnections.removeValue(forKey: identifier)
    securityObservations.removeValue(forKey: identifier)
    deadlines.removeValue(forKey: identifier)?.workItem.cancel()
    deadlineSchedules.removeValue(forKey: identifier)
    echoDeliveries.removeValue(forKey: identifier)
    connection.stateUpdateHandler = nil
    switch cancellationMode {
    case .graceful:
      connection.cancel()
    case .immediate:
      connection.forceCancel()
    }
    guard let payload, let security else { return }
    resolveConnectionOutcome(
      service: service,
      payload: payload,
      bytesSent: bytesSent,
      security: security,
      evidenceDisposition: evidenceDisposition,
      deliveryConfirmationCompletion: deliveryConfirmationCompletion
    )
  }

  private func beginQUICStreamDrain(
    _ connection: NWConnection,
    payload: Data,
    bytesSent: Int,
    security: PeerSecurityObservation,
    evidenceDisposition: PeerEvidenceDisposition,
    deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion
  ) {
    let identifier = ObjectIdentifier(connection)
    guard pendingQUICResolution == nil,
      activeConnections[identifier]?.service == .quicEcho,
      quicConnectionGroup != nil,
      quicMultiplexTracker.beginStreamDrain()
    else {
      stateHandler("failed: QUIC stream drain state")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: .quicEcho,
        reason: .echoRuntimeStateConflict
      )
      return
    }
    deadlines.removeValue(forKey: identifier)?.workItem.cancel()
    deadlineSchedules.removeValue(forKey: identifier)
    echoDeliveries.removeValue(forKey: identifier)
    securityObservations.removeValue(forKey: identifier)
    pendingQUICResolution = PeerPendingQUICResolution(
      connection: connection,
      payload: payload,
      bytesSent: bytesSent,
      security: security,
      evidenceDisposition: evidenceDisposition,
      deliveryConfirmationCompletion: deliveryConfirmationCompletion
    )
    connection.stateUpdateHandler = { [weak self, weak connection] state in
      MainActor.assumeIsolated {
        guard let self, let connection else { return }
        self.handleQUICStreamDrainState(state, connection: connection)
      }
    }
    scheduleQUICDrainDeadline()
    // The final 5A context closes the send side. The controlled Mac cancels
    // only after observing exact 5A plus clean EOF; cancelling here would
    // reset the QUIC stream before peer delivery is proven.
  }

  private func handleQUICStreamDrainState(
    _ state: NWConnection.State,
    connection: NWConnection
  ) {
    guard !stopping, !finalized,
      let pendingQUICResolution,
      ObjectIdentifier(pendingQUICResolution.connection) == ObjectIdentifier(connection),
      quicMultiplexTracker.phase == .streamDraining
    else { return }
    switch state {
    case .failed, .cancelled:
      guard let group = quicConnectionGroup else { return }
      beginQUICGroupCancellationAfterStreamTerminal(connection, group: group)
    default:
      break
    }
  }

  private func beginQUICGroupCancellationAfterStreamTerminal(
    _ connection: NWConnection,
    group: NWConnectionGroup
  ) {
    guard quicMultiplexTracker.observeStreamTerminal(),
      activeConnections.removeValue(forKey: ObjectIdentifier(connection)) != nil,
      quicConnectionGroup.map({ ObjectIdentifier($0) }) == ObjectIdentifier(group)
    else {
      stateHandler("failed: QUIC stream cancellation state")
      fail(
        failurePhase: .deliveryEvidence,
        failedService: .quicEcho,
        reason: .echoRuntimeStateConflict
      )
      return
    }
    connection.stateUpdateHandler = nil
    group.cancel()
  }

  private func scheduleQUICDrainDeadline() {
    quicDrainDeadline?.cancel()
    let deadline = DispatchWorkItem { [weak self] in
      Task { @MainActor in
        guard let self, !self.stopping, self.pendingQUICResolution != nil else {
          return
        }
        self.fail(
          failurePhase: .deliveryEvidence,
          failedService: .quicEcho,
          reason: .connectionDeadlineExpired
        )
      }
    }
    quicDrainDeadline = deadline
    DispatchQueue.main.asyncAfter(
      deadline: .now() + PeerContract.connectionProgressDeadlineSeconds,
      execute: deadline
    )
  }

  private func completePendingQUICResolution() {
    guard quicMultiplexTracker.phase == .closed,
      let pending = pendingQUICResolution
    else {
      stateHandler("failed: QUIC tunnel completion state")
      fail(
        failurePhase: .completionValidation,
        failedService: .quicEcho,
        reason: .completionEvidenceInvalid
      )
      return
    }
    pendingQUICResolution = nil
    resolveConnectionOutcome(
      service: .quicEcho,
      payload: pending.payload,
      bytesSent: pending.bytesSent,
      security: pending.security,
      evidenceDisposition: pending.evidenceDisposition,
      deliveryConfirmationCompletion: pending.deliveryConfirmationCompletion
    )
  }

  private func resolveConnectionOutcome(
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    security: PeerSecurityObservation,
    evidenceDisposition: PeerEvidenceDisposition?,
    deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion?
  ) {
    let resolvedDisposition: PeerEvidenceDisposition
    if service == .tcpSink {
      guard evidenceDisposition == nil, deliveryConfirmationCompletion == nil else {
        stateHandler("failed: TCP delivery evidence")
        fail(
          failurePhase: .completionValidation,
          failedService: service.failedService,
          reason: .completionEvidenceInvalid
        )
        return
      }
      resolvedDisposition = .accepted
    } else {
      guard let evidenceDisposition, deliveryConfirmationCompletion != nil else {
        stateHandler("failed: secure delivery evidence")
        fail(
          failurePhase: .completionValidation,
          failedService: service.failedService,
          reason: .completionEvidenceInvalid
        )
        return
      }
      resolvedDisposition = evidenceDisposition
    }
    switch completionTracker.recordResolution(
      service: service,
      payload: payload,
      bytesSent: bytesSent,
      security: security,
      evidenceDisposition: resolvedDisposition,
      deliveryConfirmationCompletion: deliveryConfirmationCompletion,
      peerTerminalObserved: service == .tcpSink,
      deliveryAcknowledgementFinalContextObserved: service != .tcpSink,
      sessionID: session.sessionID
    ) {
    case .continueRunning:
      break
    case .close:
      guard activeConnections.isEmpty else {
        stateHandler("failed: completion overlaps another connection")
        fail(
          failurePhase: .completionValidation,
          failedService: service.failedService,
          reason: .completionOverlap
        )
        return
      }
      markPhaseReached(.completionResolved)
      stopResolved(status: .closed)
    case .pairRequired:
      guard activeConnections.isEmpty else {
        stateHandler("failed: completion overlaps another connection")
        fail(
          failurePhase: .completionValidation,
          failedService: service.failedService,
          reason: .completionOverlap
        )
        return
      }
      markPhaseReached(.completionResolved)
      stopResolved(status: .pairRequired)
    case .fail:
      stateHandler("failed: duplicate or unexpected probe payload")
      fail(
        failurePhase: .completionValidation,
        failedService: service.failedService,
        reason: .completionPayloadInvalid
      )
    }
  }

  private func plainTCPParameters() throws -> NWParameters {
    try plainIPv4WiFiParameters()
  }

  private func tlsParameters() throws -> NWParameters {
    let tls = NWProtocolTLS.Options()
    configureSecurity(tls.securityProtocolOptions, alpn: PeerContract.tlsALPN)
    let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    try configureBaseParameters(parameters)
    return parameters
  }

  private func quicParameters() throws -> NWParameters {
    let quic = NWProtocolQUIC.Options(alpn: [PeerContract.quicALPN])
    quic.direction = .bidirectional
    quic.idleTimeout = Int(PeerContract.connectionProgressDeadlineSeconds * 1_000)
    quic.initialMaxData = 1_024
    quic.initialMaxStreamDataBidirectionalLocal = 256
    quic.initialMaxStreamDataBidirectionalRemote = 256
    quic.initialMaxStreamsBidirectional =
      PeerContract.maximumClientInitiatedBidirectionalQUICStreams
    quic.initialMaxStreamsUnidirectional = 0
    configureSecurity(quic.securityProtocolOptions, alpn: nil)
    let parameters = NWParameters(quic: quic)
    try configureBaseParameters(parameters)
    return parameters
  }

  private func configureBaseParameters(_ parameters: NWParameters) throws {
    try configureIPv4WiFiParameters(parameters)
  }

  private func recordQUICStreamIdentifier(
    _ connection: NWConnection,
    service: PeerService
  ) -> Bool {
    guard service == .quicEcho else { return true }
    guard
      let metadata = connection.metadata(definition: NWProtocolQUIC.definition)
        as? NWProtocolQUIC.Metadata,
      quicMultiplexTracker.observeStreamReady(
        identifier: metadata.streamIdentifier
      )
    else { return false }
    let identifier = ObjectIdentifier(connection)
    guard var record = activeConnections[identifier], record.service == service else {
      return false
    }
    record.quicStreamIdentifier = metadata.streamIdentifier
    activeConnections[identifier] = record
    quicEstablishmentDeadline?.cancel()
    quicEstablishmentDeadline = nil
    return true
  }

  private func markConnectionPhase(
    _ phase: PeerPhaseReached,
    connection: NWConnection
  ) {
    let identifier = ObjectIdentifier(connection)
    guard var record = activeConnections[identifier] else { return }
    if phase.rank > record.phase.rank {
      record.phase = phase
      activeConnections[identifier] = record
    }
    markPhaseReached(phase)
  }

  private func markPhaseReached(_ phase: PeerPhaseReached) {
    if phase.rank > phaseReached.rank {
      phaseReached = phase
    }
  }

  private func configureSecurity(_ options: sec_protocol_options_t, alpn: String?) {
    sec_protocol_options_set_local_identity(options, identity.protocolIdentity)
    sec_protocol_options_set_min_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_max_tls_protocol_version(options, .TLSv13)
    sec_protocol_options_set_tls_tickets_enabled(options, false)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_tls_false_start_enabled(options, false)
    if let alpn {
      sec_protocol_options_add_tls_application_protocol(options, alpn)
    }
  }

  private func expectedSecurityObservation(
    _ connection: NWConnection,
    service: PeerService
  ) -> PeerSecurityObservation? {
    switch service {
    case .tcpSink:
      return PeerSecurityObservation(
        transport: "tcp4",
        tlsVersion: nil,
        cipherSuite: nil,
        alpn: nil,
        earlyDataAccepted: nil
      )
    case .tls13Echo:
      guard
        let metadata = connection.metadata(definition: NWProtocolTLS.definition)
          as? NWProtocolTLS.Metadata
      else {
        return nil
      }
      return expectedSecurityObservation(
        metadata.securityProtocolMetadata,
        transport: "tls13-tcp4",
        alpn: PeerContract.tlsALPN
      )
    case .quicEcho:
      guard
        let metadata = connection.metadata(definition: NWProtocolQUIC.definition)
          as? NWProtocolQUIC.Metadata,
        metadata.negotiatedALPN == PeerContract.quicALPN
      else {
        return nil
      }
      return expectedSecurityObservation(
        metadata.securityProtocolMetadata,
        transport: "quic-tls13",
        alpn: PeerContract.quicALPN
      )
    }
  }

  private func expectedSecurityObservation(
    _ metadata: sec_protocol_metadata_t,
    transport: String,
    alpn: String
  ) -> PeerSecurityObservation? {
    let tlsVersion = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata)
    let earlyDataAccepted = sec_protocol_metadata_get_early_data_accepted(metadata)
    guard
      tlsVersion == .TLSv13,
      !earlyDataAccepted,
      let negotiated = sec_protocol_metadata_get_negotiated_protocol(metadata),
      String(cString: negotiated) == alpn
    else {
      return nil
    }
    let cipher = sec_protocol_metadata_get_negotiated_tls_ciphersuite(metadata).rawValue
    guard (0x1301...0x1305).contains(cipher) else { return nil }
    return PeerSecurityObservation(
      transport: transport,
      tlsVersion: tlsVersion.rawValue,
      cipherSuite: cipher,
      alpn: alpn,
      earlyDataAccepted: earlyDataAccepted
    )
  }
}

@MainActor
public final class LocalNetworkPrimerRuntime {
  public typealias StateHandler = @MainActor (String) -> Void

  private enum Phase {
    case initialized
    case running
    case cancelling
    case finished
    case failed
  }

  private let paths: LocalNetworkPrimerPaths
  private let processID: Int32
  private let stateHandler: StateHandler
  private var phase = Phase.initialized
  private var listener: NWListener?
  private var evidence: LocalNetworkPrimerEvidenceTracker?
  private var network: PeerNetworkReceipt?

  public init(
    paths: LocalNetworkPrimerPaths,
    processID: Int32,
    stateHandler: @escaping StateHandler
  ) {
    self.paths = paths
    self.processID = processID
    self.stateHandler = stateHandler
  }

  public func start(now: Date = Date()) throws {
    guard phase == .initialized, listener == nil else {
      throw PeerContractError.malformed("primer start state")
    }
    guard let port = NWEndpoint.Port(rawValue: PeerContract.primerPort) else {
      throw PeerContractError.malformed("primer listener port")
    }
    let listener = try NWListener(using: plainIPv4WiFiParameters(), on: port)
    var service = NWListener.Service(
      name: PeerContract.primerBonjourName,
      type: PeerContract.primerBonjourType,
      domain: PeerContract.primerBonjourDomain
    )
    service.noAutoRename = true
    listener.service = service
    listener.newConnectionLimit = 1
    listener.newConnectionHandler = { connection in
      connection.cancel()
    }
    listener.stateUpdateHandler = { [weak self] state in
      Task { @MainActor in
        self?.handleListenerState(state)
      }
    }
    listener.serviceRegistrationUpdateHandler = { [weak self] change in
      Task { @MainActor in
        self?.handleServiceRegistration(change)
      }
    }

    try paths.prepareEmptyDirectory()
    evidence = LocalNetworkPrimerEvidenceTracker(startedAt: now)
    self.listener = listener
    phase = .running
    listener.start(queue: .main)
    stateHandler("primer_starting")
  }

  public func stop() {
    switch phase {
    case .initialized:
      phase = .failed
      stateHandler("primer_failed: stopped before start")
    case .running, .cancelling:
      fail("stopped before lifecycle proof")
    case .finished, .failed:
      break
    }
  }

  private func handleListenerState(_ state: NWListener.State) {
    switch state {
    case .ready:
      guard phase == .running else {
        fail("unexpected ready state")
        return
      }
      do {
        network = try PeerNetworkIdentity.currentWiFiIPv4()
        let shouldCancel = try withEvidence { tracker in
          try tracker.observeListenerReady(at: Date())
        }
        stateHandler("primer_listener_ready")
        if shouldCancel {
          beginCancellation()
        }
      } catch {
        fail("listener ready evidence")
      }
    case .waiting:
      guard phase == .running else { return }
      stateHandler("primer_waiting_for_local_network_access")
    case .failed:
      fail("listener failed")
    case .cancelled:
      completeCancellation()
    case .setup:
      break
    @unknown default:
      fail("unknown listener state")
    }
  }

  private func handleServiceRegistration(_ change: NWListener.ServiceRegistrationChange) {
    switch change {
    case .add(let endpoint):
      guard phase == .running, isExpectedPrimerService(endpoint) else {
        fail("service registration identity")
        return
      }
      do {
        let shouldCancel = try withEvidence { tracker in
          try tracker.observeServiceRegistered(at: Date())
        }
        stateHandler("primer_service_registered")
        if shouldCancel {
          beginCancellation()
        }
      } catch {
        fail("service registration evidence")
      }
    case .remove:
      guard phase == .cancelling || phase == .finished || phase == .failed else {
        fail("unexpected service removal")
        return
      }
    @unknown default:
      fail("unknown service registration state")
    }
  }

  private func beginCancellation() {
    guard phase == .running, evidence?.canCancel == true else {
      fail("primer cancellation state")
      return
    }
    phase = .cancelling
    listener?.cancel()
  }

  private func completeCancellation() {
    guard phase == .cancelling, let network else {
      if phase != .failed {
        fail("listener cancelled without proof")
      }
      listener = nil
      return
    }
    do {
      try withEvidence { tracker in
        try tracker.observeListenerCancelled(at: Date())
      }
      guard let evidence, evidence.isProven,
        let serviceRegisteredAt = evidence.serviceRegisteredAt,
        let listenerReadyAt = evidence.listenerReadyAt,
        let listenerCancelledAt = evidence.listenerCancelledAt
      else {
        throw PeerContractError.malformed("primer lifecycle evidence")
      }
      let receipt = LocalNetworkPrimerReceipt(
        schemaVersion: PeerContract.schemaVersion,
        document: PeerContract.primerResultDocument,
        mode: PeerContract.primerMode,
        claimEligible: false,
        bundleIdentifier: PeerContract.bundleIdentifier,
        processID: processID,
        startedAt: PeerSession.timestamp(evidence.startedAt),
        serviceRegisteredAt: PeerSession.timestamp(serviceRegisteredAt),
        listenerReadyAt: PeerSession.timestamp(listenerReadyAt),
        listenerCancelledAt: PeerSession.timestamp(listenerCancelledAt),
        serviceRegistered: true,
        listenerReady: true,
        listenerCancelled: true,
        network: network,
        listener: .fixed
      )
      try receipt.validate()
      try paths.writeResult(receipt)
      phase = .finished
      listener = nil
      stateHandler("primer_closed")
    } catch {
      fail("primer result receipt")
      listener = nil
    }
  }

  private func withEvidence<T>(
    _ body: (inout LocalNetworkPrimerEvidenceTracker) throws -> T
  ) throws -> T {
    guard var evidence else {
      throw PeerContractError.malformed("primer evidence state")
    }
    let result = try body(&evidence)
    self.evidence = evidence
    return result
  }

  private func fail(_ reason: String) {
    guard phase != .finished, phase != .failed else { return }
    phase = .failed
    listener?.cancel()
    stateHandler("primer_failed: \(reason)")
  }

  private func isExpectedPrimerService(_ endpoint: NWEndpoint) -> Bool {
    guard
      case .service(let name, let type, let domain, _) = endpoint
    else {
      return false
    }
    return name == PeerContract.primerBonjourName
      && type == PeerContract.primerBonjourType
      && domain == PeerContract.primerBonjourDomain
  }
}

func plainIPv4WiFiParameters() throws -> NWParameters {
  let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
  try configureIPv4WiFiParameters(parameters)
  return parameters
}

func configureIPv4WiFiParameters(_ parameters: NWParameters) throws {
  guard
    let internetProtocol = parameters.defaultProtocolStack.internetProtocol
      as? NWProtocolIP.Options
  else {
    throw PeerContractError.malformed("IPv4 protocol stack")
  }
  internetProtocol.version = .v4
  parameters.defaultProtocolStack.internetProtocol = internetProtocol
  parameters.requiredInterfaceType = .wifi
  parameters.includePeerToPeer = false
  parameters.allowLocalEndpointReuse = false
}
