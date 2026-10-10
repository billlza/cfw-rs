import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

@Suite("Transport peer lifecycle and Mac probe contract")
struct PeerLifecycleAndMacProbeTests {
  private let now = Date(timeIntervalSince1970: 1_777_777_777.123456)
  private let certificateBase64 =
    "MIIBpDCCAUugAwIBAgIRAIJmU/PReubzdNEdfW86lXQwCgYIKoZIzj0EAwIwJTEjMCEGA1UE"
    + "AxMaY2ZtLXRyYW5zcG9ydC1wZWVyLmludmFsaWQwHhcNMjYwODIxMDE0MzIzWhcNMjYwODIx"
    + "MDE1ODUzWjAlMSMwIQYDVQQDExpjZm0tdHJhbnNwb3J0LXBlZXIuaW52YWxpZDBZMBMGByqG"
    + "SM49AgEGCCqGSM49AwEHA0IABHMEtLyIe8Va4kaRYfq3x7UfRnCVJhyKF6AU3zZCOiISKQlW"
    + "necIP95a6Lgw1VArjI3QbtYTDq6fXpCO4HtejRGjXDBaMA4GA1UdDwEB/wQEAwIHgDATBgNV"
    + "HSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMCUGA1UdEQQeMByCGmNmbS10cmFuc3Bv"
    + "cnQtcGVlci5pbnZhbGlkMAoGCCqGSM49BAMCA0cAMEQCIBaz/1qTGNQqjbJUUSIo8AUCAOno"
    + "JfGtsFBHgHZNt6NXAiBdmFpSvTdmtd+JPqPQyrAPfQdtW/WMXw96H6A245wHxw=="

  private func securityObservation(for service: PeerService) -> PeerSecurityObservation {
    switch service {
    case .tcpSink:
      PeerSecurityObservation(
        transport: "tcp4",
        tlsVersion: nil,
        cipherSuite: nil,
        alpn: nil,
        earlyDataAccepted: nil
      )
    case .tls13Echo:
      PeerSecurityObservation(
        transport: "tls13-tcp4",
        tlsVersion: 0x0304,
        cipherSuite: 0x1301,
        alpn: PeerContract.tlsALPN,
        earlyDataAccepted: false
      )
    case .quicEcho:
      PeerSecurityObservation(
        transport: "quic-tls13",
        tlsVersion: 0x0304,
        cipherSuite: 0x1301,
        alpn: PeerContract.quicALPN,
        earlyDataAccepted: false
      )
    }
  }

  private func preparedDeliveryTracker() -> PeerEchoDeliveryTracker {
    var tracker = PeerEchoDeliveryTracker()
    #expect(
      tracker.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      tracker.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .sendDeliveryConfirmation(generation: 2)
    )
    #expect(tracker.callbackGeneration == 2)
    return tracker
  }

  private func recordAccepted(
    _ service: PeerService,
    in tracker: inout PeerCompletionTracker,
    sessionID: String
  ) throws -> PeerCompletionDecision {
    precondition(service == .tcpSink)
    let payload = try PeerProbePayload.payload(for: service, sessionID: sessionID)
    return tracker.recordResolution(
      service: service,
      payload: payload,
      bytesSent: service == .tcpSink ? 0 : payload.count + 2,
      security: securityObservation(for: service),
      evidenceDisposition: .accepted,
      deliveryConfirmationCompletion: nil,
      peerTerminalObserved: true,
      deliveryAcknowledgementFinalContextObserved: false,
      sessionID: sessionID
    )
  }

  private func recordPairRequired(
    _ service: PeerService,
    completion: PeerDeliveryConfirmationCompletion,
    in tracker: inout PeerCompletionTracker,
    sessionID: String
  ) throws -> PeerCompletionDecision {
    let payload = try PeerProbePayload.payload(for: service, sessionID: sessionID)
    return tracker.recordResolution(
      service: service,
      payload: payload,
      bytesSent: payload.count + 2,
      security: securityObservation(for: service),
      evidenceDisposition: .pairRequired,
      deliveryConfirmationCompletion: completion,
      peerTerminalObserved: false,
      deliveryAcknowledgementFinalContextObserved: true,
      sessionID: sessionID
    )
  }

  private func serverResult(
    status: PeerResultStatus,
    failurePhase: PeerFailurePhase = .none,
    outcomes: ConnectionOutcomes,
    listenersClosed: Bool = true,
    schemaVersion: Int = PeerContract.resultSchemaVersion,
    document: String = PeerContract.resultDocument,
    failedService: PeerFailedService? = nil,
    failureReason: PeerFailureReason? = nil,
    phaseReached: PeerPhaseReached? = nil,
    blockingService: PeerFailedService? = nil,
    blockingPhase: PeerPhaseReached? = nil,
    blockingAdmissionSequence: Int? = nil,
    incomingAdmissionSequence: Int? = nil,
    incomingMatchesBlockerObject: Bool? = nil,
    blockingQUICStreamIdentifier: UInt64? = nil
  ) -> ResultReceipt {
    let failed = status == .failed
    return ResultReceipt(
      schemaVersion: schemaVersion,
      document: document,
      evidenceRole: PeerContract.resultEvidenceRole,
      claimEligible: false,
      sessionID: String(repeating: "1", count: 64),
      certificateSHA256: String(repeating: "2", count: 64),
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      completedAt: PeerSession.timestamp(now),
      status: status,
      failurePhase: failurePhase,
      failedService: failedService ?? (failed ? .runtime : .none),
      failureReason: failureReason ?? (failed ? .applicationLifecycleRequested : .none),
      phaseReached: phaseReached ?? (failed ? .applicationStarted : .completed),
      blockingService: blockingService,
      blockingPhase: blockingPhase,
      blockingAdmissionSequence: blockingAdmissionSequence,
      incomingAdmissionSequence: incomingAdmissionSequence,
      incomingMatchesBlockerObject: incomingMatchesBlockerObject,
      blockingQUICStreamIdentifier: blockingQUICStreamIdentifier,
      listenersClosed: listenersClosed,
      identityFilesRemoved: true,
      connections: outcomes
    )
  }

  @Test("iOS input directory accepts exactly the three canonical inputs")
  func exactPeerInputInventory() throws {
    try withPrivateTemporaryDirectory { documents in
      let paths = try PeerPaths(documentsDirectory: documents)
      try FileManager.default.createDirectory(
        at: paths.directory,
        withIntermediateDirectories: false
      )
      try setMode(0o700, for: paths.directory)
      try writePrivate(Data("session".utf8), to: paths.session)
      try writePrivate(Data("certificate".utf8), to: paths.certificate)
      try writePrivate(Data("private key".utf8), to: paths.privateKey)

      try paths.validateCleanInputs()

      let unexpected = paths.directory.appendingPathComponent(".unexpected")
      try writePrivate(Data([0x01]), to: unexpected)
      #expect(throws: PeerContractError.self) {
        try paths.validateCleanInputs()
      }
    }
  }

  @Test("service evidence resolves only after one exact outcome per service")
  func exactServiceCompletion() throws {
    let sessionID = String(repeating: "1", count: 64)
    var tracker = PeerCompletionTracker()

    #expect(try recordAccepted(.tcpSink, in: &tracker, sessionID: sessionID) == .continueRunning)
    #expect(
      try recordPairRequired(
        .tls13Echo,
        completion: .processed,
        in: &tracker,
        sessionID: sessionID
      ) == .continueRunning
    )
    #expect(
      try recordPairRequired(
        .quicEcho,
        completion: .processed,
        in: &tracker,
        sessionID: sessionID
      ) == .pairRequired
    )

    #expect(!tracker.allServicesAccepted)
    #expect(tracker.resolvedStatus == .pairRequired)
    #expect(tracker.outcomes.tcpSink.accepted == 1)
    #expect(tracker.outcomes.tls13Echo.accepted == 0)
    #expect(tracker.outcomes.quicEcho.accepted == 0)
    #expect(tracker.outcomes.tcpSink.deliveryConfirmationCompletion == nil)
    #expect(tracker.outcomes.tls13Echo.deliveryConfirmationCompletion == .processed)
    #expect(!tracker.outcomes.quicEcho.peerTerminalObserved)
    #expect(tracker.outcomes.quicEcho.deliveryAcknowledgementFinalContextObserved)
    let receipt = serverResult(status: .pairRequired, outcomes: tracker.outcomes)
    try receipt.validate()
    let object = try #require(
      JSONSerialization.jsonObject(with: ExactJSON.encode(receipt).dropLast())
        as? [String: Any]
    )
    #expect(object["status"] as? String == "pair_required")
    #expect(object["failure_phase"] as? String == "none")
  }

  @Test("echo completion and authoritative peer terminal order resolve deterministically")
  func echoDeliveryCompletionRace() {
    #expect(PeerContract.deliveryAcknowledgement == Data([0xA5]))
    #expect(PeerContract.deliveryConfirmation == Data([0x5A]))
    #expect(PeerContract.deliveryAcknowledgementHex == "a5")
    #expect(PeerContract.deliveryConfirmationHex == "5a")
    #expect(
      PeerEchoSendPlan.echo
        == PeerEchoSendDisposition(usesFinalContext: false, completesContext: true)
    )
    #expect(
      PeerEchoSendPlan.confirmation
        == PeerEchoSendDisposition(usesFinalContext: false, completesContext: true)
    )
    #expect(
      PeerEchoSendPlan.quicConfirmation
        == PeerEchoSendDisposition(usesFinalContext: true, completesContext: true)
    )
    var processedAfterTerminal = preparedDeliveryTracker()
    #expect(
      processedAfterTerminal.observeDeliveryConfirmationCompletion(
        generation: 2,
        succeeded: true
      )
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .processed
        )
    )

    var failedAfterTerminal = preparedDeliveryTracker()
    #expect(
      failedAfterTerminal.observeDeliveryConfirmationCompletion(
        generation: 2,
        succeeded: false
      )
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .failed
        )
    )

    var deadlineAfterTerminal = preparedDeliveryTracker()
    #expect(
      deadlineAfterTerminal.observeDeadline(generation: 2)
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .unobserved
        )
    )

    var acknowledgementWithoutFinalContext = PeerEchoDeliveryTracker()
    #expect(
      acknowledgementWithoutFinalContext.observeEchoSendCompletion(
        generation: 0,
        succeeded: true
      ) == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      acknowledgementWithoutFinalContext.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: false
      )
        == .fail(
          reason: .acknowledgementNotFinal,
          phaseReached: .echoCompleted
        )
    )

    var failedSend = PeerEchoDeliveryTracker()
    #expect(
      failedSend.observeEchoSendCompletion(generation: 0, succeeded: false)
        == .fail(reason: .echoSendFailed, phaseReached: .payloadReceived)
    )
    var outOfOrder = PeerEchoDeliveryTracker()
    #expect(
      outOfOrder.observeDeliveryAcknowledgement(
        generation: 0,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      )
        == .fail(
          reason: .deliveryCallbackOutOfOrder,
          phaseReached: .payloadReceived
        )
    )

    var failedAcknowledgement = PeerEchoDeliveryTracker()
    #expect(
      failedAcknowledgement.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1))
    #expect(
      failedAcknowledgement.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: true,
        finalContextObserved: true
      )
        == .fail(
          reason: .acknowledgementReceiveFailed,
          phaseReached: .echoCompleted
        )
    )

    var wrongAcknowledgement = PeerEchoDeliveryTracker()
    #expect(
      wrongAcknowledgement.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1))
    #expect(
      wrongAcknowledgement.observeDeliveryAcknowledgement(
        generation: 1,
        Data([0x00]),
        failed: false,
        finalContextObserved: true
      )
        == .fail(reason: .acknowledgementInvalid, phaseReached: .echoCompleted)
    )
  }

  @Test("delivery callback generations reject stale and future events")
  func deliveryCallbackGenerations() {
    var tracker = PeerEchoDeliveryTracker()
    #expect(tracker.callbackGeneration == 0)
    #expect(
      tracker.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(tracker.callbackGeneration == 1)
    #expect(tracker.observeDeadline(generation: 0) == .ignore)
    #expect(
      tracker.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .sendDeliveryConfirmation(generation: 2)
    )
    #expect(tracker.callbackGeneration == 2)
    #expect(tracker.observeDeadline(generation: 1) == .ignore)

    var futureCallback = PeerEchoDeliveryTracker()
    #expect(
      futureCallback.observeEchoSendCompletion(generation: 1, succeeded: true)
        == .fail(
          reason: .deliveryCallbackOutOfOrder,
          phaseReached: .payloadReceived
        )
    )
  }

  @Test("deadline tokens renew independently across every progress phase")
  func independentDeadlineTokens() {
    let progressTimes: [TimeInterval] = [0, 6, 12, 18, 24]
    let phases: [PeerConnectionDeadlinePhase] = [
      .connectionProgress(trackerGeneration: nil),
      .connectionProgress(trackerGeneration: nil),
      .connectionProgress(trackerGeneration: 0),
      .connectionProgress(trackerGeneration: 1),
      .connectionProgress(trackerGeneration: 2),
    ]
    var schedule = PeerConnectionDeadlineSchedule()
    var tickets: [PeerConnectionDeadlineTicket] = []

    for index in progressTimes.indices {
      if index > progressTimes.startIndex {
        #expect(
          progressTimes[index] - progressTimes[index - 1]
            < PeerContract.connectionProgressDeadlineSeconds
        )
      }
      let ticket = schedule.renew(phase: phases[index])
      tickets.append(ticket)
      #expect(schedule.isCurrent(ticket))
      for stale in tickets.dropLast() {
        #expect(!schedule.isCurrent(stale))
      }
    }

    #expect(
      progressTimes[progressTimes.index(before: progressTimes.endIndex)]
        - progressTimes[progressTimes.startIndex]
        > PeerContract.connectionProgressDeadlineSeconds
    )
    #expect(tickets.map(\.token) == [1, 2, 3, 4, 5])
    #expect(tickets.map(\.phase) == phases)
    #expect(tickets.map(\.trackerGeneration) == [nil, nil, 0, 1, 2])
    #expect(Set(tickets.map(\.token)).count == tickets.count)
  }

  @Test("deadlines immediately cancel connections before delivery tracking")
  func deadlineCancellationModes() {
    #expect(
      PeerConnectionDeadlinePhase.preSecurityHandshake.cancellationMode == .immediate
    )
    #expect(
      PeerConnectionDeadlinePhase.connectionProgress(trackerGeneration: nil)
        .cancellationMode == .immediate
    )
    #expect(
      PeerConnectionDeadlinePhase.connectionProgress(trackerGeneration: 0)
        .cancellationMode == .graceful
    )
  }

  @Test("security-ready renewal invalidates the shorter handshake lease")
  func securityReadyInvalidatesHandshakeDeadline() {
    var schedule = PeerConnectionDeadlineSchedule()
    let handshake = schedule.renew(phase: .preSecurityHandshake)
    #expect(schedule.isCurrent(handshake))
    #expect(
      handshake.phase.timeoutSeconds == PeerContract.preSecurityHandshakeDeadlineSeconds
    )

    let progress = schedule.renew(
      phase: .connectionProgress(trackerGeneration: nil)
    )
    #expect(!schedule.isCurrent(handshake))
    #expect(schedule.isCurrent(progress))
    #expect(
      progress.phase.timeoutSeconds == PeerContract.connectionProgressDeadlineSeconds
    )
  }

  @Test("duplicate and late evidence callbacks are idempotent but conflicts fail typed")
  func duplicateAndConflictingDeliveryCallbacks() {
    var conflictBeforeResolution = preparedDeliveryTracker()
    #expect(
      conflictBeforeResolution.observeDeliveryConfirmationCompletion(
        generation: 2,
        succeeded: true
      )
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .processed
        )
    )
    #expect(
      conflictBeforeResolution.observeDeliveryConfirmationCompletion(
        generation: 2,
        succeeded: false
      )
        == .fail(
          reason: .deliveryCallbackConflict,
          phaseReached: .deliveryEvidenceObserved
        )
    )

    var tracker = preparedDeliveryTracker()
    #expect(
      tracker.observeDeliveryConfirmationCompletion(generation: 2, succeeded: true)
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .processed
        )
    )
    #expect(
      tracker.observeDeliveryConfirmationCompletion(generation: 2, succeeded: true)
        == .ignore
    )
    #expect(tracker.observeDeadline(generation: 2) == .ignore)
    #expect(
      tracker.observeDeliveryConfirmationCompletion(generation: 2, succeeded: false)
        == .fail(
          reason: .deliveryCallbackConflict,
          phaseReached: .deliveryEvidenceObserved
        )
    )
  }

  @Test("final acknowledgement context is required before confirmation")
  func finalAcknowledgementContextIsRequired() {
    #expect(PeerAcknowledgementFinalContextPolicy.observed(contextIsFinal: true))
    #expect(!PeerAcknowledgementFinalContextPolicy.observed(contextIsFinal: false))
    var tracker = PeerEchoDeliveryTracker()
    #expect(
      tracker.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      tracker.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .sendDeliveryConfirmation(generation: 2)
    )
    #expect(
      tracker.observeDeliveryConfirmationCompletion(generation: 2, succeeded: true)
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .processed
        )
    )

    var missingFinalContext = PeerEchoDeliveryTracker()
    #expect(
      missingFinalContext.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      missingFinalContext.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: false
      )
        == .fail(
          reason: .acknowledgementNotFinal,
          phaseReached: .echoCompleted
        )
    )

    for invalidAcknowledgement in [
      Data(),
      PeerContract.deliveryAcknowledgement + Data([0x00]),
    ] {
      var invalid = PeerEchoDeliveryTracker()
      #expect(
        invalid.observeEchoSendCompletion(generation: 0, succeeded: true)
          == .waitForDeliveryAcknowledgement(generation: 1)
      )
      #expect(
        invalid.observeDeliveryAcknowledgement(
          generation: 1,
          invalidAcknowledgement,
          failed: false,
          finalContextObserved: true
        )
          == .fail(
            reason: .acknowledgementInvalid,
            phaseReached: .echoCompleted
          )
      )
    }

    var stale = PeerEchoDeliveryTracker()
    #expect(
      stale.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      stale.observeDeliveryAcknowledgement(
        generation: 0,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .ignore
    )
    #expect(
      stale.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: false
      )
        == .fail(
          reason: .acknowledgementNotFinal,
          phaseReached: .echoCompleted
        )
    )

    var staleConfirmationCompletion = PeerEchoDeliveryTracker()
    #expect(
      staleConfirmationCompletion.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      staleConfirmationCompletion.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .sendDeliveryConfirmation(generation: 2)
    )
    #expect(
      staleConfirmationCompletion.observeDeliveryConfirmationCompletion(
        generation: 1,
        succeeded: true
      ) == .ignore
    )
    #expect(
      staleConfirmationCompletion.observeDeadline(generation: 2)
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .unobserved
        )
    )
  }

  @Test("final acknowledgement remains admission blocking through confirmation")
  func finalAcknowledgementAdmissionOrdering() {
    var tracker = PeerEchoDeliveryTracker()
    #expect(
      tracker.observeEchoSendCompletion(generation: 0, succeeded: true)
        == .waitForDeliveryAcknowledgement(generation: 1)
    )
    #expect(
      tracker.observeDeliveryAcknowledgement(
        generation: 1,
        PeerContract.deliveryAcknowledgement,
        failed: false,
        finalContextObserved: true
      ) == .sendDeliveryConfirmation(generation: 2)
    )
    #expect(
      PeerConnectionAdmissionGuard.failureReason(activeConnectionCount: 1)
        == .connectionAdmissionOverlap
    )
    #expect(
      tracker.observeDeliveryConfirmationCompletion(generation: 2, succeeded: true)
        == .resolve(
          disposition: .pairRequired,
          confirmationCompletion: .processed
        )
    )
    #expect(
      PeerConnectionAdmissionGuard.failureReason(activeConnectionCount: 1)
        == .connectionAdmissionOverlap
    )
    #expect(PeerConnectionAdmissionGuard.failureReason(activeConnectionCount: 0) == nil)
  }

  @Test("overlap guard fails before any accepted outcome is recorded")
  func overlapGuard() {
    let tracker = PeerCompletionTracker()
    #expect(
      PeerEchoResolutionGuard.failureReason(
        activeConnectionCount: 2,
        targetIsActive: true
      ) == .connectionOverlap
    )
    #expect(
      PeerEchoResolutionGuard.failureReason(
        activeConnectionCount: 1,
        targetIsActive: false
      ) == .connectionOverlap
    )
    #expect(
      PeerEchoResolutionGuard.failureReason(
        activeConnectionCount: 1,
        targetIsActive: true
      ) == nil
    )
    #expect(tracker.outcomes == ConnectionOutcomes())
  }

  @Test("connection admission overlap is sticky and typed")
  func connectionAdmissionOverlapIsTyped() throws {
    #expect(PeerConnectionAdmissionGuard.failureReason(activeConnectionCount: 0) == nil)
    #expect(
      PeerConnectionAdmissionGuard.failureReason(activeConnectionCount: 1)
        == .connectionAdmissionOverlap
    )

    let failed = serverResult(
      status: .failed,
      failurePhase: .connectionAdmission,
      outcomes: ConnectionOutcomes(),
      listenersClosed: false,
      failedService: .tls13Echo,
      failureReason: .connectionAdmissionOverlap,
      phaseReached: .securityReady,
      blockingService: .tcpSink,
      blockingPhase: .securityReady,
      blockingAdmissionSequence: 1,
      incomingAdmissionSequence: 2,
      incomingMatchesBlockerObject: false
    )
    try failed.validate()
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .deliveryEvidence,
        outcomes: ConnectionOutcomes(),
        listenersClosed: false,
        failedService: .tls13Echo,
        failureReason: .connectionAdmissionOverlap,
        phaseReached: .securityReady,
        blockingService: .tcpSink,
        blockingPhase: .securityReady,
        blockingAdmissionSequence: 1,
        incomingAdmissionSequence: 2,
        incomingMatchesBlockerObject: false
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .connectionAdmission,
        outcomes: ConnectionOutcomes(),
        listenersClosed: false,
        failedService: .quicEcho,
        failureReason: .connectionAdmissionOverlap,
        phaseReached: .deliveryEvidenceObserved
      ).validate()
    }
  }

  @Test("pair-required resolution preserves full evidence without local acceptance")
  func pairRequiredServiceCompletion() throws {
    let sessionID = String(repeating: "1", count: 64)
    var tracker = PeerCompletionTracker()
    #expect(try recordAccepted(.tcpSink, in: &tracker, sessionID: sessionID) == .continueRunning)
    #expect(
      try recordPairRequired(
        .tls13Echo,
        completion: .failed,
        in: &tracker,
        sessionID: sessionID
      ) == .continueRunning
    )
    #expect(
      try recordPairRequired(
        .quicEcho,
        completion: .processed,
        in: &tracker,
        sessionID: sessionID
      ) == .pairRequired
    )
    #expect(tracker.resolvedStatus == .pairRequired)
    #expect(!tracker.allServicesAccepted)
    #expect(tracker.outcomes.tls13Echo.accepted == 0)
    #expect(tracker.outcomes.tls13Echo.evidenceDisposition == .pairRequired)
    #expect(tracker.outcomes.tls13Echo.bytesReceived == 32)
    #expect(tracker.outcomes.tls13Echo.bytesSent == 34)
    #expect(tracker.outcomes.tls13Echo.controlBytesReceived == 1)
    #expect(tracker.outcomes.tls13Echo.controlBytesSubmitted == 1)
    #expect(tracker.outcomes.tls13Echo.deliveryConfirmationCompletion == .failed)
    #expect(!tracker.outcomes.tls13Echo.peerTerminalObserved)
    #expect(tracker.outcomes.tls13Echo.deliveryAcknowledgementFinalContextObserved)
  }

  @Test("server result v5 keeps pair-required evidence non-claimable and canonical")
  func serverResultV5() throws {
    let sessionID = String(repeating: "1", count: 64)
    var tracker = PeerCompletionTracker()
    _ = try recordAccepted(.tcpSink, in: &tracker, sessionID: sessionID)
    _ = try recordPairRequired(
      .tls13Echo,
      completion: .unobserved,
      in: &tracker,
      sessionID: sessionID
    )
    #expect(
      try recordPairRequired(
        .quicEcho,
        completion: .processed,
        in: &tracker,
        sessionID: sessionID
      ) == .pairRequired
    )

    let receipt = serverResult(status: .pairRequired, outcomes: tracker.outcomes)
    try receipt.validate()
    let canonical = try ExactJSON.encode(receipt)
    let object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    #expect(object["schema_version"] as? Int == 5)
    #expect(object["document"] as? String == "cfm-ios-transport-peer-result-v5")
    #expect(object["evidence_role"] as? String == "server_observation_only")
    #expect(object["claim_eligible"] as? Bool == false)
    #expect(object["status"] as? String == "pair_required")
    #expect(object["failure_phase"] as? String == "none")
    #expect(object["failed_service"] as? String == "none")
    #expect(object["failure_reason"] as? String == "none")
    #expect(object["phase_reached"] as? String == "completed")
    #expect(object["blocking_service"] is NSNull)
    #expect(object["blocking_phase"] is NSNull)
    #expect(object["blocking_admission_sequence"] is NSNull)
    #expect(object["incoming_admission_sequence"] is NSNull)
    #expect(object["incoming_matches_blocker_object"] is NSNull)
    #expect(object["blocking_quic_stream_identifier"] is NSNull)
    let connections = try #require(object["connections"] as? [String: Any])
    let tls = try #require(connections["tls13_echo"] as? [String: Any])
    #expect(tls["accepted"] as? Int == 0)
    #expect(tls["evidence_disposition"] as? String == "pair_required")
    #expect(tls["delivery_confirmation_completion"] as? String == "unobserved")
    #expect(tls["peer_terminal_observed"] as? Bool == false)
    #expect(tls["delivery_acknowledgement_final_context_observed"] as? Bool == true)
    #expect(tls["control_bytes_submitted"] as? Int == 1)
    #expect(tls["control_bytes_sent"] == nil)

    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .none,
        outcomes: tracker.outcomes
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(status: .closed, outcomes: tracker.outcomes).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .pairRequired,
        outcomes: tracker.outcomes,
        schemaVersion: 2,
        document: "cfm-ios-transport-peer-result-v2"
      ).validate()
    }

    let failed = serverResult(
      status: .failed,
      failurePhase: .deliveryEvidence,
      outcomes: ConnectionOutcomes(),
      listenersClosed: false,
      failedService: .quicEcho,
      failureReason: .unexpectedTrailingBytes,
      phaseReached: .deliveryConfirmationSubmitted
    )
    try failed.validate()
    let failedObject = try #require(
      JSONSerialization.jsonObject(with: ExactJSON.encode(failed).dropLast())
        as? [String: Any]
    )
    #expect(failedObject["failure_phase"] as? String == "delivery_evidence")
    #expect(failedObject["failed_service"] as? String == "quic_echo")
    #expect(failedObject["failure_reason"] as? String == "unexpected_trailing_bytes")
    #expect(
      failedObject["phase_reached"] as? String == "delivery_confirmation_submitted"
    )

    let acknowledgementNotFinal = serverResult(
      status: .failed,
      failurePhase: .deliveryEvidence,
      outcomes: ConnectionOutcomes(),
      listenersClosed: false,
      failedService: .tls13Echo,
      failureReason: .acknowledgementNotFinal,
      phaseReached: .echoCompleted
    )
    try acknowledgementNotFinal.validate()
    var arbitraryFailureObject = failedObject
    arbitraryFailureObject["failure_reason"] = "arbitrary network error text"
    let arbitraryFailureData = try JSONSerialization.data(
      withJSONObject: arbitraryFailureObject,
      options: [.sortedKeys]
    )
    #expect(throws: DecodingError.self) {
      try JSONDecoder().decode(ResultReceipt.self, from: arbitraryFailureData)
    }

    try serverResult(
      status: .failed,
      failurePhase: .completionValidation,
      outcomes: ConnectionOutcomes(),
      failedService: .runtime,
      failureReason: .completionEvidenceInvalid,
      phaseReached: .completionResolved
    ).validate()

    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .deliveryEvidence,
        outcomes: ConnectionOutcomes(),
        failedService: PeerFailedService.none,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .failed,
        failurePhase: .deliveryEvidence,
        outcomes: ConnectionOutcomes(),
        failedService: .runtime,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
    #expect(throws: PeerContractError.self) {
      try serverResult(
        status: .pairRequired,
        outcomes: tracker.outcomes,
        failedService: .quicEcho,
        failureReason: .unexpectedTrailingBytes,
        phaseReached: .deliveryConfirmationSubmitted
      ).validate()
    }
  }

  @Test("result v5 fixture is shared with the Python validator")
  func sharedResultV5Fixture() throws {
    let packageRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let fixture =
      packageRoot
      .appendingPathComponent("Fixtures", isDirectory: true)
      .appendingPathComponent("result-v5-pair-required.json")
    let data = try Data(contentsOf: fixture)
    let receipt = try JSONDecoder().decode(ResultReceipt.self, from: data)
    try receipt.validate()
    #expect(receipt.status == .pairRequired)
    #expect(receipt.connections.quicEcho.evidenceDisposition == .pairRequired)
    #expect(try ExactJSON.encode(receipt) == data)
  }

  @Test("legacy server result v4 is rejected by the v5 model")
  func legacyServerResultV4Rejected() throws {
    let packageRoot = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let fixture =
      packageRoot
      .appendingPathComponent("Fixtures", isDirectory: true)
      .appendingPathComponent("result-v4-pair-required.json")
    let data = try Data(contentsOf: fixture)
    let legacy = try JSONDecoder().decode(ResultReceipt.self, from: data)
    #expect(throws: PeerContractError.self) {
      try legacy.validate()
    }
  }

  @Test("duplicate, wrong-payload, and wrong-byte successes fail closed")
  func invalidServiceCompletion() throws {
    let sessionID = String(repeating: "1", count: 64)
    let payload = try PeerProbePayload.payload(for: .tls13Echo, sessionID: sessionID)
    var duplicate = PeerCompletionTracker()
    #expect(
      duplicate.recordResolution(
        service: .tls13Echo,
        payload: payload,
        bytesSent: payload.count + 2,
        security: securityObservation(for: .tls13Echo),
        evidenceDisposition: .pairRequired,
        deliveryConfirmationCompletion: .processed,
        peerTerminalObserved: false,
        deliveryAcknowledgementFinalContextObserved: true,
        sessionID: sessionID
      ) == .continueRunning
    )
    #expect(
      duplicate.recordResolution(
        service: .tls13Echo,
        payload: payload,
        bytesSent: payload.count + 2,
        security: securityObservation(for: .tls13Echo),
        evidenceDisposition: .pairRequired,
        deliveryConfirmationCompletion: .processed,
        peerTerminalObserved: false,
        deliveryAcknowledgementFinalContextObserved: true,
        sessionID: sessionID
      ) == .fail
    )

    var wrongPayload = PeerCompletionTracker()
    #expect(
      wrongPayload.recordResolution(
        service: .tcpSink,
        payload: Data(repeating: 0, count: 32),
        bytesSent: 0,
        security: securityObservation(for: .tcpSink),
        evidenceDisposition: .accepted,
        deliveryConfirmationCompletion: nil,
        peerTerminalObserved: true,
        deliveryAcknowledgementFinalContextObserved: false,
        sessionID: sessionID
      ) == .fail
    )
    #expect(wrongPayload.outcomes.tcpSink.accepted == 0)

    var wrongByteCount = PeerCompletionTracker()
    #expect(
      wrongByteCount.recordResolution(
        service: .quicEcho,
        payload: try PeerProbePayload.payload(for: .quicEcho, sessionID: sessionID),
        bytesSent: payload.count,
        security: securityObservation(for: .quicEcho),
        evidenceDisposition: .pairRequired,
        deliveryConfirmationCompletion: .processed,
        peerTerminalObserved: false,
        deliveryAcknowledgementFinalContextObserved: true,
        sessionID: sessionID
      ) == .fail
    )

    var pairWithoutFinalContext = PeerCompletionTracker()
    #expect(
      pairWithoutFinalContext.recordResolution(
        service: .tls13Echo,
        payload: payload,
        bytesSent: payload.count + 2,
        security: securityObservation(for: .tls13Echo),
        evidenceDisposition: .pairRequired,
        deliveryConfirmationCompletion: .failed,
        peerTerminalObserved: false,
        deliveryAcknowledgementFinalContextObserved: false,
        sessionID: sessionID
      ) == .fail
    )

    var locallyAcceptedSecureOutcome = PeerCompletionTracker()
    #expect(
      locallyAcceptedSecureOutcome.recordResolution(
        service: .tls13Echo,
        payload: payload,
        bytesSent: payload.count + 2,
        security: securityObservation(for: .tls13Echo),
        evidenceDisposition: .accepted,
        deliveryConfirmationCompletion: .processed,
        peerTerminalObserved: false,
        deliveryAcknowledgementFinalContextObserved: true,
        sessionID: sessionID
      ) == .fail
    )
  }

  @Test("network shutdown includes every listener and the QUIC tunnel")
  func observedNetworkShutdown() {
    let resources = Set(PeerService.allCases.map(PeerNetworkShutdownResource.listener))
      .union([.quicConnectionGroup])
    var tracker = PeerNetworkShutdownTracker(expectedResources: resources)
    let tcpCompletedShutdown = tracker.observeCancellation(for: .listener(.tcpSink))
    let tlsCompletedShutdown = tracker.observeCancellation(for: .listener(.tls13Echo))
    #expect(!tcpCompletedShutdown)
    #expect(!tlsCompletedShutdown)
    #expect(tracker.observedResources.count == 2)
    let quicListenerCompletedShutdown = tracker.observeCancellation(
      for: .listener(.quicEcho)
    )
    let groupCompletedShutdown = tracker.observeCancellation(for: .quicConnectionGroup)
    let duplicateCompletedShutdown = tracker.observeCancellation(for: .quicConnectionGroup)
    #expect(!quicListenerCompletedShutdown)
    #expect(groupCompletedShutdown)
    #expect(!duplicateCompletedShutdown)
  }

  @Test("QUIC multiplex admission is one tunnel with one client stream")
  func quicMultiplexAdmissionLifecycle() {
    var tracker = PeerQUICMultiplexTracker()
    let streamBeforeTunnel = tracker.admitStream()
    let firstTunnel = tracker.admitTunnel(admissionSequence: 7)
    let secondTunnel = tracker.admitTunnel(admissionSequence: 8)
    let firstStream = tracker.admitStream()
    let secondStream = tracker.admitStream()
    let firstReady = tracker.observeStreamReady(
      identifier: PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier
    )
    let duplicateReady = tracker.observeStreamReady(
      identifier: PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier
    )
    let serverInitiatedReady = tracker.observeStreamReady(identifier: 1)
    let beganDrain = tracker.beginStreamDrain()
    let streamDuringDrain = tracker.admitStream()
    let streamTerminal = tracker.observeStreamTerminal()
    let tunnelCancelled = tracker.observeTunnelCancelled()
    #expect(!streamBeforeTunnel)
    #expect(firstTunnel)
    #expect(!secondTunnel)
    #expect(firstStream)
    #expect(!secondStream)
    #expect(firstReady)
    #expect(duplicateReady)
    #expect(!serverInitiatedReady)
    #expect(beganDrain)
    #expect(!streamDuringDrain)
    #expect(streamTerminal)
    #expect(tunnelCancelled)
    #expect(tracker.phase == .closed)
    #expect(tracker.tunnelAdmissionSequence == 7)
  }

  @Test("application launch mode is explicit and closed")
  func explicitLaunchMode() throws {
    #expect(
      try PeerLaunchMode.parse(arguments: [PeerContract.primerLaunchArgument]) == .primer
    )
    #expect(
      try PeerLaunchMode.parse(arguments: [PeerContract.transportRunLaunchArgument])
        == .session
    )
    #expect(throws: PeerContractError.self) {
      try PeerLaunchMode.parse(arguments: [])
    }
    #expect(throws: PeerContractError.self) {
      try PeerLaunchMode.parse(arguments: ["--unknown"])
    }
    #expect(throws: PeerContractError.self) {
      try PeerLaunchMode.parse(arguments: [PeerContract.primerLaunchArgument, "extra"])
    }
  }

  @Test("primer proof requires registration, ready, then observed cancellation")
  func primerLifecycleEvidence() throws {
    var incomplete = LocalNetworkPrimerEvidenceTracker(startedAt: now)
    #expect(throws: PeerContractError.self) {
      try incomplete.observeListenerCancelled(at: now.addingTimeInterval(1))
    }

    var tracker = LocalNetworkPrimerEvidenceTracker(startedAt: now)
    let registrationCompleted = try tracker.observeServiceRegistered(
      at: now.addingTimeInterval(1)
    )
    let readyCompleted = try tracker.observeListenerReady(at: now.addingTimeInterval(2))
    #expect(!registrationCompleted)
    #expect(readyCompleted)
    #expect(tracker.canCancel)
    try tracker.observeListenerCancelled(at: now.addingTimeInterval(3))
    #expect(tracker.isProven)
  }

  @Test("primer receipt and private path are canonical and write-once")
  func canonicalPrimerReceipt() throws {
    let receipt = try makePrimerReceipt()
    let canonical = try ExactJSON.encode(receipt)
    #expect(try ExactJSON.decodePrimerResult(canonical) == receipt)

    var object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    var listener = try #require(object["listener"] as? [String: Any])
    listener["fallback"] = true
    object["listener"] = listener
    var altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: PeerContractError.self) {
      try ExactJSON.decodePrimerResult(altered)
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      // The system permission sheet exits this foreground-only app. A bounded
      // host retry must be able to reuse the still-empty owned directory
      // without weakening its metadata or accepting stale receipts.
      try paths.prepareEmptyDirectory()
      try paths.writeResult(receipt)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
      #expect(try ExactJSON.decodePrimerResult(Data(contentsOf: paths.result)) == receipt)
      #expect(try paths.loadFreshResult(now: now) == receipt)
      let directoryMode = try #require(
        FileManager.default.attributesOfItem(atPath: paths.directory.path)[.posixPermissions]
          as? NSNumber
      )
      let resultMode = try #require(
        FileManager.default.attributesOfItem(atPath: paths.result.path)[.posixPermissions]
          as? NSNumber
      )
      #expect(directoryMode.intValue == 0o700)
      #expect(resultMode.intValue == 0o600)
      #expect(throws: PeerContractError.self) {
        try paths.writeResult(receipt)
      }
    }
  }

  @Test("primer receipt freshness and file metadata fail closed")
  func freshPrimerReceipt() throws {
    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      try paths.writeResult(try makePrimerReceipt())
      #expect(throws: PeerContractError.stalePrimer) {
        try paths.loadFreshResult(
          now: now.addingTimeInterval(PeerContract.maximumSessionSeconds + 1)
        )
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      try paths.writeResult(try makePrimerReceipt())
      try setMode(0o644, for: paths.result)
      #expect(throws: PeerContractError.self) {
        try paths.loadFreshResult(now: now)
      }
    }
  }

  @Test("primer retry rejects mode drift and symbolic-link directories")
  func unsafePrimerRetryDirectory() throws {
    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try FileManager.default.createDirectory(
        at: paths.directory,
        withIntermediateDirectories: false
      )
      try setMode(0o755, for: paths.directory)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      let target = documents.appendingPathComponent("primer-target", isDirectory: true)
      try FileManager.default.createDirectory(
        at: target,
        withIntermediateDirectories: false
      )
      try FileManager.default.createSymbolicLink(
        at: paths.directory,
        withDestinationURL: target
      )
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try FileManager.default.createDirectory(
        at: paths.transportDirectory,
        withIntermediateDirectories: false
      )
      try setMode(0o700, for: paths.transportDirectory)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }
  }

  @Test("probe payloads are domain-separated and stable")
  func canonicalProbePayloads() throws {
    let sessionID = String(repeating: "1", count: 64)
    let expected = [
      PeerService.tcpSink: "6c7014f02ed356b257c33ef87ad4c0d2c3541e69d7e34814191ddbfc386d90fb",
      PeerService.tls13Echo: "76ee2dbd470cd582ac9215cfc43278709de0194ad89655df299f7c90f6fab1e2",
      PeerService.quicEcho: "846b31f741343a4815bb326cde1316b9c1e8c6e2382e4ae93785a4080d756009",
    ]
    var payloads = Set<Data>()
    for service in PeerService.allCases {
      let payload = try PeerProbePayload.payload(for: service, sessionID: sessionID)
      #expect(payload.count == 32)
      let payloadHex = payload.map { String(format: "%02x", $0) }.joined()
      #expect(payloadHex == expected[service])
      payloads.insert(payload)
    }
    #expect(payloads.count == PeerService.allCases.count)
  }

  @Test("ready receipt rejects unknown nested fields")
  func strictNestedReadyShape() throws {
    let certificate = try fixtureCertificate()
    let ready = try makeReady(certificate: certificate)
    let canonical = try ExactJSON.encode(ready)
    _ = try ExactJSON.decodeReady(canonical)

    var object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    var network = try #require(object["network"] as? [String: Any])
    network["fallback"] = false
    object["network"] = network
    var altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: PeerContractError.self) {
      try ExactJSON.decodeReady(altered)
    }
  }

  @Test("Mac probe plan is canonical and bounded to seven attempts")
  func canonicalMacProbePlan() throws {
    let certificate = try fixtureCertificate()
    let plan = makePlan(certificate: certificate)
    let canonical = try ExactJSON.encode(plan)
    #expect(try MacProbePlan.decodeCanonical(canonical, now: now) == plan)
    #expect(plan.schemaVersion == 1)
    #expect(plan.document == "cfm-ios-transport-peer-mac-probe-plan-v1")
    #expect(PeerContract.schemaVersion == 1)
    #expect(PeerContract.readyDocument == "cfm-ios-transport-peer-ready-v1")
    #expect(PeerContract.tlsALPN == "cfm-transport-peer-tls/1")
    #expect(PeerContract.quicALPN == "cfm-transport-peer-quic/1")
    #expect(PeerContract.preSecurityHandshakeDeadlineSeconds == 4)
    #expect(PeerContract.quicEstablishmentDeadlineSeconds == 7)
    #expect(PeerContract.connectionProgressDeadlineSeconds == 7)
    #expect(MacProbeContract.connectionDeadlineSeconds == 8)
    #expect(MacSendPlan.streamMessage.usesFinalContext == false)
    #expect(MacSendPlan.streamMessage.completesContext)
    #expect(MacSendPlan.streamFinal.usesFinalContext)
    #expect(MacSendPlan.streamFinal.completesContext)
    #expect(
      PeerContract.preSecurityHandshakeDeadlineSeconds
        < MacProbeContract.connectionDeadlineSeconds
    )
    #expect(
      PeerContract.connectionProgressDeadlineSeconds
        < MacProbeContract.connectionDeadlineSeconds
    )
    #expect(
      PeerContract.quicEstablishmentDeadlineSeconds
        < MacProbeContract.connectionDeadlineSeconds
    )
    #expect(MacProbeContract.attemptCount == 7)
    #expect(MacProbeContract.attemptCount < PeerContract.maximumConnections)
    #expect(PeerContract.observableQUICConnectionGroupLimit == 2)
    #expect(PeerContract.maximumClientInitiatedBidirectionalQUICStreams == 1)
    #expect(PeerContract.maximumServerInitiatedBidirectionalQUICStreams == 0)
    #expect(PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier == 0)
    #expect(
      PeerContract.maximumClientInitiatedBidirectionalQUICStreams
        < PeerContract.maximumConnections
    )

    var object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    object["fallback"] = true
    var altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: MacProbeError.self) {
      try MacProbePlan.decodeCanonical(altered, now: now)
    }
  }

  @Test("Mac probe run directory is private, exact, and source-bound")
  func strictMacProbeRunDirectory() throws {
    try withPrivateTemporaryDirectory { directory in
      let certificate = try fixtureCertificate()
      let plan = makePlan(certificate: certificate)
      let ready = try makeReady(certificate: certificate)
      let planURL = directory.appendingPathComponent(MacProbeContract.planFileName)
      let readyURL = directory.appendingPathComponent(MacProbeContract.readyFileName)
      try writePrivate(try ExactJSON.encode(plan), to: planURL)
      try writePrivate(
        try ExactJSON.encode(ready),
        to: readyURL
      )
      try writePrivate(
        certificate,
        to: directory.appendingPathComponent(MacProbeContract.certificateFileName)
      )

      let loaded = try MacProbeRunDirectory.load(path: directory.path, now: now)
      #expect(loaded.plan == plan)
      #expect(loaded.ready == ready)
      #expect(loaded.certificateDER == certificate)

      let unexpected = directory.appendingPathComponent("unexpected")
      try writePrivate(Data([0x01]), to: unexpected)
      #expect(throws: MacProbeError.self) {
        try MacProbeRunDirectory.load(path: directory.path, now: now)
      }
      try FileManager.default.removeItem(at: unexpected)

      try FileManager.default.removeItem(at: readyURL)
      let readyAfterPlan = try makeReady(
        certificate: certificate,
        startedAt: now
      )
      try writePrivate(try ExactJSON.encode(readyAfterPlan), to: readyURL)
      #expect(throws: MacProbeError.self) {
        try MacProbeRunDirectory.load(path: directory.path, now: now)
      }
      try FileManager.default.removeItem(at: readyURL)
      try writePrivate(try ExactJSON.encode(ready), to: readyURL)

      try setMode(0o660, for: planURL)
      #expect(throws: MacProbeError.self) {
        try MacProbeRunDirectory.load(path: directory.path, now: now)
      }
    }
  }

  @Test("zero-length negative receipt states only observed early-data metadata")
  func earlyDataReceiptWording() throws {
    let receipt = MacProbeInvalidFrameReceipt(
      clientCompleted: true,
      connectionEnded: true,
      tlsVersion: 0x0304,
      cipherSuite: 0x1301,
      alpn: PeerContract.tlsALPN,
      earlyDataAccepted: false,
      clientBytesSent: 2,
      invalidZeroLengthFrameSent: true
    )
    let encoded = try ExactJSON.encode(receipt)
    let text = try #require(String(data: encoded, encoding: .utf8))
    #expect(text.contains("\"client_completed\":true"))
    #expect(text.contains("\"connection_ended\":true"))
    #expect(text.contains("\"early_data_accepted\":false"))
    #expect(!text.contains("\"accepted\":"))
    #expect(!text.contains("peer_closed"))
    #expect(!text.contains("early_data_rejected"))
    #expect(!text.contains("0rtt"))
  }

  @Test("negative handshakes accept only bounded no-ready outcomes")
  func negativeHandshakeClassification() {
    #expect(
      MacTransportProbe.boundedNegativeHandshakeDidNotReachReady(
        MacProbeError.connectionFailed("tls12")
      )
    )
    #expect(
      MacTransportProbe.boundedNegativeHandshakeDidNotReachReady(
        MacProbeError.deadline("tls12")
      )
    )
    #expect(
      !MacTransportProbe.boundedNegativeHandshakeDidNotReachReady(
        MacProbeError.protocolMismatch("tls12")
      )
    )
    #expect(
      !MacTransportProbe.boundedNegativeHandshakeDidNotReachReady(
        MacProbeError.invalidInput("tls12")
      )
    )
  }

  @Test("Mac probe accepts only a clean empty connection end")
  func cleanConnectionEndClassification() {
    #expect(
      MacTransportProbe.classifyConnectionEnd(
        bytesReceived: 0,
        complete: true,
        failed: false
      ) == .clean
    )
    #expect(
      MacTransportProbe.classifyConnectionEnd(
        bytesReceived: 0,
        complete: false,
        failed: true
      ) == .failed
    )
    #expect(
      MacTransportProbe.classifyConnectionEnd(
        bytesReceived: 1,
        complete: true,
        failed: false
      ) == .unexpectedBytes
    )
    #expect(
      MacTransportProbe.classifyConnectionEnd(
        bytesReceived: 0,
        complete: false,
        failed: false
      ) == .remainedOpen
    )
  }

  @Test("final exact receive waits for stream completion")
  func finalExactReceiveWaitsForCompletion() {
    var finalTracker = MacExactReceiveTracker(
      expectedBytes: 1,
      requiresStreamCompletion: true
    )
    #expect(finalTracker.observe(bytes: 1, streamComplete: false) == .readMore)
    #expect(finalTracker.receivedBytes == 1)
    #expect(finalTracker.observe(bytes: 0, streamComplete: true) == .complete)

    var singleFinalChunk = MacExactReceiveTracker(
      expectedBytes: 1,
      requiresStreamCompletion: true
    )
    #expect(singleFinalChunk.observe(bytes: 1, streamComplete: true) == .complete)

    var normalTracker = MacExactReceiveTracker(
      expectedBytes: 1,
      requiresStreamCompletion: false
    )
    #expect(normalTracker.observe(bytes: 1, streamComplete: false) == .complete)

    var overflow = MacExactReceiveTracker(
      expectedBytes: 1,
      requiresStreamCompletion: true
    )
    #expect(overflow.observe(bytes: 2, streamComplete: true) == .overflow)

    var truncated = MacExactReceiveTracker(
      expectedBytes: 2,
      requiresStreamCompletion: true
    )
    #expect(truncated.observe(bytes: 1, streamComplete: true) == .truncated)

    var emptyPartial = MacExactReceiveTracker(
      expectedBytes: 1,
      requiresStreamCompletion: true
    )
    #expect(emptyPartial.observe(bytes: 0, streamComplete: false) == .emptyPartial)
  }

  @Test("Mac probe result is strict, canonical, and ineligible for product claims")
  func strictMacProbeResult() throws {
    let certificate = try fixtureCertificate()
    let result = try makeResult(certificate: certificate)
    let canonical = try ExactJSON.encode(result)
    #expect(try MacProbeResult.decodeCanonical(canonical, now: now) == result)
    #expect(result.mode == "lab_smoke_only")
    #expect(result.claimEligible == false)
    #expect(result.schemaVersion == 3)
    #expect(result.document == "cfm-ios-transport-peer-mac-probe-result-v3")
    #expect(result.positiveChecks.tls13Echo.deliveryAcknowledgementHex == "a5")
    #expect(result.positiveChecks.tls13Echo.deliveryConfirmationHex == "5a")
    #expect(result.positiveChecks.tls13Echo.deliveryConfirmationStreamComplete)
    let canonicalText = try #require(String(data: canonical, encoding: .utf8))
    #expect(canonicalText.contains("tls12_did_not_reach_ready"))
    #expect(canonicalText.contains("alpn_mismatch_did_not_reach_ready"))
    #expect(!canonicalText.contains("tls12_rejected"))
    #expect(!canonicalText.contains("\"accepted\":"))

    var object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    var positive = try #require(object["positive_checks"] as? [String: Any])
    var tls = try #require(positive["tls13_echo"] as? [String: Any])
    tls["accepted"] = 1
    positive["tls13_echo"] = tls
    object["positive_checks"] = positive
    var altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: MacProbeError.self) {
      try MacProbeResult.decodeCanonical(altered, now: now)
    }

    for streamComplete: Any? in [false, nil] {
      object = try #require(
        JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
      )
      positive = try #require(object["positive_checks"] as? [String: Any])
      tls = try #require(positive["tls13_echo"] as? [String: Any])
      if let streamComplete {
        tls["delivery_confirmation_stream_complete"] = streamComplete
      } else {
        tls.removeValue(forKey: "delivery_confirmation_stream_complete")
      }
      positive["tls13_echo"] = tls
      object["positive_checks"] = positive
      altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
      altered.append(0x0A)
      #expect(throws: MacProbeError.self) {
        try MacProbeResult.decodeCanonical(altered, now: now)
      }
    }

    object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    object["schema_version"] = 1
    object["document"] = "cfm-ios-transport-peer-mac-probe-result-v1"
    altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: MacProbeError.self) {
      try MacProbeResult.decodeCanonical(altered, now: now)
    }

    object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    positive = try #require(object["positive_checks"] as? [String: Any])
    tls = try #require(positive["tls13_echo"] as? [String: Any])
    tls["delivery_confirmation_hex"] = "5b"
    positive["tls13_echo"] = tls
    object["positive_checks"] = positive
    altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: MacProbeError.self) {
      try MacProbeResult.decodeCanonical(altered, now: now)
    }

    object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    var negative = try #require(object["negative_checks"] as? [String: Any])
    var wrongPin = try #require(negative["wrong_leaf_pin_rejected"] as? [String: Any])
    wrongPin["verify_callback_invoked"] = false
    negative["wrong_leaf_pin_rejected"] = wrongPin
    object["negative_checks"] = negative
    altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: MacProbeError.self) {
      try MacProbeResult.decodeCanonical(altered, now: now)
    }
  }

  private func fixtureCertificate() throws -> Data {
    try #require(Data(base64Encoded: certificateBase64))
  }

  private func makePrimerReceipt() throws -> LocalNetworkPrimerReceipt {
    LocalNetworkPrimerReceipt(
      schemaVersion: PeerContract.schemaVersion,
      document: PeerContract.primerResultDocument,
      mode: PeerContract.primerMode,
      claimEligible: false,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      startedAt: PeerSession.timestamp(now.addingTimeInterval(-3)),
      serviceRegisteredAt: PeerSession.timestamp(now.addingTimeInterval(-2)),
      listenerReadyAt: PeerSession.timestamp(now.addingTimeInterval(-1)),
      listenerCancelledAt: PeerSession.timestamp(now),
      serviceRegistered: true,
      listenerReady: true,
      listenerCancelled: true,
      network: try PeerNetworkReceipt(interfaceName: "en0", ipv4: "192.168.1.20"),
      listener: .fixed
    )
  }

  private func makePlan(certificate: Data) -> MacProbePlan {
    MacProbePlan(
      schemaVersion: MacProbeContract.planSchemaVersion,
      document: MacProbeContract.planDocument,
      sessionID: String(repeating: "1", count: 64),
      createdAt: PeerSession.timestamp(now.addingTimeInterval(-0.25)),
      expiresAt: PeerSession.timestamp(now.addingTimeInterval(600)),
      peerIPv4: "192.168.1.20",
      certificateSHA256: PeerDigest.sha256(certificate)
    )
  }

  private func makeReady(certificate: Data, startedAt: Date? = nil) throws -> ReadyReceipt {
    ReadyReceipt(
      schemaVersion: PeerContract.schemaVersion,
      document: PeerContract.readyDocument,
      sessionID: String(repeating: "1", count: 64),
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      startedAt: PeerSession.timestamp(startedAt ?? now.addingTimeInterval(-0.5)),
      expiresAt: PeerSession.timestamp(now.addingTimeInterval(600)),
      certificateSHA256: PeerDigest.sha256(certificate),
      network: try PeerNetworkReceipt(interfaceName: "en0", ipv4: "192.168.1.20"),
      listeners: .fixed
    )
  }

  private func makeResult(certificate: Data) throws -> MacProbeResult {
    let sessionID = String(repeating: "1", count: 64)
    let certificateSHA256 = PeerDigest.sha256(certificate)
    let tcpPayload = try PeerProbePayload.payload(for: .tcpSink, sessionID: sessionID)
    let tlsPayload = try PeerProbePayload.payload(for: .tls13Echo, sessionID: sessionID)
    let quicPayload = try PeerProbePayload.payload(for: .quicEcho, sessionID: sessionID)
    return MacProbeResult(
      schemaVersion: MacProbeContract.resultSchemaVersion,
      document: MacProbeContract.resultDocument,
      mode: MacProbeContract.resultMode,
      claimEligible: false,
      sessionID: sessionID,
      certificateSHA256: certificateSHA256,
      processID: 42,
      peerIPv4: "192.168.1.20",
      attemptCount: MacProbeContract.attemptCount,
      startedAt: PeerSession.timestamp(now.addingTimeInterval(-0.2)),
      completedAt: PeerSession.timestamp(now.addingTimeInterval(-0.1)),
      negativeChecks: MacProbeNegativeReceipts(
        tls12DidNotReachReady: MacProbeDidNotReachReadyReceipt(
          didNotReachReady: true,
          clientBytesSent: 0
        ),
        wrongLeafPinRejected: MacProbeWrongLeafPinReceipt(
          didNotReachReady: true,
          clientBytesSent: 0,
          verifyCallbackInvoked: true,
          leafMatchedSessionCertificate: true,
          verifyReturnedFalse: true
        ),
        alpnMismatchDidNotReachReady: MacProbeDidNotReachReadyReceipt(
          didNotReachReady: true,
          clientBytesSent: 0
        ),
        zeroLengthFrameConnectionEnded: MacProbeInvalidFrameReceipt(
          clientCompleted: true,
          connectionEnded: true,
          tlsVersion: 0x0304,
          cipherSuite: 0x1301,
          alpn: PeerContract.tlsALPN,
          earlyDataAccepted: false,
          clientBytesSent: 2,
          invalidZeroLengthFrameSent: true
        )
      ),
      positiveChecks: MacProbePositiveReceipts(
        tcpSink: MacProbeTCPReceipt(
          clientCompleted: true,
          transport: "tcp4",
          payloadSHA256: PeerDigest.sha256(tcpPayload),
          payloadBytes: tcpPayload.count,
          clientBytesSent: tcpPayload.count,
          clientBytesReceived: 0
        ),
        tls13Echo: secureReceipt(
          transport: "tls13-tcp4",
          alpn: PeerContract.tlsALPN,
          payload: tlsPayload,
          certificateSHA256: certificateSHA256
        ),
        quicEcho: secureReceipt(
          transport: "quic-tls13",
          alpn: PeerContract.quicALPN,
          payload: quicPayload,
          certificateSHA256: certificateSHA256
        )
      )
    )
  }

  private func secureReceipt(
    transport: String,
    alpn: String,
    payload: Data,
    certificateSHA256: String
  ) -> MacProbeSecureReceipt {
    MacProbeSecureReceipt(
      clientCompleted: true,
      transport: transport,
      payloadSHA256: PeerDigest.sha256(payload),
      payloadBytes: payload.count,
      clientBytesSent: payload.count + 2,
      clientBytesReceived: payload.count + 2,
      clientControlBytesSent: PeerContract.deliveryAcknowledgement.count,
      clientControlBytesReceived: PeerContract.deliveryConfirmation.count,
      deliveryAcknowledgementHex: PeerContract.deliveryAcknowledgementHex,
      deliveryConfirmationHex: PeerContract.deliveryConfirmationHex,
      deliveryConfirmationStreamComplete: true,
      tlsVersion: 0x0304,
      cipherSuite: 0x1301,
      alpn: alpn,
      earlyDataAccepted: false,
      certificateSHA256: certificateSHA256
    )
  }

  private func withPrivateTemporaryDirectory(
    _ body: (URL) throws -> Void
  ) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "cfm-ios-peer-tests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false
    )
    try setMode(0o700, for: directory)
    defer {
      do {
        try FileManager.default.removeItem(at: directory)
      } catch {
        Issue.record(error)
      }
    }
    try body(directory)
  }

  private func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: [.withoutOverwriting])
    try setMode(0o600, for: url)
  }

  private func setMode(_ mode: mode_t, for url: URL) throws {
    guard chmod(url.path, mode) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
  }
}
