import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

// Echo delivery: completion races, callback generations, deadline tokens,
// the final acknowledgement and connection admission overlap.
extension PeerLifecycleAndMacProbeTests {
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
}
