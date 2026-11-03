import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

@Suite("Transport peer lifecycle and Mac probe contract")
struct PeerLifecycleAndMacProbeTests {
  let now = Date(timeIntervalSince1970: 1_777_777_777.123456)
  let certificateBase64 =
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

  func preparedDeliveryTracker() -> PeerEchoDeliveryTracker {
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

  func recordAccepted(
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

  func recordPairRequired(
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

  func serverResult(
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

  func withPrivateTemporaryDirectory(
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

  func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: [.withoutOverwriting])
    try setMode(0o600, for: url)
  }

  func setMode(_ mode: mode_t, for url: URL) throws {
    guard chmod(url.path, mode) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
  }
}
