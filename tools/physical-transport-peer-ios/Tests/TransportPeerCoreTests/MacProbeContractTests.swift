import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

// The Mac probe: probe payloads, the ready receipt, the plan, run
// directory, receipts and result, with the builders only these tests use.
extension PeerLifecycleAndMacProbeTests {
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
}
