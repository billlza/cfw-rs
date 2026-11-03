import Foundation
@preconcurrency import Network
import TransportPeerCore

public enum MacTransportProbe {
  static let queue = DispatchQueue(label: "com.bill.cfm.transport-peer.mac-probe")

  public static func run(inputs: MacProbeInputs, now: Date = Date()) throws -> MacProbeResult {
    try inputs.plan.validate(now: now)
    guard MacProbeContract.attemptCount == 7,
      MacProbeContract.attemptCount < PeerContract.maximumConnections
    else {
      throw MacProbeError.invalidInput("probe attempt budget")
    }
    let started = Date()

    let tls12DidNotReachReady = try expectedDidNotReachReady(
      inputs: inputs,
      label: "tls12",
      minimumTLSVersion: .TLSv12,
      maximumTLSVersion: .TLSv12,
      alpn: PeerContract.tlsALPN
    )
    let wrongLeafPinRejected = try wrongLeafPinDidNotReachReady(inputs: inputs)
    let alpnMismatchDidNotReachReady = try expectedDidNotReachReady(
      inputs: inputs,
      label: "ALPN mismatch",
      minimumTLSVersion: .TLSv13,
      maximumTLSVersion: .TLSv13,
      alpn: MacProbeContract.mismatchedALPN
    )
    let zeroLengthFrameConnectionEnded = try invalidZeroLengthFrame(inputs: inputs)

    let tcp = try positiveTCP(inputs: inputs)
    let tls = try positiveTLS(inputs: inputs)
    let quic = try positiveQUIC(inputs: inputs)

    return MacProbeResult(
      schemaVersion: MacProbeContract.resultSchemaVersion,
      document: MacProbeContract.resultDocument,
      mode: MacProbeContract.resultMode,
      claimEligible: false,
      sessionID: inputs.plan.sessionID,
      certificateSHA256: inputs.plan.certificateSHA256,
      processID: inputs.ready.processID,
      peerIPv4: inputs.plan.peerIPv4,
      attemptCount: MacProbeContract.attemptCount,
      startedAt: PeerSession.timestamp(started),
      completedAt: PeerSession.timestamp(Date()),
      negativeChecks: MacProbeNegativeReceipts(
        tls12DidNotReachReady: tls12DidNotReachReady,
        wrongLeafPinRejected: wrongLeafPinRejected,
        alpnMismatchDidNotReachReady: alpnMismatchDidNotReachReady,
        zeroLengthFrameConnectionEnded: zeroLengthFrameConnectionEnded
      ),
      positiveChecks: MacProbePositiveReceipts(
        tcpSink: tcp,
        tls13Echo: tls,
        quicEcho: quic
      )
    )
  }

  private static func expectedDidNotReachReady(
    inputs: MacProbeInputs,
    label: String,
    minimumTLSVersion: tls_protocol_version_t,
    maximumTLSVersion: tls_protocol_version_t,
    alpn: String
  ) throws -> MacProbeDidNotReachReadyReceipt {
    let parameters = try tlsParameters(
      certificateDER: inputs.certificateDER,
      alpn: alpn,
      minimumTLSVersion: minimumTLSVersion,
      maximumTLSVersion: maximumTLSVersion,
      trustMode: .exactLeaf
    )
    let connection = connection(
      inputs: inputs,
      port: PeerContract.tlsEchoPort,
      parameters: parameters
    )
    defer { connection.cancel() }
    do {
      try waitUntilReady(connection, label: label)
    } catch {
      guard boundedNegativeHandshakeDidNotReachReady(error) else { throw error }
      return MacProbeDidNotReachReadyReceipt(
        didNotReachReady: true,
        clientBytesSent: 0
      )
    }
    throw MacProbeError.protocolMismatch("\(label) unexpectedly reached ready")
  }

  private static func wrongLeafPinDidNotReachReady(
    inputs: MacProbeInputs
  ) throws -> MacProbeWrongLeafPinReceipt {
    let evidence = WrongLeafPinEvidence()
    let parameters = try tlsParameters(
      certificateDER: inputs.certificateDER,
      alpn: PeerContract.tlsALPN,
      minimumTLSVersion: .TLSv13,
      maximumTLSVersion: .TLSv13,
      trustMode: .wrongLeafPin(evidence)
    )
    let connection = connection(
      inputs: inputs,
      port: PeerContract.tlsEchoPort,
      parameters: parameters
    )
    defer { connection.cancel() }
    do {
      try waitUntilReady(connection, label: "wrong leaf pin")
    } catch {
      guard boundedNegativeHandshakeDidNotReachReady(error) else { throw error }
      let snapshot = evidence.snapshot()
      guard snapshot.verifyCallbackInvoked,
        snapshot.leafMatchedSessionCertificate,
        snapshot.verifyReturnedFalse
      else {
        throw MacProbeError.protocolMismatch("wrong leaf pin verification evidence")
      }
      return MacProbeWrongLeafPinReceipt(
        didNotReachReady: true,
        clientBytesSent: 0,
        verifyCallbackInvoked: snapshot.verifyCallbackInvoked,
        leafMatchedSessionCertificate: snapshot.leafMatchedSessionCertificate,
        verifyReturnedFalse: snapshot.verifyReturnedFalse
      )
    }
    throw MacProbeError.protocolMismatch("wrong leaf pin unexpectedly reached ready")
  }

  static func boundedNegativeHandshakeDidNotReachReady(_ error: Error) -> Bool {
    switch error {
    case MacProbeError.connectionFailed, MacProbeError.deadline:
      true
    default:
      false
    }
  }

  private static func invalidZeroLengthFrame(
    inputs: MacProbeInputs
  ) throws -> MacProbeInvalidFrameReceipt {
    let parameters = try tlsParameters(
      certificateDER: inputs.certificateDER,
      alpn: PeerContract.tlsALPN,
      minimumTLSVersion: .TLSv13,
      maximumTLSVersion: .TLSv13,
      trustMode: .exactLeaf
    )
    let connection = connection(
      inputs: inputs,
      port: PeerContract.tlsEchoPort,
      parameters: parameters
    )
    defer { connection.cancel() }
    try waitUntilReady(connection, label: "zero-length frame")
    let security = try securityObservation(
      connection,
      definition: NWProtocolTLS.definition,
      expectedALPN: PeerContract.tlsALPN,
      label: "zero-length frame"
    )
    guard security.earlyDataAccepted == false else {
      throw MacProbeError.protocolMismatch("zero-length frame accepted early data")
    }
    let invalidFrame = Data([0, 0])
    try send(invalidFrame, on: connection, label: "zero-length frame")
    try waitForConnectionEnd(connection, label: "zero-length frame")
    return MacProbeInvalidFrameReceipt(
      clientCompleted: true,
      connectionEnded: true,
      tlsVersion: security.tlsVersion,
      cipherSuite: security.cipherSuite,
      alpn: security.alpn,
      earlyDataAccepted: security.earlyDataAccepted,
      clientBytesSent: invalidFrame.count,
      invalidZeroLengthFrameSent: true
    )
  }

  private static func positiveTCP(inputs: MacProbeInputs) throws -> MacProbeTCPReceipt {
    let payload = try PeerProbePayload.payload(
      for: .tcpSink,
      sessionID: inputs.plan.sessionID
    )
    let parameters = try plainTCPParameters()
    let connection = connection(
      inputs: inputs,
      port: PeerContract.tcpSinkPort,
      parameters: parameters
    )
    defer { connection.cancel() }
    try waitUntilReady(connection, label: "TCP sink")
    try send(payload, on: connection, label: "TCP sink")
    try waitForConnectionEnd(connection, label: "TCP sink")
    return MacProbeTCPReceipt(
      clientCompleted: true,
      transport: "tcp4",
      payloadSHA256: PeerDigest.sha256(payload),
      payloadBytes: payload.count,
      clientBytesSent: payload.count,
      clientBytesReceived: 0
    )
  }

  private static func positiveTLS(inputs: MacProbeInputs) throws -> MacProbeSecureReceipt {
    let parameters = try tlsParameters(
      certificateDER: inputs.certificateDER,
      alpn: PeerContract.tlsALPN,
      minimumTLSVersion: .TLSv13,
      maximumTLSVersion: .TLSv13,
      trustMode: .exactLeaf
    )
    return try positiveSecure(
      inputs: inputs,
      service: .tls13Echo,
      transport: "tls13-tcp4",
      port: PeerContract.tlsEchoPort,
      parameters: parameters,
      definition: NWProtocolTLS.definition,
      expectedALPN: PeerContract.tlsALPN
    )
  }

  private static func positiveQUIC(inputs: MacProbeInputs) throws -> MacProbeSecureReceipt {
    let parameters = try quicParameters(
      certificateDER: inputs.certificateDER,
      alpn: PeerContract.quicALPN
    )
    return try positiveSecure(
      inputs: inputs,
      service: .quicEcho,
      transport: "quic-tls13",
      port: PeerContract.quicEchoPort,
      parameters: parameters,
      definition: NWProtocolQUIC.definition,
      expectedALPN: PeerContract.quicALPN
    )
  }

  private static func positiveSecure(
    inputs: MacProbeInputs,
    service: PeerService,
    transport: String,
    port: UInt16,
    parameters: NWParameters,
    definition: NWProtocolDefinition,
    expectedALPN: String
  ) throws -> MacProbeSecureReceipt {
    let payload = try PeerProbePayload.payload(for: service, sessionID: inputs.plan.sessionID)
    let frame = framed(payload)
    let connection = connection(inputs: inputs, port: port, parameters: parameters)
    defer { connection.cancel() }
    try waitUntilReady(connection, label: service.rawValue)
    let security = try securityObservation(
      connection,
      definition: definition,
      expectedALPN: expectedALPN,
      label: service.rawValue
    )
    try send(
      frame,
      on: connection,
      label: service.rawValue,
      disposition: MacSendPlan.streamMessage
    )
    let response = try receiveExact(frame.count, on: connection, label: service.rawValue)
    guard response == frame else {
      throw MacProbeError.protocolMismatch("\(service.rawValue) echo bytes")
    }
    try send(
      PeerContract.deliveryAcknowledgement,
      on: connection,
      label: "\(service.rawValue) delivery acknowledgement",
      disposition: MacSendPlan.streamFinal
    )
    let confirmation = try receiveExact(
      PeerContract.deliveryConfirmation.count,
      on: connection,
      label: "\(service.rawValue) delivery confirmation",
      requiresStreamCompletion: true
    )
    guard confirmation == PeerContract.deliveryConfirmation else {
      throw MacProbeError.protocolMismatch("\(service.rawValue) delivery confirmation")
    }
    return MacProbeSecureReceipt(
      clientCompleted: true,
      transport: transport,
      payloadSHA256: PeerDigest.sha256(payload),
      payloadBytes: payload.count,
      clientBytesSent: frame.count,
      clientBytesReceived: response.count,
      clientControlBytesSent: PeerContract.deliveryAcknowledgement.count,
      clientControlBytesReceived: confirmation.count,
      deliveryAcknowledgementHex: PeerContract.deliveryAcknowledgementHex,
      deliveryConfirmationHex: PeerContract.deliveryConfirmationHex,
      deliveryConfirmationStreamComplete: true,
      tlsVersion: security.tlsVersion,
      cipherSuite: security.cipherSuite,
      alpn: security.alpn,
      earlyDataAccepted: security.earlyDataAccepted,
      certificateSHA256: inputs.plan.certificateSHA256
    )
  }

  private static func framed(_ payload: Data) -> Data {
    precondition(payload.count <= UInt16.max)
    var frame = Data([
      UInt8((payload.count >> 8) & 0xff),
      UInt8(payload.count & 0xff),
    ])
    frame.append(payload)
    return frame
  }
}
