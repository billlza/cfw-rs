import Foundation
@preconcurrency import Network
import Security
import TransportPeerCore

private final class BlockingResult<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var result: Result<Value, Error>?

  func resolve(_ value: Result<Value, Error>) {
    lock.lock()
    guard result == nil else {
      lock.unlock()
      return
    }
    result = value
    lock.unlock()
    semaphore.signal()
  }

  func wait(label: String) throws -> Value {
    let timeout = DispatchTime.now() + MacProbeContract.connectionDeadlineSeconds
    guard semaphore.wait(timeout: timeout) == .success else {
      throw MacProbeError.deadline(label)
    }
    lock.lock()
    defer { lock.unlock() }
    guard let result else {
      throw MacProbeError.connectionFailed(label)
    }
    return try result.get()
  }
}

private struct ReceiveChunk: Sendable {
  let content: Data
  let complete: Bool
}

enum MacExactReceiveDecision: Equatable, Sendable {
  case readMore
  case complete
  case emptyPartial
  case overflow
  case truncated
}

struct MacExactReceiveTracker: Equatable, Sendable {
  let expectedBytes: Int
  let requiresStreamCompletion: Bool
  private(set) var receivedBytes = 0

  mutating func observe(bytes: Int, streamComplete: Bool) -> MacExactReceiveDecision {
    guard bytes >= 0, expectedBytes > 0 else { return .overflow }
    if bytes == 0, !streamComplete { return .emptyPartial }
    receivedBytes += bytes
    guard receivedBytes <= expectedBytes else { return .overflow }
    if streamComplete, receivedBytes != expectedBytes { return .truncated }
    if receivedBytes == expectedBytes,
      !requiresStreamCompletion || streamComplete
    {
      return .complete
    }
    return .readMore
  }
}

struct MacSendDisposition: Equatable, Sendable {
  let usesFinalContext: Bool
  let completesContext: Bool
}

enum MacSendPlan {
  static let streamMessage = MacSendDisposition(
    usesFinalContext: false,
    completesContext: true
  )
  static let streamFinal = MacSendDisposition(
    usesFinalContext: true,
    completesContext: true
  )
}

enum MacConnectionEndDecision: Equatable, Sendable {
  case clean
  case failed
  case unexpectedBytes
  case remainedOpen
}

private struct SecurityObservation: Sendable {
  let tlsVersion: UInt16
  let cipherSuite: UInt16
  let alpn: String
  let earlyDataAccepted: Bool
}

private struct TrustEvaluation: Sendable {
  let accepted: Bool
  let leafMatchedSessionCertificate: Bool
}

private struct WrongLeafPinEvidenceSnapshot: Sendable {
  let verifyCallbackInvoked: Bool
  let leafMatchedSessionCertificate: Bool
  let verifyReturnedFalse: Bool
}

private final class WrongLeafPinEvidence: @unchecked Sendable {
  private let lock = NSLock()
  private var snapshotValue = WrongLeafPinEvidenceSnapshot(
    verifyCallbackInvoked: false,
    leafMatchedSessionCertificate: false,
    verifyReturnedFalse: false
  )

  func record(_ evaluation: TrustEvaluation) {
    lock.lock()
    snapshotValue = WrongLeafPinEvidenceSnapshot(
      verifyCallbackInvoked: true,
      leafMatchedSessionCertificate: evaluation.leafMatchedSessionCertificate,
      verifyReturnedFalse: evaluation.accepted == false
    )
    lock.unlock()
  }

  func snapshot() -> WrongLeafPinEvidenceSnapshot {
    lock.lock()
    defer { lock.unlock() }
    return snapshotValue
  }
}

private enum TrustMode: Sendable {
  case exactLeaf
  case wrongLeafPin(WrongLeafPinEvidence)
}

public enum MacTransportProbe {
  private static let queue = DispatchQueue(label: "com.bill.cfm.transport-peer.mac-probe")

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

  private static func connection(
    inputs: MacProbeInputs,
    port rawPort: UInt16,
    parameters: NWParameters
  ) -> NWConnection {
    let port = NWEndpoint.Port(rawValue: rawPort)!
    return NWConnection(
      host: NWEndpoint.Host(inputs.plan.peerIPv4),
      port: port,
      using: parameters
    )
  }

  private static func waitUntilReady(_ connection: NWConnection, label: String) throws {
    let result = BlockingResult<Void>()
    connection.stateUpdateHandler = { state in
      switch state {
      case .ready:
        result.resolve(.success(()))
      case .failed, .cancelled:
        result.resolve(.failure(MacProbeError.connectionFailed(label)))
      default:
        break
      }
    }
    connection.start(queue: queue)
    do {
      try result.wait(label: "\(label) ready")
    } catch {
      connection.forceCancel()
      throw error
    }
    guard connection.currentPath?.usesInterfaceType(.wifi) == true else {
      connection.cancel()
      throw MacProbeError.protocolMismatch("\(label) path is not Wi-Fi")
    }
  }

  private static func send(
    _ data: Data,
    on connection: NWConnection,
    label: String,
    disposition: MacSendDisposition = MacSendPlan.streamFinal
  ) throws {
    let result = BlockingResult<Void>()
    connection.send(
      content: data,
      contentContext: disposition.usesFinalContext ? .finalMessage : .defaultMessage,
      isComplete: disposition.completesContext,
      completion: .contentProcessed { error in
        if error == nil {
          result.resolve(.success(()))
        } else {
          result.resolve(.failure(MacProbeError.connectionFailed("\(label) send")))
        }
      }
    )
    try result.wait(label: "\(label) send")
  }

  private static func receiveExact(
    _ expectedBytes: Int,
    on connection: NWConnection,
    label: String,
    requiresStreamCompletion: Bool = false
  ) throws -> Data {
    var collected = Data()
    var tracker = MacExactReceiveTracker(
      expectedBytes: expectedBytes,
      requiresStreamCompletion: requiresStreamCompletion
    )
    while true {
      let remaining = max(0, expectedBytes - tracker.receivedBytes)
      let result = BlockingResult<ReceiveChunk>()
      connection.receive(minimumIncompleteLength: 1, maximumLength: max(1, remaining + 1)) {
        content, _, isComplete, error in
        if error != nil {
          result.resolve(.failure(MacProbeError.connectionFailed("\(label) receive")))
        } else {
          result.resolve(
            .success(ReceiveChunk(content: content ?? Data(), complete: isComplete))
          )
        }
      }
      let chunk = try result.wait(label: "\(label) receive")
      collected.append(chunk.content)
      switch tracker.observe(
        bytes: chunk.content.count,
        streamComplete: chunk.complete
      ) {
      case .readMore:
        continue
      case .complete:
        return collected
      case .emptyPartial:
        throw MacProbeError.protocolMismatch("\(label) empty partial response")
      case .overflow:
        throw MacProbeError.protocolMismatch("\(label) response overflow")
      case .truncated:
        throw MacProbeError.protocolMismatch("\(label) truncated response")
      }
    }
  }

  private static func waitForConnectionEnd(_ connection: NWConnection, label: String) throws {
    let result = BlockingResult<Void>()
    connection.receive(minimumIncompleteLength: 1, maximumLength: 1) {
      content, _, complete, error in
      switch classifyConnectionEnd(
        bytesReceived: content?.count ?? 0,
        complete: complete,
        failed: error != nil
      ) {
      case .clean:
        result.resolve(.success(()))
      case .failed:
        result.resolve(.failure(MacProbeError.connectionFailed("\(label) connection end")))
      case .unexpectedBytes:
        result.resolve(.failure(MacProbeError.protocolMismatch("\(label) unexpected response")))
      case .remainedOpen:
        result.resolve(.failure(MacProbeError.protocolMismatch("\(label) remained open")))
      }
    }
    try result.wait(label: "\(label) connection end")
  }

  static func classifyConnectionEnd(
    bytesReceived: Int,
    complete: Bool,
    failed: Bool
  ) -> MacConnectionEndDecision {
    guard bytesReceived >= 0 else { return .failed }
    if failed { return .failed }
    if bytesReceived != 0 { return .unexpectedBytes }
    return complete ? .clean : .remainedOpen
  }

  private static func plainTCPParameters() throws -> NWParameters {
    let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
    try configureBase(parameters)
    return parameters
  }

  private static func tlsParameters(
    certificateDER: Data,
    alpn: String,
    minimumTLSVersion: tls_protocol_version_t,
    maximumTLSVersion: tls_protocol_version_t,
    trustMode: TrustMode
  ) throws -> NWParameters {
    let tls = NWProtocolTLS.Options()
    try configureSecurity(
      tls.securityProtocolOptions,
      certificateDER: certificateDER,
      alpn: alpn,
      addALPNToSecurityOptions: true,
      minimumTLSVersion: minimumTLSVersion,
      maximumTLSVersion: maximumTLSVersion,
      trustMode: trustMode
    )
    let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    try configureBase(parameters)
    return parameters
  }

  private static func quicParameters(
    certificateDER: Data,
    alpn: String
  ) throws -> NWParameters {
    let quic = NWProtocolQUIC.Options(alpn: [alpn])
    quic.direction = .bidirectional
    quic.idleTimeout = Int(MacProbeContract.connectionDeadlineSeconds * 1_000)
    quic.initialMaxData = 1_024
    quic.initialMaxStreamDataBidirectionalLocal = 256
    quic.initialMaxStreamDataBidirectionalRemote = 256
    quic.initialMaxStreamsBidirectional =
      PeerContract.maximumServerInitiatedBidirectionalQUICStreams
    quic.initialMaxStreamsUnidirectional = 0
    try configureSecurity(
      quic.securityProtocolOptions,
      certificateDER: certificateDER,
      alpn: alpn,
      addALPNToSecurityOptions: false,
      minimumTLSVersion: .TLSv13,
      maximumTLSVersion: .TLSv13,
      trustMode: .exactLeaf
    )
    let parameters = NWParameters(quic: quic)
    try configureBase(parameters)
    return parameters
  }

  private static func configureBase(_ parameters: NWParameters) throws {
    guard let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options else {
      throw MacProbeError.invalidInput("IPv4 protocol stack")
    }
    ip.version = .v4
    parameters.defaultProtocolStack.internetProtocol = ip
    parameters.requiredInterfaceType = .wifi
    parameters.includePeerToPeer = false
    parameters.allowLocalEndpointReuse = false
  }

  private static func configureSecurity(
    _ options: sec_protocol_options_t,
    certificateDER: Data,
    alpn: String,
    addALPNToSecurityOptions: Bool,
    minimumTLSVersion: tls_protocol_version_t,
    maximumTLSVersion: tls_protocol_version_t,
    trustMode: TrustMode
  ) throws {
    guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
      throw MacProbeError.invalidInput("certificate DER")
    }
    sec_protocol_options_set_tls_server_name(options, MacProbeContract.serverName)
    sec_protocol_options_set_min_tls_protocol_version(options, minimumTLSVersion)
    sec_protocol_options_set_max_tls_protocol_version(options, maximumTLSVersion)
    sec_protocol_options_set_tls_tickets_enabled(options, false)
    sec_protocol_options_set_tls_resumption_enabled(options, false)
    sec_protocol_options_set_tls_false_start_enabled(options, false)
    if addALPNToSecurityOptions {
      sec_protocol_options_add_tls_application_protocol(options, alpn)
    }
    sec_protocol_options_set_verify_block(
      options,
      { _, trust, complete in
        let baseEvaluation = evaluateTrust(
          trust,
          certificate: certificate,
          certificateDER: certificateDER
        )
        switch trustMode {
        case .exactLeaf:
          complete(baseEvaluation.accepted)
        case .wrongLeafPin(let evidence):
          let rejectedEvaluation = TrustEvaluation(
            accepted: false,
            leafMatchedSessionCertificate: baseEvaluation.leafMatchedSessionCertificate
          )
          evidence.record(rejectedEvaluation)
          complete(false)
        }
      },
      queue
    )
  }

  private static func evaluateTrust(
    _ protocolTrust: sec_trust_t,
    certificate: SecCertificate,
    certificateDER: Data
  ) -> TrustEvaluation {
    let trust = sec_trust_copy_ref(protocolTrust).takeRetainedValue()
    guard
      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, MacProbeContract.serverName as CFString))
        == errSecSuccess,
      SecTrustSetAnchorCertificates(trust, [certificate] as CFArray) == errSecSuccess,
      SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess
    else {
      return TrustEvaluation(accepted: false, leafMatchedSessionCertificate: false)
    }
    var trustError: CFError?
    guard SecTrustEvaluateWithError(trust, &trustError),
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      chain.count == 1
    else {
      return TrustEvaluation(accepted: false, leafMatchedSessionCertificate: false)
    }
    let actualLeaf = SecCertificateCopyData(chain[0]) as Data
    let leafMatched =
      actualLeaf == certificateDER
      && PeerDigest.sha256(actualLeaf) == PeerDigest.sha256(certificateDER)
    return TrustEvaluation(
      accepted: leafMatched,
      leafMatchedSessionCertificate: leafMatched
    )
  }

  private static func securityObservation(
    _ connection: NWConnection,
    definition: NWProtocolDefinition,
    expectedALPN: String,
    label: String
  ) throws -> SecurityObservation {
    let metadata: sec_protocol_metadata_t
    if definition == NWProtocolTLS.definition,
      let tls = connection.metadata(definition: definition) as? NWProtocolTLS.Metadata
    {
      metadata = tls.securityProtocolMetadata
    } else if definition == NWProtocolQUIC.definition,
      let quic = connection.metadata(definition: definition) as? NWProtocolQUIC.Metadata,
      quic.negotiatedALPN == expectedALPN,
      quic.streamIdentifier
        == PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier
    {
      metadata = quic.securityProtocolMetadata
    } else {
      throw MacProbeError.protocolMismatch("\(label) security metadata")
    }
    let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata)
    let cipher = sec_protocol_metadata_get_negotiated_tls_ciphersuite(metadata)
    let earlyDataAccepted = sec_protocol_metadata_get_early_data_accepted(metadata)
    guard version == .TLSv13,
      (0x1301...0x1305).contains(cipher.rawValue),
      let negotiated = sec_protocol_metadata_get_negotiated_protocol(metadata),
      String(cString: negotiated) == expectedALPN,
      earlyDataAccepted == false
    else {
      throw MacProbeError.protocolMismatch("\(label) negotiated security")
    }
    return SecurityObservation(
      tlsVersion: version.rawValue,
      cipherSuite: cipher.rawValue,
      alpn: expectedALPN,
      earlyDataAccepted: earlyDataAccepted
    )
  }
}
