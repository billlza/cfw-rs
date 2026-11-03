import Foundation
@preconcurrency import Network
import Security
import TransportPeerCore

struct SecurityObservation: Sendable {
  let tlsVersion: UInt16
  let cipherSuite: UInt16
  let alpn: String
  let earlyDataAccepted: Bool
}

struct TrustEvaluation: Sendable {
  let accepted: Bool
  let leafMatchedSessionCertificate: Bool
}

struct WrongLeafPinEvidenceSnapshot: Sendable {
  let verifyCallbackInvoked: Bool
  let leafMatchedSessionCertificate: Bool
  let verifyReturnedFalse: Bool
}

final class WrongLeafPinEvidence: @unchecked Sendable {
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

enum TrustMode: Sendable {
  case exactLeaf
  case wrongLeafPin(WrongLeafPinEvidence)
}

extension MacTransportProbe {
  static func plainTCPParameters() throws -> NWParameters {
    let parameters = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
    try configureBase(parameters)
    return parameters
  }

  static func tlsParameters(
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

  static func quicParameters(
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

  static func securityObservation(
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
