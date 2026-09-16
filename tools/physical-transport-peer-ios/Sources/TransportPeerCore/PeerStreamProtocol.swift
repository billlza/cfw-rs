import Foundation

public enum PeerService: String, CaseIterable, Sendable {
  case tcpSink
  case tls13Echo
  case quicEcho
}

public enum PeerStreamDecision: Equatable, Sendable {
  case readMore
  case complete(payload: Data, response: Data?)
  case reject
}

public enum PeerStreamProtocol {
  public static func evaluate(
    service: PeerService,
    buffer: Data,
    streamComplete: Bool
  ) -> PeerStreamDecision {
    switch service {
    case .tcpSink:
      guard buffer.count <= PeerContract.maximumPayloadBytes else { return .reject }
      return streamComplete ? .complete(payload: buffer, response: nil) : .readMore
    case .tls13Echo, .quicEcho:
      guard buffer.count <= PeerContract.maximumPayloadBytes + 2 else { return .reject }
      guard buffer.count >= 2 else { return streamComplete ? .reject : .readMore }
      let length = Int(buffer[buffer.startIndex]) << 8 | Int(buffer[buffer.startIndex + 1])
      guard 1...PeerContract.maximumPayloadBytes ~= length else { return .reject }
      let frameSize = length + 2
      guard buffer.count <= frameSize else { return .reject }
      if buffer.count < frameSize {
        return streamComplete ? .reject : .readMore
      }
      return .complete(payload: Data(buffer.dropFirst(2)), response: buffer)
    }
  }
}

public enum PeerCompletionDecision: Equatable, Sendable {
  case continueRunning
  case close
  case pairRequired
  case fail
}

public struct PeerSecurityObservation: Equatable, Sendable {
  public let transport: String
  public let tlsVersion: UInt16?
  public let cipherSuite: UInt16?
  public let alpn: String?
  public let earlyDataAccepted: Bool?

  public init(
    transport: String,
    tlsVersion: UInt16?,
    cipherSuite: UInt16?,
    alpn: String?,
    earlyDataAccepted: Bool?
  ) {
    self.transport = transport
    self.tlsVersion = tlsVersion
    self.cipherSuite = cipherSuite
    self.alpn = alpn
    self.earlyDataAccepted = earlyDataAccepted
  }
}

enum PeerEchoDeliveryDecision: Equatable, Sendable {
  case waitForDeliveryAcknowledgement(generation: UInt64)
  case sendDeliveryConfirmation(generation: UInt64)
  case ignore
  case resolve(
    disposition: PeerEvidenceDisposition,
    confirmationCompletion: PeerDeliveryConfirmationCompletion
  )
  case fail(reason: PeerFailureReason, phaseReached: PeerPhaseReached)
}

enum PeerAcknowledgementFinalContextPolicy {
  static func observed(contextIsFinal: Bool) -> Bool {
    contextIsFinal
  }
}

struct PeerEchoSendDisposition: Equatable, Sendable {
  let usesFinalContext: Bool
  let completesContext: Bool
}

enum PeerEchoSendPlan {
  static let echo = PeerEchoSendDisposition(
    usesFinalContext: false,
    completesContext: true
  )
  static let confirmation = PeerEchoSendDisposition(
    usesFinalContext: false,
    completesContext: true
  )
  static let quicConfirmation = PeerEchoSendDisposition(
    usesFinalContext: true,
    completesContext: true
  )
}

enum PeerEchoResolutionGuard {
  static func failureReason(
    activeConnectionCount: Int,
    targetIsActive: Bool
  ) -> PeerFailureReason? {
    guard activeConnectionCount == 1, targetIsActive else {
      return .connectionOverlap
    }
    return nil
  }
}

enum PeerConnectionAdmissionGuard {
  static func failureReason(activeConnectionCount: Int) -> PeerFailureReason? {
    guard activeConnectionCount == 0 else {
      return .connectionAdmissionOverlap
    }
    return nil
  }
}

enum PeerConnectionDeadlinePhase: Equatable, Sendable {
  case preSecurityHandshake
  case connectionProgress(trackerGeneration: UInt64?)

  var trackerGeneration: UInt64? {
    switch self {
    case .preSecurityHandshake:
      nil
    case .connectionProgress(let trackerGeneration):
      trackerGeneration
    }
  }

  var timeoutSeconds: TimeInterval {
    switch self {
    case .preSecurityHandshake:
      PeerContract.preSecurityHandshakeDeadlineSeconds
    case .connectionProgress:
      PeerContract.connectionProgressDeadlineSeconds
    }
  }

  var cancellationMode: PeerConnectionCancellationMode {
    switch self {
    case .preSecurityHandshake, .connectionProgress(trackerGeneration: nil):
      .immediate
    case .connectionProgress:
      .graceful
    }
  }
}

enum PeerConnectionCancellationMode: Equatable, Sendable {
  case graceful
  case immediate
}

struct PeerConnectionDeadlineTicket: Equatable, Sendable {
  let token: UInt64
  let phase: PeerConnectionDeadlinePhase

  var trackerGeneration: UInt64? {
    phase.trackerGeneration
  }
}

struct PeerConnectionDeadlineSchedule: Equatable, Sendable {
  private(set) var currentToken: UInt64 = 0

  mutating func renew(phase: PeerConnectionDeadlinePhase) -> PeerConnectionDeadlineTicket {
    currentToken += 1
    return PeerConnectionDeadlineTicket(
      token: currentToken,
      phase: phase
    )
  }

  func isCurrent(_ ticket: PeerConnectionDeadlineTicket) -> Bool {
    ticket.token == currentToken
  }
}

struct PeerEchoDeliveryTracker: Equatable, Sendable {
  private enum ConfirmationCompletion: Equatable, Sendable {
    case processed
    case failed

    init(succeeded: Bool) {
      self = succeeded ? .processed : .failed
    }

    var receiptValue: PeerDeliveryConfirmationCompletion {
      switch self {
      case .processed: .processed
      case .failed: .failed
      }
    }
  }

  private enum Phase: Equatable, Sendable {
    case awaitingEchoSendCompletion
    case awaitingDeliveryAcknowledgement
    case awaitingDeliveryEvidence(completion: ConfirmationCompletion?)
    case resolved(
      disposition: PeerEvidenceDisposition,
      completion: PeerDeliveryConfirmationCompletion
    )
    case failed(reason: PeerFailureReason, phaseReached: PeerPhaseReached)
  }

  private var phase = Phase.awaitingEchoSendCompletion
  private(set) var callbackGeneration: UInt64 = 0

  mutating func observeEchoSendCompletion(
    generation: UInt64,
    succeeded: Bool
  ) -> PeerEchoDeliveryDecision {
    if let generationDecision = validateGeneration(generation) {
      return generationDecision
    }
    guard phase == .awaitingEchoSendCompletion else {
      return fail(.deliveryCallbackOutOfOrder)
    }
    guard succeeded else {
      return fail(.echoSendFailed)
    }
    callbackGeneration += 1
    phase = .awaitingDeliveryAcknowledgement
    return .waitForDeliveryAcknowledgement(generation: callbackGeneration)
  }

  mutating func observeDeliveryAcknowledgement(
    generation: UInt64,
    _ data: Data,
    failed: Bool,
    finalContextObserved: Bool
  ) -> PeerEchoDeliveryDecision {
    if let generationDecision = validateGeneration(generation) {
      return generationDecision
    }
    guard phase == .awaitingDeliveryAcknowledgement else {
      return fail(.deliveryCallbackOutOfOrder)
    }
    guard !failed else {
      return fail(.acknowledgementReceiveFailed)
    }
    guard data == PeerContract.deliveryAcknowledgement else {
      return fail(.acknowledgementInvalid)
    }
    guard finalContextObserved else {
      return fail(.acknowledgementNotFinal)
    }
    callbackGeneration += 1
    phase = .awaitingDeliveryEvidence(completion: nil)
    return .sendDeliveryConfirmation(generation: callbackGeneration)
  }

  mutating func observeDeliveryConfirmationCompletion(
    generation: UInt64,
    succeeded: Bool
  ) -> PeerEchoDeliveryDecision {
    if let generationDecision = validateGeneration(generation) {
      return generationDecision
    }
    let observedCompletion = ConfirmationCompletion(succeeded: succeeded)
    switch phase {
    case .awaitingDeliveryEvidence(let completion):
      if let completion {
        return completion == observedCompletion
          ? .ignore
          : fail(.deliveryCallbackConflict)
      }
      return resolve(
        disposition: .pairRequired,
        confirmationCompletion: observedCompletion.receiptValue
      )
    case .resolved(_, let completion):
      return completion == observedCompletion.receiptValue
        ? .ignore
        : fail(.deliveryCallbackConflict)
    case .failed:
      return .ignore
    default:
      return fail(.deliveryCallbackOutOfOrder)
    }
  }

  mutating func observeUnexpectedTrailingBytes(
    generation: UInt64
  ) -> PeerEchoDeliveryDecision {
    if let generationDecision = validateGeneration(generation) {
      return generationDecision
    }
    switch phase {
    case .awaitingDeliveryEvidence:
      return fail(.unexpectedTrailingBytes)
    case .resolved:
      return fail(.deliveryCallbackConflict)
    case .failed:
      return .ignore
    default:
      return fail(.deliveryCallbackOutOfOrder)
    }
  }

  mutating func observeDeadline(generation: UInt64) -> PeerEchoDeliveryDecision {
    if let generationDecision = validateGeneration(generation) {
      return generationDecision
    }
    switch phase {
    case .awaitingDeliveryEvidence(nil):
      return resolve(
        disposition: .pairRequired,
        confirmationCompletion: .unobserved
      )
    case .resolved, .failed:
      return .ignore
    default:
      return fail(.connectionDeadlineExpired)
    }
  }

  private mutating func resolve(
    disposition: PeerEvidenceDisposition,
    confirmationCompletion: PeerDeliveryConfirmationCompletion
  ) -> PeerEchoDeliveryDecision {
    phase = .resolved(
      disposition: disposition,
      completion: confirmationCompletion
    )
    return .resolve(
      disposition: disposition,
      confirmationCompletion: confirmationCompletion
    )
  }

  private mutating func validateGeneration(
    _ generation: UInt64
  ) -> PeerEchoDeliveryDecision? {
    if generation < callbackGeneration {
      return .ignore
    }
    if generation > callbackGeneration {
      return fail(.deliveryCallbackOutOfOrder)
    }
    return nil
  }

  private mutating func fail(_ reason: PeerFailureReason) -> PeerEchoDeliveryDecision {
    let phaseReached = currentPhaseReached
    phase = .failed(reason: reason, phaseReached: phaseReached)
    return .fail(reason: reason, phaseReached: phaseReached)
  }

  private var currentPhaseReached: PeerPhaseReached {
    switch phase {
    case .awaitingEchoSendCompletion:
      .payloadReceived
    case .awaitingDeliveryAcknowledgement:
      .echoCompleted
    case .awaitingDeliveryEvidence:
      .deliveryConfirmationSubmitted
    case .resolved:
      .deliveryEvidenceObserved
    case .failed(_, let phaseReached):
      phaseReached
    }
  }
}

public struct PeerCompletionTracker: Equatable, Sendable {
  public private(set) var outcomes = ConnectionOutcomes()

  public init() {}

  public mutating func recordResolution(
    service: PeerService,
    payload: Data,
    bytesSent: Int,
    security: PeerSecurityObservation,
    evidenceDisposition: PeerEvidenceDisposition,
    deliveryConfirmationCompletion: PeerDeliveryConfirmationCompletion?,
    peerTerminalObserved: Bool,
    deliveryAcknowledgementFinalContextObserved: Bool,
    sessionID: String
  ) -> PeerCompletionDecision {
    let expectedPayload: Data
    do {
      expectedPayload = try PeerProbePayload.payload(for: service, sessionID: sessionID)
    } catch {
      return .fail
    }
    guard payload == expectedPayload else { return .fail }

    guard outcome(for: service) == ConnectionOutcome(),
      evidenceDisposition != .unobserved
    else {
      return .fail
    }
    switch service {
    case .tcpSink:
      guard evidenceDisposition == .accepted,
        deliveryConfirmationCompletion == nil,
        peerTerminalObserved,
        !deliveryAcknowledgementFinalContextObserved
      else { return .fail }
    case .tls13Echo, .quicEcho:
      guard evidenceDisposition == .pairRequired,
        !peerTerminalObserved,
        deliveryAcknowledgementFinalContextObserved,
        deliveryConfirmationCompletion == .processed
          || deliveryConfirmationCompletion == .failed
          || deliveryConfirmationCompletion == .unobserved
      else { return .fail }
    }
    let expectedBytesSent = service == .tcpSink ? 0 : payload.count + 2
    guard bytesSent == expectedBytesSent,
      securityIsExpected(security, for: service)
    else { return .fail }

    var outcome = ConnectionOutcome()
    outcome.accepted = evidenceDisposition == .accepted ? 1 : 0
    outcome.evidenceDisposition = evidenceDisposition
    outcome.bytesReceived = payload.count
    outcome.bytesSent = bytesSent
    outcome.controlBytesReceived = service == .tcpSink ? 0 : 1
    outcome.controlBytesSubmitted = service == .tcpSink ? 0 : 1
    outcome.deliveryConfirmationCompletion = deliveryConfirmationCompletion
    outcome.peerTerminalObserved = peerTerminalObserved
    outcome.deliveryAcknowledgementFinalContextObserved =
      deliveryAcknowledgementFinalContextObserved
    outcome.transport = security.transport
    outcome.tlsVersion = security.tlsVersion
    outcome.cipherSuite = security.cipherSuite
    outcome.alpn = security.alpn
    outcome.earlyDataAccepted = security.earlyDataAccepted
    outcome.payloadSHA256 = PeerDigest.sha256(payload)
    setOutcome(outcome, for: service)

    switch resolvedStatus {
    case .none:
      return .continueRunning
    case .some(.closed):
      return .close
    case .some(.pairRequired):
      return .pairRequired
    case .some(.failed):
      return .fail
    }
  }

  private func securityIsExpected(
    _ observation: PeerSecurityObservation,
    for service: PeerService
  ) -> Bool {
    switch service {
    case .tcpSink:
      return observation
        == PeerSecurityObservation(
          transport: "tcp4",
          tlsVersion: nil,
          cipherSuite: nil,
          alpn: nil,
          earlyDataAccepted: nil
        )
    case .tls13Echo, .quicEcho:
      let expectedTransport = service == .tls13Echo ? "tls13-tcp4" : "quic-tls13"
      let expectedALPN = service == .tls13Echo ? PeerContract.tlsALPN : PeerContract.quicALPN
      guard let cipherSuite = observation.cipherSuite else { return false }
      return observation.transport == expectedTransport
        && observation.tlsVersion == 0x0304
        && (0x1301...0x1305).contains(cipherSuite)
        && observation.alpn == expectedALPN
        && observation.earlyDataAccepted == false
    }
  }

  public var resolvedStatus: PeerResultStatus? {
    let dispositions = [
      outcomes.tcpSink.evidenceDisposition,
      outcomes.tls13Echo.evidenceDisposition,
      outcomes.quicEcho.evidenceDisposition,
    ]
    guard !dispositions.contains(.unobserved) else { return nil }
    return dispositions.contains(.pairRequired) ? .pairRequired : .closed
  }

  public var allServicesAccepted: Bool {
    resolvedStatus == .closed
  }

  private func outcome(for service: PeerService) -> ConnectionOutcome {
    switch service {
    case .tcpSink: outcomes.tcpSink
    case .tls13Echo: outcomes.tls13Echo
    case .quicEcho: outcomes.quicEcho
    }
  }

  private mutating func setOutcome(_ outcome: ConnectionOutcome, for service: PeerService) {
    switch service {
    case .tcpSink: outcomes.tcpSink = outcome
    case .tls13Echo: outcomes.tls13Echo = outcome
    case .quicEcho: outcomes.quicEcho = outcome
    }
  }
}

enum PeerNetworkShutdownResource: Hashable, Sendable {
  case listener(PeerService)
  case quicConnectionGroup
}

struct PeerNetworkShutdownTracker: Equatable, Sendable {
  let expectedResources: Set<PeerNetworkShutdownResource>
  private(set) var observedResources: Set<PeerNetworkShutdownResource> = []

  init(expectedResources: Set<PeerNetworkShutdownResource>) {
    self.expectedResources = expectedResources
  }

  mutating func observeCancellation(for resource: PeerNetworkShutdownResource) -> Bool {
    guard expectedResources.contains(resource) else { return false }
    let inserted = observedResources.insert(resource).inserted
    return inserted && observedResources == expectedResources
  }
}

enum PeerQUICMultiplexPhase: Equatable, Sendable {
  case idle
  case awaitingStream
  case streamActive
  case streamDraining
  case tunnelCancelling
  case closed
}

struct PeerQUICMultiplexTracker: Equatable, Sendable {
  private(set) var phase = PeerQUICMultiplexPhase.idle
  private(set) var tunnelAdmissionSequence: Int?
  private(set) var streamIdentifier: UInt64?

  mutating func admitTunnel(admissionSequence: Int) -> Bool {
    guard phase == .idle, admissionSequence > 0 else { return false }
    phase = .awaitingStream
    tunnelAdmissionSequence = admissionSequence
    return true
  }

  mutating func admitStream() -> Bool {
    guard phase == .awaitingStream else { return false }
    phase = .streamActive
    return true
  }

  mutating func observeStreamReady(identifier: UInt64) -> Bool {
    guard phase == .streamActive else { return false }
    if let streamIdentifier {
      return streamIdentifier == identifier
    }
    guard identifier == PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier else {
      return false
    }
    streamIdentifier = identifier
    return true
  }

  mutating func beginStreamDrain() -> Bool {
    guard phase == .streamActive,
      streamIdentifier == PeerContract.clientInitiatedBidirectionalQUICStreamIdentifier
    else { return false }
    phase = .streamDraining
    return true
  }

  mutating func observeStreamTerminal() -> Bool {
    guard phase == .streamDraining else { return false }
    phase = .tunnelCancelling
    return true
  }

  mutating func observeTunnelCancelled() -> Bool {
    guard phase == .tunnelCancelling else { return false }
    phase = .closed
    return true
  }

  var blockingPhase: PeerPhaseReached {
    switch phase {
    case .idle, .awaitingStream:
      .connectionAccepted
    case .streamActive:
      streamIdentifier == nil ? .connectionAccepted : .securityReady
    case .streamDraining, .tunnelCancelling:
      .deliveryEvidenceObserved
    case .closed:
      .completionResolved
    }
  }
}

struct LocalNetworkPrimerEvidenceTracker: Equatable, Sendable {
  let startedAt: Date
  private(set) var serviceRegisteredAt: Date?
  private(set) var listenerReadyAt: Date?
  private(set) var listenerCancelledAt: Date?

  init(startedAt: Date) {
    self.startedAt = startedAt
  }

  mutating func observeServiceRegistered(at date: Date) throws -> Bool {
    guard serviceRegisteredAt == nil, date >= startedAt, listenerCancelledAt == nil else {
      throw PeerContractError.malformed("primer service-registration state")
    }
    serviceRegisteredAt = date
    return canCancel
  }

  mutating func observeListenerReady(at date: Date) throws -> Bool {
    guard listenerReadyAt == nil, date >= startedAt, listenerCancelledAt == nil else {
      throw PeerContractError.malformed("primer listener-ready state")
    }
    listenerReadyAt = date
    return canCancel
  }

  mutating func observeListenerCancelled(at date: Date) throws {
    guard listenerCancelledAt == nil,
      let serviceRegisteredAt,
      let listenerReadyAt,
      date >= serviceRegisteredAt,
      date >= listenerReadyAt
    else {
      throw PeerContractError.malformed("primer listener-cancelled state")
    }
    listenerCancelledAt = date
  }

  var canCancel: Bool {
    serviceRegisteredAt != nil && listenerReadyAt != nil && listenerCancelledAt == nil
  }

  var isProven: Bool {
    canCancel == false
      && serviceRegisteredAt != nil
      && listenerReadyAt != nil
      && listenerCancelledAt != nil
  }
}
