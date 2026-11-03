import CFWSharedProtocol
import Foundation

extension AuthenticatedProxyAgentTransport {
  /// The wait for every ProxyAgent reply except a start, whose Agent replies only
  /// after its libbox start (`EngineStartBudget.proxyAgentStartReply`).
  public static let defaultReplyTimeout: Duration = .seconds(5)

  /// The Host's wait for a profile probe: the probe's own timeout plus the
  /// ordinary reply wait, inside which the ProxyAgent replies by its allowance
  /// (`ProxyAgentCallBudget.profileProbeReplyAllowance`).
  public static func profileProbeReplyTimeout(timeoutMS: UInt16) -> Duration {
    .milliseconds(Int64(timeoutMS)) + defaultReplyTimeout
  }

  /// Arms one production reply deadline.
  static let productionReplyDeadline: @Sendable (Duration) -> CallbackDeadlineScheduler = {
    CallbackDeadlineScheduler(timeout: $0)
  }

  public init(
    machServiceName: String,
    teamIdentifier: String,
    proxyAgentBundleIdentifier: String,
    currentCodeHash: ServiceCodeHash,
    serviceController: any ProxyAgentServiceControlling = SMProxyAgentServiceController(),
    replyTimeout: Duration = defaultReplyTimeout
  ) throws {
    try self.init(
      machServiceName: machServiceName,
      teamIdentifier: teamIdentifier,
      proxyAgentBundleIdentifier: proxyAgentBundleIdentifier,
      currentCodeHash: currentCodeHash,
      serviceController: serviceController,
      replyTimeout: replyTimeout,
      makeReplyDeadline: Self.productionReplyDeadline)
  }

  static func shouldRetireConnection(after error: Error) -> Bool {
    if error is CancellationError { return true }
    guard let error = error as? ProxyAgentHostError else { return false }
    switch error {
    case .transportTimedOut, .transportUnavailable, .malformedResponse, .responseMismatch:
      return true
    case .registrationRequiresApproval, .registrationUnavailable,
      .registrationFailed, .transportCapacityExceeded, .authorizationDenied,
      .authorizationPending, .authorizationFailed, .agentFailure:
      return false
    }
  }
}
