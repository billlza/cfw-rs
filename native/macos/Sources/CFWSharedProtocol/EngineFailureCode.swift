import Foundation

/// A failure the ProxyAgent reports to the Host. The raw values are the codes
/// on the wire, which `EngineFailure` limits to lowercase letters, digits and
/// hyphens, so every case can cross XPC.
public enum ProxyAgentFailureCode: String, CaseIterable, Sendable {
  case invalidConfigurationSlot = "invalid-configuration-slot"
  case lifecycleConflict = "proxy-lifecycle-conflict"
  case startupCancelled = "proxy-startup-cancelled"
  /// The stop names a generation other than the one the ProxyAgent holds.
  case staleStopRequest = "stale-stop-request"
  /// The ProxyAgent holds no session and has no record of stopping or failing
  /// the stop's generation, as after it ended and launchd started it again.
  case stopWithoutSession = "proxy-stop-without-session"
  case recoveryBlocked = "proxy-recovery-blocked"
  case authorizationRequired = "system-proxy-authorization-required"
  case engineLeaseFailed = "proxy-engine-lease-failed"
  case configurationFailed = "proxy-configuration-failed"
  case engineCreationFailed = "proxy-engine-creation-failed"
  case engineStartFailed = "proxy-engine-start-failed"
  case engineStartTimedOut = "proxy-engine-start-timed-out"
  case mixedEndpointInUse = "mixed-endpoint-in-use"
  case controllerEndpointInUse = "controller-endpoint-in-use"
  case listenerReadinessTimedOut = "proxy-listener-readiness-timeout"
  case engineUnclosable = "proxy-engine-unclosable"
  case engineCrashed = "proxy-engine-crashed"
  case preferencesFailed = "system-proxy-preferences-failed"
  case existingSystemProxy = "existing-system-proxy"
  case ownershipJournalFailed = "proxy-ownership-journal-failed"
  case ownershipConflict = "system-proxy-ownership-conflict"
  case cleanupFailed = "proxy-cleanup-failed"
  /// A start arrived without the one-use owner authorization.
  case startRequiresOwnerAuthorization = "start-requires-owner-authorization"
  case missingStopGeneration = "missing-stop-generation"
  case wrongProcessBoundary = "wrong-process-boundary"
  case invalidOwnerAuthorization = "invalid-owner-authorization"
  case invalidRuntimeConfiguration = "invalid-runtime-configuration"
  case invalidValidationRequest = "invalid-validation-request"
  case validatorUnavailable = "configuration-validator-unavailable"
  case configurationRejected = "configuration-rejected"
  case validatorFailed = "configuration-validator-failed"
  /// libbox accepted the configuration but could not close what it built to
  /// check it.
  case configurationCheckCleanupFailed = "configuration-check-cleanup-failed"
  case profileProbeBusy = "profile-probe-busy"
  case profileProbeInvalid = "profile-probe-invalid"
  case profileProbeFailed = "profile-probe-failed"
  /// A spent or retiring ProxyAgent refuses checks, probes and starts; the
  /// ProxyAgent macOS starts once it ended takes them.
  case agentEnding = "proxy-agent-ending"
  /// A configuration check, this one or an earlier one, ran past its reply.
  case configurationCheckTimedOut = "configuration-check-timed-out"
  /// A profile probe ran past its reply.
  case profileProbeTimedOut = "profile-probe-timed-out"

  /// Whether the same request may succeed when sent again.
  public var isRetryable: Bool {
    switch self {
    case .validatorUnavailable, .validatorFailed, .configurationCheckCleanupFailed,
      .profileProbeBusy, .profileProbeFailed, .agentEnding, .configurationCheckTimedOut,
      .profileProbeTimedOut:
      true
    case .invalidConfigurationSlot, .lifecycleConflict, .startupCancelled, .staleStopRequest,
      .stopWithoutSession, .recoveryBlocked, .authorizationRequired, .engineLeaseFailed,
      .configurationFailed, .engineCreationFailed, .engineStartFailed, .engineStartTimedOut,
      .mixedEndpointInUse, .controllerEndpointInUse, .listenerReadinessTimedOut,
      .engineUnclosable, .engineCrashed, .preferencesFailed, .existingSystemProxy,
      .ownershipJournalFailed, .ownershipConflict, .cleanupFailed,
      .startRequiresOwnerAuthorization, .missingStopGeneration, .wrongProcessBoundary,
      .invalidOwnerAuthorization, .invalidRuntimeConfiguration, .invalidValidationRequest,
      .configurationRejected, .profileProbeInvalid:
      false
    }
  }
}

/// What a ProxyAgent failure says: one of its own codes, or an Authority error
/// it passes on.
public enum ProxyAgentFailure: Hashable, Sendable {
  case agent(ProxyAgentFailureCode)
  case authority(AuthorityErrorCode)

  /// Authority error codes are spelled with underscores, which the engine
  /// protocol does not admit. They travel after this prefix with hyphens.
  private static let authorityPrefix = "authority-"

  public static var allCases: [ProxyAgentFailure] {
    ProxyAgentFailureCode.allCases.map(Self.agent) + AuthorityErrorCode.allCases.map(Self.authority)
  }

  /// The failure a wire code names, or nil for a code this build does not know.
  public init?(code: String) {
    if let agent = ProxyAgentFailureCode(rawValue: code) {
      self = .agent(agent)
      return
    }
    guard code.hasPrefix(Self.authorityPrefix) else { return nil }
    let spelling = code.dropFirst(Self.authorityPrefix.count)
    guard !spelling.contains("_"),
      let authority = AuthorityErrorCode(
        rawValue: spelling.replacingOccurrences(of: "-", with: "_"))
    else { return nil }
    self = .authority(authority)
  }

  /// The failure's code on the wire.
  public var code: String {
    switch self {
    case .agent(let code):
      code.rawValue
    case .authority(let code):
      Self.authorityPrefix + code.rawValue.replacingOccurrences(of: "_", with: "-")
    }
  }

  /// Whether the same request may succeed when sent again. An Authority error
  /// the ProxyAgent passes on is final for that request.
  public var isRetryable: Bool {
    switch self {
    case .agent(let code): code.isRetryable
    case .authority: false
    }
  }
}

/// A failure the Packet Tunnel provider reports, or that the Host observes in
/// Network Extension's own state. The raw values are the codes on the wire.
public enum PacketTunnelFailureCode: String, CaseIterable, Sendable {
  case providerUnavailable = "tunnel-provider-unavailable"
  case globalAuthorityUnavailable = "global-authority-unavailable"
  case startTicketInvalid = "tunnel-start-ticket-invalid"
  case startTicketExpired = "tunnel-start-ticket-expired"
  case providerConfigurationMalformed = "tunnel-provider-configuration-malformed"
  case configurationSlotInvalid = "tunnel-configuration-slot-invalid"
  case lifecycleConflict = "tunnel-lifecycle-conflict"
  case startupCancelled = "tunnel-startup-cancelled"
  case configurationInvalid = "tunnel-configuration-invalid"
  case engineCreationFailed = "tunnel-engine-creation-failed"
  case packetPumpSetupFailed = "tunnel-packet-pump-setup-failed"
  case packetPumpFailed = "tunnel-packet-pump-failed"
  case engineStartFailed = "tunnel-engine-start-failed"
  case engineStartTimedOut = "tunnel-engine-start-timed-out"
  case mixedEndpointInUse = "mixed-endpoint-in-use"
  case controllerEndpointInUse = "controller-endpoint-in-use"
  case engineUnclosable = "tunnel-engine-unclosable"
  case networkSettingsFailed = "tunnel-network-settings-failed"
  /// A provider message other than a snapshot request.
  case unsupportedCommand = "unsupported-provider-command"
  /// The Host's own observation: Network Extension reported a VPN status this
  /// build does not know.
  case unknownConnectionStatus = "unknown-nevpn-status"

  /// Whether the same request may succeed when sent again.
  public var isRetryable: Bool {
    switch self {
    case .providerUnavailable, .startTicketExpired, .engineCreationFailed,
      .packetPumpSetupFailed, .packetPumpFailed, .engineStartFailed, .networkSettingsFailed:
      true
    case .globalAuthorityUnavailable, .startTicketInvalid, .providerConfigurationMalformed,
      .configurationSlotInvalid, .lifecycleConflict, .startupCancelled, .configurationInvalid,
      .engineStartTimedOut, .mixedEndpointInUse, .controllerEndpointInUse, .engineUnclosable,
      .unsupportedCommand, .unknownConnectionStatus:
      false
    }
  }
}

extension EngineFailure {
  /// A ProxyAgent failure. Its code decides whether a retry may succeed.
  public init(_ failure: ProxyAgentFailure, message: String) {
    self.init(code: failure.code, message: message, isRetryable: failure.isRetryable)
  }

  /// A Packet Tunnel failure. Its code decides whether a retry may succeed.
  public init(_ code: PacketTunnelFailureCode, message: String) {
    self.init(code: code.rawValue, message: message, isRetryable: code.isRetryable)
  }
}
