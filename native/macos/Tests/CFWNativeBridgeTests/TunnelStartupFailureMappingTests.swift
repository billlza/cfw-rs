import CFWAppleNetwork
import CFWSharedProtocol
import Testing

@testable import CFWNativeBridge

struct TunnelStartupFailureMappingTests {
  @Test func expiredTicketReachesTheRustBoundaryWithoutBecomingUnavailable() {
    let mapped = NativeBridgeCoordinator.map(
      AppleNetworkError.providerFailure(TunnelStartupFailure.ticketExpired))
    #expect(mapped.responseFailure.code == .ticketExpired)
  }

  @Test func providerStartTimeoutReachesTheRustBoundaryAsItsOwnCause() {
    let mapped = NativeBridgeCoordinator.map(
      AppleNetworkError.providerFailure(TunnelStartupFailure.engineStartTimedOut))
    #expect(mapped.responseFailure.code == .engineStartTimedOut)
    #expect(
      mapped.responseFailure.message == NativeBridgeErrorCode.engineStartTimedOut.stableMessage)
    // The same wire code and text as the Rust BackendErrorKind::EngineStartTimedOut.
    #expect(NativeBridgeErrorCode.engineStartTimedOut.rawValue == "engine_start_timed_out")
    #expect(
      NativeBridgeErrorCode.engineStartTimedOut.stableMessage
        == "The engine did not finish starting in time and was stopped, usually because rule "
        + "datasets were still downloading. Datasets that finished are kept for the next start.")
  }

  /// The code and message of the Host's own error for `error`. The Rust
  /// boundary sends only a code's stable message anyway, so the message
  /// checked here is the one the Host composes its own reports from.
  private func hostFailure(_ error: any Error) -> (code: NativeBridgeErrorCode, message: String) {
    switch NativeBridgeCoordinator.map(error) {
    case .failure(let code, let message): (code, message)
    }
  }

  /// What each ProxyAgent failure means at the Rust boundary, after crossing
  /// XPC. The table is the review point for every code and its mapping.
  @Test func everyProxyAgentFailureReachesRustAsItsNativeCode() throws {
    let expected: [ProxyAgentFailureCode: NativeBridgeErrorCode] = [
      .invalidConfigurationSlot: .internal,
      .lifecycleConflict: .busy,
      .startupCancelled: .busy,
      .staleStopRequest: .identityRejected,
      .stopWithoutSession: .identityRejected,
      .recoveryBlocked: .cleanupUnproven,
      .authorizationRequired: .permissionDenied,
      .engineLeaseFailed: .systemProxyAuthorityFailed,
      .configurationFailed: .systemProxyConfigurationFailed,
      .engineCreationFailed: .systemProxyRuntimeFailed,
      .engineStartFailed: .systemProxyRuntimeFailed,
      .engineStartTimedOut: .engineStartTimedOut,
      .mixedEndpointInUse: .mixedEndpointInUse,
      .controllerEndpointInUse: .controllerEndpointInUse,
      .listenerReadinessTimedOut: .systemProxyRuntimeFailed,
      .engineUnclosable: .cleanupUnproven,
      .engineCrashed: .systemProxyRuntimeFailed,
      .preferencesFailed: .systemProxyPreferencesFailed,
      .existingSystemProxy: .existingSystemProxy,
      .ownershipJournalFailed: .systemProxyJournalFailed,
      .ownershipConflict: .cleanupUnproven,
      .cleanupFailed: .cleanupUnproven,
      .startRequiresOwnerAuthorization: .internal,
      .missingStopGeneration: .internal,
      .wrongProcessBoundary: .internal,
      .invalidOwnerAuthorization: .identityRejected,
      .invalidRuntimeConfiguration: .identityRejected,
      .invalidValidationRequest: .configurationRejected,
      .validatorUnavailable: .unavailable,
      .configurationRejected: .systemProxyConfigurationFailed,
      .validatorFailed: .unavailable,
      .configurationCheckCleanupFailed: .unavailable,
      .profileProbeBusy: .unavailable,
      .profileProbeInvalid: .configurationRejected,
      .profileProbeFailed: .unavailable,
    ]
    #expect(Set(expected.keys) == Set(ProxyAgentFailureCode.allCases))
    for failure in ProxyAgentFailure.allCases {
      let received = try #require(
        try ProtocolCodec.decodeResponse(
          ProtocolCodec.encode(
            ResponseEnvelope(
              requestID: RequestID(),
              failure: EngineFailure(failure, message: "private diagnostic")))
        ).failure)
      let mapped = hostFailure(ProxyAgentHostError.agentFailure(received))
      switch failure {
      case .agent(let code):
        #expect(mapped.code == expected[code], "\(code)")
      case .authority(let code):
        #expect(mapped.code == code.nativeBridgeCode, "\(code)")
      }
      #expect(mapped.message == mapped.code.stableMessage, "\(failure)")
    }
  }

  /// What each Packet Tunnel failure means at the Rust boundary.
  @Test func everyPacketTunnelFailureReachesRustAsItsNativeCode() {
    let expected: [PacketTunnelFailureCode: NativeBridgeErrorCode] = [
      .providerUnavailable: .unavailable,
      .globalAuthorityUnavailable: .globalAuthorityUnavailable,
      .startTicketInvalid: .ticketInvalid,
      .startTicketExpired: .ticketExpired,
      .providerConfigurationMalformed: .configurationRejected,
      .configurationSlotInvalid: .internal,
      .lifecycleConflict: .busy,
      .startupCancelled: .busy,
      .configurationInvalid: .configurationRejected,
      .engineCreationFailed: .unavailable,
      .packetPumpSetupFailed: .unavailable,
      .packetPumpFailed: .unavailable,
      .engineStartFailed: .unavailable,
      .engineStartTimedOut: .engineStartTimedOut,
      .mixedEndpointInUse: .identityRejected,
      .controllerEndpointInUse: .controllerEndpointInUse,
      .engineUnclosable: .cleanupUnproven,
      .networkSettingsFailed: .unavailable,
      .unsupportedCommand: .internal,
      .unknownConnectionStatus: .unavailable,
    ]
    #expect(Set(expected.keys) == Set(PacketTunnelFailureCode.allCases))
    for code in PacketTunnelFailureCode.allCases {
      let mapped = hostFailure(
        AppleNetworkError.providerFailure(EngineFailure(code, message: "private diagnostic")))
      #expect(mapped.code == expected[code], "\(code)")
      #expect(mapped.message == mapped.code.stableMessage, "\(code)")
    }
  }

  /// A known code whose retry flag contradicts it did not come from this
  /// build's owner, so the Host rejects the reply instead of trusting either.
  @Test func ownerFailuresWithAContradictingRetryFlagAreRejected() {
    for code in [ProxyAgentFailureCode.engineStartTimedOut, .profileProbeFailed] {
      let flipped = EngineFailure(
        code: code.rawValue, message: "A contradicting reply.", isRetryable: !code.isRetryable)
      #expect(
        NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(flipped))
          .responseFailure.code == .identityRejected, "\(code)")
    }
    let authority = EngineFailure(
      code: ProxyAgentFailure.authority(.quarantined).code, message: "A contradicting reply.",
      isRetryable: true)
    #expect(
      NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(authority))
        .responseFailure.code == .identityRejected)
    let tunnel = EngineFailure(
      code: PacketTunnelFailureCode.startTicketExpired.rawValue, message: "A contradicting reply.",
      isRetryable: false)
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.providerFailure(tunnel))
        .responseFailure.code == .identityRejected)
  }

  /// The Host and both owners ship in one signed app, so a code the Host does
  /// not know is an internal fault. Reporting it as a rejected configuration
  /// would send the user to edit a profile that is not at fault.
  @Test func ownerFailuresTheHostDoesNotKnowAreInternalFaults() {
    for (isRetryable, expected) in [
      (false, NativeBridgeErrorCode.internal), (true, NativeBridgeErrorCode.unavailable),
    ] {
      let failure = EngineFailure(
        code: "future-owner-failure", message: "A failure from a future owner.",
        isRetryable: isRetryable)
      #expect(
        NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(failure))
          .responseFailure.code == expected)
      #expect(
        NativeBridgeCoordinator.map(AppleNetworkError.providerFailure(failure))
          .responseFailure.code == expected)
    }
  }

  /// The timeout crosses XPC as the ProxyAgent's own code, which the engine
  /// protocol admits, and reaches Rust as the shared native code.
  @Test func proxyAgentStartTimeoutReachesTheRustBoundaryAsItsOwnCause() throws {
    let sent = EngineFailure(
      .agent(.engineStartTimedOut),
      message: "System Proxy runtime startup did not finish in time and was interrupted.")
    let received = try #require(
      try ProtocolCodec.decodeResponse(
        ProtocolCodec.encode(ResponseEnvelope(requestID: RequestID(), failure: sent))
      ).failure)
    let timedOut = NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(received))
    #expect(timedOut.responseFailure.code == .engineStartTimedOut)
    #expect(
      timedOut.responseFailure.message == NativeBridgeErrorCode.engineStartTimedOut.stableMessage)
    let failed = NativeBridgeCoordinator.map(
      ProxyAgentHostError.agentFailure(
        EngineFailure(.agent(.engineStartFailed), message: "System Proxy runtime startup failed.")))
    #expect(failed.responseFailure.code == .systemProxyRuntimeFailed)
  }
}
