import Foundation
import Testing

@testable import CFWSharedProtocol

/// The codes the owners send, spelled as they travel, and whether each says a
/// retry may succeed. A Host rejects a reply whose flag contradicts its own
/// table, and an older Host or owner of the same lineage reads both, so a
/// renamed code or a flipped flag has to show up here.
private let proxyAgentWireCodes: [ProxyAgentFailureCode: (code: String, retryable: Bool)] = [
  .invalidConfigurationSlot: ("invalid-configuration-slot", false),
  .lifecycleConflict: ("proxy-lifecycle-conflict", false),
  .startupCancelled: ("proxy-startup-cancelled", false),
  .staleStopRequest: ("stale-stop-request", false),
  .stopWithoutSession: ("proxy-stop-without-session", false),
  .recoveryBlocked: ("proxy-recovery-blocked", false),
  .authorizationRequired: ("system-proxy-authorization-required", false),
  .engineLeaseFailed: ("proxy-engine-lease-failed", false),
  .configurationFailed: ("proxy-configuration-failed", false),
  .engineCreationFailed: ("proxy-engine-creation-failed", false),
  .engineStartFailed: ("proxy-engine-start-failed", false),
  .engineStartTimedOut: ("proxy-engine-start-timed-out", false),
  .mixedEndpointInUse: ("mixed-endpoint-in-use", false),
  .controllerEndpointInUse: ("controller-endpoint-in-use", false),
  .listenerReadinessTimedOut: ("proxy-listener-readiness-timeout", false),
  .engineUnclosable: ("proxy-engine-unclosable", false),
  .engineCrashed: ("proxy-engine-crashed", false),
  .preferencesFailed: ("system-proxy-preferences-failed", false),
  .existingSystemProxy: ("existing-system-proxy", false),
  .ownershipJournalFailed: ("proxy-ownership-journal-failed", false),
  .ownershipConflict: ("system-proxy-ownership-conflict", false),
  .cleanupFailed: ("proxy-cleanup-failed", false),
  .startRequiresOwnerAuthorization: ("start-requires-owner-authorization", false),
  .missingStopGeneration: ("missing-stop-generation", false),
  .wrongProcessBoundary: ("wrong-process-boundary", false),
  .invalidOwnerAuthorization: ("invalid-owner-authorization", false),
  .invalidRuntimeConfiguration: ("invalid-runtime-configuration", false),
  .invalidValidationRequest: ("invalid-validation-request", false),
  .validatorUnavailable: ("configuration-validator-unavailable", true),
  .configurationRejected: ("configuration-rejected", false),
  .validatorFailed: ("configuration-validator-failed", true),
  .configurationCheckCleanupFailed: ("configuration-check-cleanup-failed", true),
  .profileProbeBusy: ("profile-probe-busy", true),
  .profileProbeInvalid: ("profile-probe-invalid", false),
  .profileProbeFailed: ("profile-probe-failed", true),
]
private let packetTunnelWireCodes: [PacketTunnelFailureCode: (code: String, retryable: Bool)] = [
  .providerUnavailable: ("tunnel-provider-unavailable", true),
  .globalAuthorityUnavailable: ("global-authority-unavailable", false),
  .startTicketInvalid: ("tunnel-start-ticket-invalid", false),
  .startTicketExpired: ("tunnel-start-ticket-expired", true),
  .providerConfigurationMalformed: ("tunnel-provider-configuration-malformed", false),
  .configurationSlotInvalid: ("tunnel-configuration-slot-invalid", false),
  .lifecycleConflict: ("tunnel-lifecycle-conflict", false),
  .startupCancelled: ("tunnel-startup-cancelled", false),
  .configurationInvalid: ("tunnel-configuration-invalid", false),
  .engineCreationFailed: ("tunnel-engine-creation-failed", true),
  .packetPumpSetupFailed: ("tunnel-packet-pump-setup-failed", true),
  .packetPumpFailed: ("tunnel-packet-pump-failed", true),
  .engineStartFailed: ("tunnel-engine-start-failed", true),
  .engineStartTimedOut: ("tunnel-engine-start-timed-out", false),
  .mixedEndpointInUse: ("mixed-endpoint-in-use", false),
  .controllerEndpointInUse: ("controller-endpoint-in-use", false),
  .engineUnclosable: ("tunnel-engine-unclosable", false),
  .networkSettingsFailed: ("tunnel-network-settings-failed", true),
  .unsupportedCommand: ("unsupported-provider-command", false),
  .unknownConnectionStatus: ("unknown-nevpn-status", false),
]
/// Sends `failure` the way an owner replies and returns what the Host decodes.
private func roundTrip(_ failure: EngineFailure) throws -> EngineFailure? {
  try ProtocolCodec.decodeResponse(
    ProtocolCodec.encode(ResponseEnvelope(requestID: RequestID(), failure: failure))
  ).failure
}

@Test func everyProxyAgentFailureCrossesTheEngineProtocolUnderItsOwnCode() throws {
  #expect(Set(proxyAgentWireCodes.keys) == Set(ProxyAgentFailureCode.allCases))
  for code in ProxyAgentFailureCode.allCases {
    #expect(code.rawValue == proxyAgentWireCodes[code]?.code, "\(code)")
    #expect(code.isRetryable == proxyAgentWireCodes[code]?.retryable, "\(code)")
    // The Authority family owns this prefix.
    #expect(!code.rawValue.hasPrefix("authority-"), "\(code)")
  }
  var codes = Set<String>()
  for failure in ProxyAgentFailure.allCases {
    #expect(codes.insert(failure.code).inserted, "\(failure) shares its code")
    let sent = EngineFailure(failure, message: "A ProxyAgent failure.")
    let received = try #require(try roundTrip(sent))
    #expect(received == sent)
    #expect(ProxyAgentFailure(code: received.code) == failure)
    #expect(received.isRetryable == failure.isRetryable)
  }
}

@Test func authorityErrorsTravelWithHyphensAndOnlyInTheirExactSpelling() {
  #expect(
    ProxyAgentFailure.authority(.globalAuthorityUnavailable).code
      == "authority-global-authority-unavailable")
  #expect(ProxyAgentFailure.authority(.busy).code == "authority-busy")
  #expect(
    ProxyAgentFailure(code: "authority-ticket-expired") == .authority(.ticketExpired))
  for code in [
    "authority-ticket_expired", "authority-", "authority-ticket-expired-", "authority-future-code",
    "authority-authorization-required", "future-owner-failure", "",
  ] {
    #expect(ProxyAgentFailure(code: code) == nil, "\(code)")
  }
}

@Test func everyPacketTunnelFailureCrossesTheEngineProtocolUnderItsOwnCode() throws {
  #expect(Set(packetTunnelWireCodes.keys) == Set(PacketTunnelFailureCode.allCases))
  var codes = Set<String>()
  for code in PacketTunnelFailureCode.allCases {
    #expect(code.rawValue == packetTunnelWireCodes[code]?.code, "\(code)")
    #expect(code.isRetryable == packetTunnelWireCodes[code]?.retryable, "\(code)")
    #expect(codes.insert(code.rawValue).inserted, "\(code) shares its code")
    let sent = EngineFailure(code, message: "A Packet Tunnel failure.")
    let received = try #require(try roundTrip(sent))
    #expect(received == sent)
    #expect(PacketTunnelFailureCode(rawValue: received.code) == code)
  }
  for failure in [
    TunnelStartupFailure.ticketExpired, TunnelStartupFailure.engineStartTimedOut,
    TunnelStartupFailure.engineUnclosable,
  ] {
    #expect(try roundTrip(failure) == failure)
  }
}
