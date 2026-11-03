import CFWCredentialTransport
import CFWCredentialVault
import CryptoKit
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions
import Testing

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

// How start failures cross the bridge: the native configuration identity,
// preference and extension errors, failure stages, their recovery meaning, and
// endpoint failures.
extension NativeBridgeStartCommandIntegrationTests {
  @Test func directIPv4HostRouteParticipatesInTheNativeConfigurationIdentity() throws {
    let ordinary = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(ipv6Enabled: true)
    )
    let excluded = try startRequest(
      tunnelOptions: try TunnelNetworkOptions(
        ipv6Enabled: true,
        directIPv4Hosts: [TunnelNetworkOptions.releasePacketTransportIPv4]
      )
    )

    #expect(ordinary.configJSON == excluded.configJSON)
    #expect(ordinary.configContentDigest == excluded.configContentDigest)
    #expect(ordinary.configDigest != excluded.configDigest)
    #expect(excluded.tunnelOptions?.directIPv4Hosts == ["35.194.216.98"])
  }

  @Test func preferenceNSErrorMappingPreservesProvenanceAndIgnoresDiagnosticPolicy() {
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.preferenceMutationUncertain)
        .responseFailure.code == .busy)
    #expect(
      NativeBridgeCoordinator.map(
        AppleNetworkError.preferenceMutationJournalUnavailable("injected")
      ).responseFailure.code == .cleanupUnproven)
    let permission = NetworkExtensionOperationFailure(
      domain: NSPOSIXErrorDomain,
      code: Int(POSIXErrorCode.EPERM.rawValue),
      diagnostic: "operation not permitted"
    )
    let permissionFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.preferenceSaveFailed(permission)
    )
    let permissionCode: NativeBridgeErrorCode
    let permissionMessage: String
    switch permissionFailure {
    case .failure(let code, let message):
      permissionCode = code
      permissionMessage = message
    }
    #expect(permissionCode == .permissionDenied)
    #expect(permissionMessage.contains("preference save failed"))
    #expect(!permissionMessage.contains("(operation)"))
    #expect(permissionMessage.contains("\(permission.domain):\(permission.code)"))

    let readWrite = NetworkExtensionOperationFailure(
      domain: NEVPNErrorDomain,
      code: NEVPNError.configurationReadWriteFailed.rawValue,
      diagnostic: "permission denied text must not change classification"
    )
    let readWriteFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.preferenceLoadFailed(readWrite)
    )
    let readWriteCode: NativeBridgeErrorCode
    let readWriteMessage: String
    switch readWriteFailure {
    case .failure(let code, let message):
      readWriteCode = code
      readWriteMessage = message
    }
    #expect(readWriteCode == .unavailable)
    #expect(readWriteMessage.contains("preference load failed"))
    #expect(!readWriteMessage.contains("(operation)"))
    #expect(readWriteMessage.contains("\(readWrite.domain):\(readWrite.code)"))

    let authorizationRequired = NativeBridgeCoordinator.map(
      AppleNetworkError.systemExtensionInstallationFailed(
        domain: OSSystemExtensionErrorDomain,
        code: OSSystemExtensionError.authorizationRequired.rawValue,
        message: "authorization required"
      )
    ).responseFailure
    #expect(authorizationRequired.code == .approvalDenied)
    let unknownSystemExtensionFailure = NativeBridgeCoordinator.map(
      AppleNetworkError.systemExtensionInstallationFailed(
        domain: OSSystemExtensionErrorDomain,
        code: OSSystemExtensionError.unknown.rawValue,
        message: "authorization required text is not policy"
      )
    ).responseFailure
    #expect(unknownSystemExtensionFailure.code == .unavailable)
  }

  @Test func extensionValidationFailureRemainsDistinctAcrossTheBridge() throws {
    let mapped = NativeBridgeCoordinator.map(
      AppleNetworkError.systemExtensionInstallationFailed(
        domain: OSSystemExtensionErrorDomain,
        code: OSSystemExtensionError.validationFailed.rawValue,
        message: "private diagnostic")
    )
    .responseFailure
    #expect(mapped.code == .systemExtensionValidationFailed)
    #expect(mapped.message.contains("extension configuration or signature"))
    let encoded = try JSONEncoder().encode(mapped)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("private diagnostic"))
    #expect(try JSONDecoder().decode(NativeBridgeFailure.self, from: encoded) == mapped)
  }

  @Test func proxyFailureStageIsPreservedWithoutRawDiagnostics() throws {
    let cases: [(String, NativeBridgeErrorCode)] = [
      ("proxy-configuration-failed", .systemProxyConfigurationFailed),
      ("proxy-engine-creation-failed", .systemProxyRuntimeFailed),
      ("proxy-engine-start-failed", .systemProxyRuntimeFailed),
      ("system-proxy-preferences-failed", .systemProxyPreferencesFailed),
      ("proxy-ownership-journal-failed", .systemProxyJournalFailed),
      ("proxy-engine-lease-failed", .systemProxyAuthorityFailed),
    ]
    for (code, expected) in cases {
      let failure = EngineFailure(code: code, message: "private credential", isRetryable: false)
      let mapped = NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(failure))
        .responseFailure
      #expect(mapped.code == expected)
      #expect(mapped.message == expected.stableMessage)
      let encoded = try JSONEncoder().encode(mapped)
      #expect(!String(decoding: encoded, as: UTF8.self).contains("private credential"))
      #expect(try JSONDecoder().decode(NativeBridgeFailure.self, from: encoded) == mapped)
    }
  }

  @Test func proxyAuthorityAndCleanupErrorsRetainTheirRecoveryMeaning() throws {
    // Each Authority error the ProxyAgent passes on survives the engine
    // protocol, whose codes admit no underscore, and keeps its meaning.
    for code in AuthorityErrorCode.allCases {
      let sent = EngineFailure(.authority(code), message: "private diagnostic")
      let failure = try #require(
        try ProtocolCodec.decodeResponse(
          ProtocolCodec.encode(ResponseEnvelope(requestID: RequestID(), failure: sent))
        ).failure)
      let mapped = NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(failure))
        .responseFailure
      #expect(mapped.code == code.nativeBridgeCode)
      #expect(mapped.message == code.stableMessage)
    }
    // A ProxyAgent whose libbox runtime could not be closed reports it from a
    // failed start (inside its cleanup failure) or from a stop.
    for code in ["proxy-cleanup-failed", "proxy-engine-unclosable"] {
      let cleanup = EngineFailure(
        code: code, message: "private cleanup diagnostic", isRetryable: false)
      let mapped = NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(cleanup))
        .responseFailure
      #expect(mapped.code == .cleanupUnproven, "\(code)")
      #expect(mapped.message == NativeBridgeErrorCode.cleanupUnproven.stableMessage)
    }
    let tunnel = NativeBridgeCoordinator.map(
      AppleNetworkError.providerFailure(TunnelStartupFailure.engineUnclosable)
    ).responseFailure
    #expect(tunnel.code == .cleanupUnproven)
    #expect(tunnel.message == NativeBridgeErrorCode.cleanupUnproven.stableMessage)
  }

  @Test func existingProxyFailureRemainsSpecificWithoutEchoingSuppliedDiagnostics() throws {
    let failure = EngineFailure(
      code: "existing-system-proxy", message: "private-source-value", isRetryable: false)
    let mapped = NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(failure))
      .responseFailure
    #expect(mapped.code == .existingSystemProxy)
    #expect(mapped.message.contains("Another system proxy is enabled"))
    let wire = try JSONEncoder().encode(mapped)
    #expect(!String(decoding: wire, as: UTF8.self).contains("private-source-value"))
    #expect(try JSONDecoder().decode(NativeBridgeFailure.self, from: wire) == mapped)
  }

  @Test func endpointFailureMappingRequiresAnExactNonRetryableOwnerRole() {
    let mixed = EngineFailure(
      code: "mixed-endpoint-in-use", message: "mixed occupied", isRetryable: false)
    let controller = EngineFailure(
      code: "controller-endpoint-in-use", message: "controller occupied", isRetryable: false)
    let retryableController = EngineFailure(
      code: "controller-endpoint-in-use", message: "invalid retry policy", isRetryable: true)
    let nearMatch = EngineFailure(
      code: "controller-endpoint-in-use-now", message: "near match", isRetryable: false)

    #expect(
      NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(mixed))
        .responseFailure.code == .mixedEndpointInUse)
    #expect(
      NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(controller))
        .responseFailure.code == .controllerEndpointInUse)
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.providerFailure(controller))
        .responseFailure.code == .controllerEndpointInUse)
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.providerFailure(mixed))
        .responseFailure.code == .identityRejected)
    #expect(
      NativeBridgeCoordinator.map(ProxyAgentHostError.agentFailure(retryableController))
        .responseFailure.code == .identityRejected)
    #expect(
      NativeBridgeCoordinator.map(AppleNetworkError.providerFailure(nearMatch))
        .responseFailure.code == .internal)
  }
}
