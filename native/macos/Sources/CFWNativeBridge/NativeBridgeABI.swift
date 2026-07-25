import CFWAppleNetwork
import CFWCredentialVault
import CFWSharedProtocol
import Foundation
@preconcurrency import Security

private struct HostSigningIdentity {
  let teamIdentifier: String

  static func current() throws -> HostSigningIdentity {
    guard Bundle.main.bundleIdentifier == "com.bill.clashformac" else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Native bridge is loaded by an unexpected host bundle."
      )
    }
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Unable to inspect the host signing identity."
      )
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "Unable to resolve the host static signing identity."
      )
    }
    var information: CFDictionary?
    guard
      SecCodeCopySigningInformation(
        staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
        == errSecSuccess,
      let values = information as? [CFString: Any],
      let teamIdentifier = values[kSecCodeInfoTeamIdentifier] as? String
    else {
      throw NativeBridgeExecutionError.failure(
        .identityRejected,
        "The host signature does not contain a Team ID."
      )
    }
    _ = try CodeIdentityRequirement(
      expectedTeamIdentifier: teamIdentifier,
      expectedBundleIdentifier: "com.bill.clashformac"
    )
    return HostSigningIdentity(teamIdentifier: teamIdentifier)
  }
}

private enum ProductionNativeBridge {
  static let coordinator: Result<NativeBridgeCoordinator, NativeBridgeExecutionError> = Result {
    let signing = try HostSigningIdentity.current()
    let teamIdentifier = signing.teamIdentifier
    let installer = OSSystemExtensionInstaller(
      extensionIdentifier: "com.bill.clashformac.packet-tunnel",
      approvalHandler: {}
    )
    // One shared, typed, bounded Host Authority client backs both the machine-wide
    // lease inspector and the Tunnel-start preparer. Its connection lifecycle
    // (bounded timeouts, invalidation/interruption) fails closed.
    let authorityClient = BoundedAuthorityXPCClient(remote: NSXPCGlobalAuthorityRemote())
    let tunnel = NetworkExtensionHostBridge(
      providerBundleIdentifier: "com.bill.clashformac.packet-tunnel",
      installer: installer,
      // Production stays fail-closed until an end-to-end signed Host→Authority
      // channel is provable; the concrete Authority-backed preparer is wired but
      // not selected until then.
      preparer: HostTunnelStartPreparerFactory.production(authority: authorityClient)
    )
    let proxy = try AuthenticatedProxyAgentTransport(
      machServiceName: "com.bill.clashformac.proxy-agent",
      teamIdentifier: teamIdentifier,
      proxyAgentBundleIdentifier: "com.bill.clashformac.proxy-agent"
    )
    let credentialVault = try CredentialVault(
      accessGroup: "\(teamIdentifier).com.bill.clashformac.credentials"
    )
    let configurationStore = try AppGroupConfigurationStore(
      appGroupIdentifier: "\(teamIdentifier).group.com.bill.clashformac"
    )
    return NativeBridgeCoordinator(
      proxy: proxy,
      tunnel: tunnel,
      configurationStore: configurationStore,
      engineLease: GlobalAuthorityEngineLeaseInspector(authority: authorityClient),
      credentialVault: credentialVault
    )
  }.mapError { error in
    if let error = error as? NativeBridgeExecutionError {
      return error
    }
    return .failure(
      .unavailable, "Native bridge initialization failed: \(error.localizedDescription)")
  }
}

private final class NativeBridgeABIExecutor: @unchecked Sendable {
  static let shared = NativeBridgeABIExecutor()

  func execute(_ requestData: Data) async -> Data {
    let request: NativeRequestEnvelope
    do {
      request = try NativeBridgeProtocolCodec.decodeRequest(requestData)
    } catch {
      return encode(
        NativeResponseEnvelope(
          requestID: nil,
          failure: NativeBridgeFailure(
            code: .configurationRejected,
            message: "Native bridge request is malformed or exceeds its fixed bound."
          )
        )
      )
    }
    do {
      let coordinator = try ProductionNativeBridge.coordinator.get()
      let result = try await coordinator.execute(request.command)
      return encode(NativeResponseEnvelope(requestID: request.requestID, result: result))
    } catch {
      let mapped = NativeBridgeCoordinator.map(error)
      return encode(
        NativeResponseEnvelope(requestID: request.requestID, failure: mapped.responseFailure)
      )
    }
  }

  private func encode(_ response: NativeResponseEnvelope) -> Data {
    do {
      return try NativeBridgeProtocolCodec.encodeResponse(response)
    } catch {
      // This fixed response is substantially below the response bound and has
      // no user-controlled content. If encoding it fails, the C boundary still
      // invokes its callback exactly once with an empty response, which Rust
      // treats as an explicit internal error rather than success.
      return Data()
    }
  }
}

private struct NativeBridgeCallback: @unchecked Sendable {
  let function: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int) -> Void
  let context: UnsafeMutableRawPointer?

  func invoke(with data: Data) {
    data.withUnsafeBytes { bytes in
      function(context, bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count)
    }
  }
}

private final class NativeBridgeRequestBuffer: @unchecked Sendable {
  private var data: Data

  init(bytes: UnsafePointer<UInt8>, count: Int) {
    data = Data(bytes: bytes, count: count)
  }

  deinit {
    erase()
  }

  func execute() async -> Data {
    defer { erase() }
    return await NativeBridgeABIExecutor.shared.execute(data)
  }

  private func erase() {
    data.resetBytes(in: data.startIndex..<data.endIndex)
    data.removeAll(keepingCapacity: false)
  }
}

@_cdecl("cfw_native_bridge_execute_v1")
public func cfwNativeBridgeExecuteV1(
  _ requestBytes: UnsafePointer<UInt8>?,
  _ requestLength: Int,
  _ callback: (
    @convention(c) (
      UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int
    ) -> Void
  )?,
  _ callbackContext: UnsafeMutableRawPointer?
) -> Int32 {
  guard let callback else {
    return 1
  }
  guard requestLength > 0,
    requestLength <= NativeBridgeProtocolConstants.maximumRequestBytes,
    let requestBytes
  else {
    return 2
  }
  let request = NativeBridgeRequestBuffer(bytes: requestBytes, count: requestLength)
  let completion = NativeBridgeCallback(function: callback, context: callbackContext)
  Task {
    completion.invoke(with: await request.execute())
  }
  return 0
}
