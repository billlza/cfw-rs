import CFWCredentialTransport
import CFWSharedProtocol
import Foundation

extension NativeBridgeCoordinator {
  func testProfileDelays(_ request: ProfileDelayTestRequest) async throws -> [ProfileProxyDelay] {
    do {
      var material = try credentialVault.resolve(
        audience: request.audience, slots: request.credentialSlots)
      defer { material.erase() }
      var configuration = try CredentialInjector.inject(
        template: Data(request.configJSON.utf8), slots: request.credentialSlots,
        material: material)
      defer { configuration.resetBytes(in: configuration.startIndex..<configuration.endIndex) }
      try Task.checkCancellation()
      try await proxy.ensureRegistered()
      return try await proxy.testProfileProxies(
        configuration: configuration, proxies: request.proxies, timeoutMS: request.timeoutMS,
        targetURL: request.targetURL ?? "", expectedStatus: request.expectedStatus ?? "")
    } catch {
      throw Self.map(error)
    }
  }
}
