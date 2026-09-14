import CFWSharedProtocol
import Foundation

#if canImport(Libbox)
  import Libbox
#endif

public protocol LibboxProfileProbing: Sendable {
  func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay]
}

public struct SourceBuiltLibboxProfileProbe: LibboxProfileProbing {
  public init() {}

  public func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay] {
    try ProfileDelayTestRequest.validateTargets(proxies, timeoutMS: timeoutMS)
    try ProfileDelayTestRequest.validateTargetURL(targetURL, expectedStatus: expectedStatus)
    let configurationText = try LibboxConfigurationDocument.text(from: configuration)
    #if canImport(Libbox)
      let names = String(decoding: try JSONEncoder().encode(proxies), as: UTF8.self)
      var error: NSError?
      let response = LibboxTestProfileProxiesWithTarget(
        configurationText, names, Int32(timeoutMS), targetURL, expectedStatus, &error)
      if let error {
        throw LibboxRuntimeError.serviceStartFailed(error.localizedDescription)
      }
      guard response.utf8.count <= 65536 else {
        throw LibboxRuntimeError.serviceStartFailed("Invalid latency response")
      }
      let results = try JSONDecoder().decode([ProfileProxyDelay].self, from: Data(response.utf8))
      guard results.map(\.name) == proxies else {
        throw LibboxRuntimeError.serviceStartFailed("Latency response targets changed")
      }
      return results
    #else
      _ = configurationText
      throw LibboxRuntimeError.libboxUnavailable
    #endif
  }
}
