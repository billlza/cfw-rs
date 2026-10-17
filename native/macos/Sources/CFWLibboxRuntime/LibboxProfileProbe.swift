import CFWSharedProtocol
import Foundation
import OSLog

#if canImport(Libbox)
  import Libbox
#endif

public protocol LibboxProfileProbing: Sendable {
  func test(
    configuration: Data, proxies: [String], timeoutMS: UInt16, targetURL: String,
    expectedStatus: String
  ) throws -> [ProfileProxyDelay]
}

/// What CFM's profile-probe patch says about a probe beyond libbox's own text,
/// which never leaves `LibboxDiagnostic`.
enum LibboxProfileProbeReport {
  /// The patch reports a probe instance it could not close, a close that
  /// panicked included, under this text (`experimental/libbox/profile_probe.go`,
  /// whose Go tests hold it).
  static let unclosedInstance = "profile probe cleanup failed"

  /// The error of a probe libbox failed with `report`. One whose instance
  /// libbox could not close leaves what it built in this process, which the
  /// error carries as its unclosed call instance.
  static func error(for report: String) -> LibboxRuntimeError {
    report.contains(unclosedInstance)
      ? .profileProbeCleanupFailed(LibboxDiagnostic(report))
      : .serviceStartFailed(LibboxDiagnostic(report))
  }
}

public struct SourceBuiltLibboxProfileProbe: LibboxProfileProbing {
  private static let logger = Logger(
    subsystem: "com.bill.clashformac",
    category: "libbox-profile-probe"
  )

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
        let failure = LibboxProfileProbeReport.error(for: error.localizedDescription)
        if failure.unclosedCallInstance != nil {
          Self.logger.fault(
            "libbox could not close a profile probe's instance; what it built stays in this process"
          )
        }
        throw failure
      }
      guard response.utf8.count <= 65536 else {
        throw LibboxRuntimeError.serviceStartFailed(LibboxDiagnostic("Invalid latency response"))
      }
      let results = try JSONDecoder().decode([ProfileProxyDelay].self, from: Data(response.utf8))
      guard results.map(\.name) == proxies else {
        throw LibboxRuntimeError.serviceStartFailed(
          LibboxDiagnostic("Latency response targets changed"))
      }
      return results
    #else
      _ = configurationText
      throw LibboxRuntimeError.libboxUnavailable
    #endif
  }
}
