import Foundation
import Testing

@testable import CFWLibboxRuntime

/// Stands in for libbox's text, which can name servers and paths.
private let canary = "outbound canary-server.example:443 at /Users/someone/Library/cache.db"

/// Every way an error reaches a string: interpolation, descriptions, dumps and
/// the NSError a Swift error bridges to.
private func renderings(of error: any Error) -> [String] {
  var dumped = ""
  dump(error, to: &dumped)
  let bridged = error as NSError
  return [
    String(describing: error), String(reflecting: error), "\(error)", dumped,
    error.localizedDescription, bridged.description, bridged.localizedDescription,
    String(describing: bridged.userInfo),
  ]
}

@Test func libboxTextNeverLeavesAnyRuntimeError() {
  let diagnostic = LibboxDiagnostic(canary)
  let errors: [any Error] = [
    LibboxRuntimeError.configurationCheckFailed(diagnostic),
    LibboxRuntimeError.configurationCheckCleanupFailed(diagnostic),
    LibboxRuntimeError.setupFailed(diagnostic),
    LibboxRuntimeError.serverCreationFailed(diagnostic),
    LibboxRuntimeError.serviceStartFailed(diagnostic),
    LibboxRuntimeError.serviceNotRunning(state: 3, message: diagnostic),
    LibboxInstanceUnclosable(closeFailure: canary),
  ]
  for error in errors {
    for rendering in renderings(of: error) {
      #expect(!rendering.contains("canary-server"), "\(type(of: error)) shows \(rendering)")
    }
  }
  #expect(Mirror(reflecting: diagnostic).children.isEmpty)
  // The runtime and its tests still read the text through the module.
  #expect(diagnostic.text == canary)
  #expect(LibboxDiagnostic("a") != LibboxDiagnostic("b"))
}

/// The profile-probe patch joins its failures; only its cleanup failure means
/// the probe's instance stays in the process, which the probe's error then
/// carries for the ProxyAgent to retire on.
@Test func aProbeReportTellsWhetherItsInstanceStayedOpen() {
  #expect(LibboxProfileProbeReport.unclosedInstance == "profile probe cleanup failed")
  for report in [
    "profile probe cleanup failed",
    "profile probe startup failed\nprofile probe cleanup failed",
  ] {
    let error = LibboxProfileProbeReport.error(for: report)
    #expect(error == .profileProbeCleanupFailed(LibboxDiagnostic(report)), "\(report)")
    #expect(error.unclosedCallInstance != nil, "\(report)")
  }
  for report in ["profile probe startup failed", "dial tcp 1.2.3.4:443: i/o timeout", ""] {
    let error = LibboxProfileProbeReport.error(for: report)
    #expect(error == .serviceStartFailed(LibboxDiagnostic(report)), "\(report)")
    #expect(error.unclosedCallInstance == nil, "\(report)")
  }
}
