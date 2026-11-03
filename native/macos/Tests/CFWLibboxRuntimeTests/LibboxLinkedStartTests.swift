import CFWSharedProtocol
import Dispatch
import Foundation
import Synchronization
import Testing

@testable import CFWLibboxRuntime

// The linked libbox runtime, built only where Libbox links: it bounds every
// start and stays startable.
#if canImport(Libbox)
  /// The real runtime ends every start in a state it can start from again. A
  /// start that fails before libbox starts the network leaves it idle; a stalled
  /// rule-set download is interrupted at the owner's deadline, while a rule set
  /// that finished downloading is kept for the next start; a download stalled
  /// at its proxy is interrupted alike; a start with too little time left never
  /// begins; and a later start from the kept rule set listens, then stops and
  /// releases its listeners. A runtime whose close fails, at a stop, at the
  /// interrupt or after a start's own failure, is spent instead: it reports
  /// that close failure from then on and never reaches libbox again. So is a
  /// runtime whose close never returns, at a stop once the stop's bound passed
  /// and at the interrupt once the interrupt limit passed.
  /// libbox takes its directories once per process, so this is the bundle's only
  /// test that starts it.
  @Test func linkedRuntimeBoundsEveryStartAndStaysStartable() throws {
    let stalled = try LoopbackServer(response: nil)
    defer { stalled.cancel() }
    let ruleSet = Data(#"{"version":1,"rules":[{"domain_suffix":["linked-test.invalid"]}]}"#.utf8)
    let headers =
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
      + "Content-Length: \(ruleSet.count)\r\nConnection: close\r\n\r\n"
    let served = try LoopbackServer(response: Data(headers.utf8) + ruleSet)
    defer { served.cancel() }
    let stalledProxy = try LoopbackServer(response: nil)
    defer { stalledProxy.cancel() }
    let stalledSet = LinkedRuleSet(
      tag: "stalled", url: "http://127.0.0.1:\(stalled.port)/stalled.srs", format: "binary")
    let servedSet = LinkedRuleSet(
      tag: "served", url: "http://127.0.0.1:\(served.port)/linked.json", format: "source")
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer {
      do { try FileManager.default.removeItem(at: root) } catch { Issue.record(error) }
    }
    let directories = try LibboxRuntimeDirectories.prepare(container: root, role: .systemProxy)
    let runtime = try SourceBuiltLibboxServiceRuntime(role: .systemProxy, directories: directories)
    let endpoints = try LinkedEndpoints()
    let cache = root.appendingPathComponent("cache.db")

    // libbox cannot open a cache file that is a directory, so the start fails
    // before the network starts, and nothing that started is left to close.
    let blockedCache = root.appendingPathComponent("blocked-cache.db", isDirectory: true)
    try FileManager.default.createDirectory(at: blockedCache, withIntermediateDirectories: false)
    let failed = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [stalledSet], cacheFile: blockedCache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early never returned")
    stopIfStarted(runtime, failed)
    guard case .failure(let error) = failed,
      case .serviceStartFailed(let diagnostic)? = error as? LibboxRuntimeError
    else {
      Issue.record("expected a start failure whose cleanup succeeded, got \(failed)")
      return
    }
    // libbox names the cache path it could not open; however the failure is
    // printed or described, that text stays inside libbox's own type.
    #expect(diagnostic.text.contains("blocked-cache"))
    var dumped = ""
    dump(error, to: &dumped)
    for rendering in [
      String(describing: error), String(reflecting: error), "\(error)", dumped,
      error.localizedDescription, (error as NSError).description,
      String(describing: (error as NSError).userInfo),
    ] {
      #expect(!rendering.contains("blocked-cache"), "\(rendering)")
    }

    // Each stalled start also carries a rule set that downloads at once.
    let stalledConfiguration = try endpoints.configuration(
      ruleSets: [servedSet, stalledSet], cacheFile: cache)
    for attempt in 1...2 {
      let deadline = EngineStartDeadline(
        receivedAt: ContinuousClock.now.advanced(
          by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
      let timedOut = try #require(
        boundedStart(runtime, stalledConfiguration, deadline: deadline),
        "the interrupt never ended stalled start \(attempt)")
      stopIfStarted(runtime, timedOut)
      let lateness = deadline.instant.duration(to: .now)
      #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try timedOut.get() }
      #expect(lateness >= .zero, "start \(attempt) returned \(lateness) before its deadline")
      #expect(
        lateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
        "start \(attempt) returned \(lateness) after its deadline")
      #expect(stalled.acceptedConnections == attempt, "the stall was not the rule-set download")
    }
    #expect(
      served.acceptedConnections == 1,
      "a rule set that finished downloading before the interrupt was not kept")

    // Rule sets download through the outbound their `download_detour` names,
    // in production the profile's selected node. A proxy that accepts the
    // connection and never answers must not hold the start past its deadline
    // either; the URL is the served one, so a download that skipped the proxy
    // would succeed.
    let proxiedSet = LinkedRuleSet(
      tag: "proxied", url: "http://127.0.0.1:\(served.port)/proxied.json", format: "source",
      detour: "proxy")
    let proxiedDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let proxied = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(
          ruleSets: [proxiedSet], cacheFile: cache, proxyPort: stalledProxy.port),
        deadline: proxiedDeadline),
      "the interrupt never ended a start stalled at its proxy")
    stopIfStarted(runtime, proxied)
    let proxiedLateness = proxiedDeadline.instant.duration(to: .now)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try proxied.get() }
    #expect(proxiedLateness >= .zero)
    #expect(
      proxiedLateness < EngineStartBudget.deadlineTolerance + EngineStartBudget.interruptAllowance,
      "a start stalled at its proxy returned \(proxiedLateness) after its deadline")
    #expect(stalledProxy.acceptedConnections == 1, "the stall was not the proxy")
    #expect(served.acceptedConnections == 1, "the proxied download reached the server")

    // With less than the minimum start window left the runtime never begins
    // the start: it times out without downloading anything.
    let tooLate = try #require(
      boundedStart(
        runtime, stalledConfiguration,
        deadline: EngineStartDeadline(
          receivedAt: ContinuousClock.now.advanced(
            by: .seconds(1) - EngineStartBudget.ownerLibboxStart))),
      "a start with too little time left never returned")
    stopIfStarted(runtime, tooLate)
    #expect(throws: LibboxRuntimeError.serviceStartTimedOut) { try tooLate.get() }
    #expect(stalled.acceptedConnections == 2, "a start that never began downloaded its rule set")

    let started = try #require(
      boundedStart(
        runtime,
        try endpoints.configuration(ruleSets: [servedSet], cacheFile: cache),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start from the kept rule set never returned")
    try started.get()
    #expect(served.acceptedConnections == 1, "the start downloaded a rule set it had kept")
    try runtime.healthCheck()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: POSIXError(.EADDRINUSE), "libbox does not listen on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }
    try runtime.stop()
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port)") {
        _ = try probeLoopbackPort(port)
      }
    }

    // libbox closes an instance once, so a close that fails leaves the runtime
    // spent. Its monitor fails here while libbox still closes every other part,
    // listeners included.
    let servedConfiguration = try endpoints.configuration(
      ruleSets: [servedSet], cacheFile: cache)
    let stopSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    try #require(
      boundedStart(stopSpent, servedConfiguration, deadline: EngineStartDeadline(receivedAt: .now)),
      "a start whose close will fail never returned"
    ).get()
    let stopFailure = try #require(
      closeFailure(of: stopSpent), "a close whose network monitor failed reported success")
    guard case .closeFailed(let stopDiagnostic) = stopFailure.cause else {
      Issue.record("expected the close's own failure, got \(stopFailure.cause)")
      return
    }
    #expect(stopDiagnostic.text.contains(LinkedMonitorCloseFault.text))
    for port in [endpoints.mixedPort, endpoints.controllerPort] {
      #expect(throws: Never.self, "libbox still listens on \(port) after its failed close") {
        _ = try probeLoopbackPort(port)
      }
    }
    #expect(closeFailure(of: stopSpent) == stopFailure, "a later stop reached libbox again")
    #expect(throws: stopFailure) {
      try stopSpent.start(
        configuration: servedConfiguration, packetFileDescriptor: nil,
        deadline: EngineStartDeadline(receivedAt: .now))
    }

    // A stalled start whose close fails when it is interrupted is spent alike.
    let interruptSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    let spentDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let interrupted = try #require(
      boundedStart(interruptSpent, stalledConfiguration, deadline: spentDeadline),
      "the interrupt never ended a start whose close fails")
    stopIfStarted(interruptSpent, interrupted)
    guard case .failure(let error) = interrupted,
      let startFailure = error as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the interrupted start to report its failed close, got \(interrupted)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "the stall was not the rule-set download")
    #expect(closeFailure(of: interruptSpent) == startFailure)

    // A start that fails on its own closes its instance itself. When that close
    // fails libbox keeps the instance and cannot close it again, so the runtime
    // is spent rather than idle. libbox closes only what started, so these
    // starts fail once the network monitor runs: their rule set downloads
    // through an outbound the configuration lacks, which fails before any
    // connection to the stalled server.
    let missingDetourSet = LinkedRuleSet(
      tag: stalledSet.tag, url: stalledSet.url, format: stalledSet.format, detour: "missing")
    let failedSpent = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { throw LinkedMonitorCloseFault() })
    let ownFailure = try #require(
      boundedStart(
        failedSpent,
        try endpoints.configuration(
          ruleSets: [missingDetourSet], cacheFile: root.appendingPathComponent("own-failure.db")),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start that failed early and could not close never returned")
    stopIfStarted(failedSpent, ownFailure)
    guard case .failure(let ownError) = ownFailure,
      let ownCloseFailure = ownError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the failed start to report its failed close, got \(ownFailure)")
      return
    }
    #expect(stalled.acceptedConnections == 3, "a start that failed early downloaded its rule set")
    #expect(
      closeFailure(of: failedSpent) == ownCloseFailure,
      "the failed start did not leave the runtime spent")

    // libbox closes the instance of a start that failed on its own inside that
    // start, holding its lifecycle lock. A close that never returns there
    // holds the start and the interrupt alike, so the start is abandoned at
    // the interrupt limit and leaves the runtime spent.
    let ownStall = LinkedMonitorCloseStall()
    defer { ownStall.release() }
    let ownStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { ownStall.hold() })
    let ownStallDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let ownStalledStart = try #require(
      boundedStart(
        ownStalled,
        try endpoints.configuration(
          ruleSets: [missingDetourSet], cacheFile: root.appendingPathComponent("own-stall.db")),
        deadline: ownStallDeadline),
      "a start that failed early and whose close stalled was not abandoned")
    let ownStallLateness = ownStallDeadline.instant.duration(to: .now)
    stopIfStarted(ownStalled, ownStalledStart)
    guard case .failure(let ownStallError) = ownStalledStart,
      let ownStallFailure = ownStallError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the failed start's stalled close to spend it, got \(ownStalledStart)")
      return
    }
    #expect(ownStallFailure.cause == .interruptDidNotReturn)
    #expect(ownStallLateness >= EngineStartBudget.interruptLimit)
    #expect(
      ownStallLateness
        < EngineStartBudget.interruptLimit + EngineStartBudget.deadlineTolerance * 2
        + .milliseconds(500),
      "the stalled failed start returned \(ownStallLateness) after its deadline")
    #expect(stalled.acceptedConnections == 3, "a start that failed early downloaded its rule set")
    #expect(closeFailure(of: ownStalled) == ownStallFailure)

    // A stalled start whose interrupted close never returns is abandoned at
    // the interrupt limit. Each stalled close keeps its cache file locked, so
    // these runtimes use their own.
    let interruptStall = LinkedMonitorCloseStall()
    defer { interruptStall.release() }
    let interruptStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { interruptStall.hold() })
    let abandonedDeadline = EngineStartDeadline(
      receivedAt: ContinuousClock.now.advanced(
        by: .seconds(3) - EngineStartBudget.ownerLibboxStart))
    let abandoned = try #require(
      boundedStart(
        interruptStalled,
        try endpoints.configuration(
          ruleSets: [stalledSet], cacheFile: root.appendingPathComponent("interrupt-stall.db")),
        deadline: abandonedDeadline),
      "a start whose interrupt never returned was not abandoned")
    let abandonedLateness = abandonedDeadline.instant.duration(to: .now)
    stopIfStarted(interruptStalled, abandoned)
    guard case .failure(let abandonedError) = abandoned,
      let abandonedFailure = abandonedError as? LibboxInstanceUnclosable
    else {
      Issue.record("expected the abandoned start to report the runtime spent, got \(abandoned)")
      return
    }
    #expect(abandonedFailure.cause == .interruptDidNotReturn)
    #expect(abandonedLateness >= EngineStartBudget.interruptLimit)
    #expect(
      abandonedLateness
        < EngineStartBudget.interruptLimit + EngineStartBudget.deadlineTolerance * 2
        + .milliseconds(500),
      "the abandoned start returned \(abandonedLateness) after its deadline")
    #expect(stalled.acceptedConnections == 4, "the stall was not the rule-set download")
    #expect(closeFailure(of: interruptStalled) == abandonedFailure)

    // A stop whose close never returns stops waiting at the stop's bound.
    let stopStall = LinkedMonitorCloseStall()
    defer { stopStall.release() }
    let stopStalled = try SourceBuiltLibboxServiceRuntime(
      role: .systemProxy, directories: directories,
      interfaceMonitorClose: { stopStall.hold() })
    try #require(
      boundedStart(
        stopStalled,
        try endpoints.configuration(
          ruleSets: [servedSet], cacheFile: root.appendingPathComponent("stop-stall.db")),
        deadline: EngineStartDeadline(receivedAt: .now)),
      "a start whose close will stall never returned"
    ).get()
    let stopBegan = ContinuousClock.now
    let stalledStop = try #require(
      closeFailure(of: stopStalled), "a close that never returned reported success")
    let stopWait = stopBegan.duration(to: .now)
    #expect(stalledStop.cause == .closeDidNotReturn)
    #expect(stopWait >= EngineStopBudget.libboxClose)
    #expect(
      stopWait < EngineStopBudget.libboxClose + .milliseconds(500),
      "the stop waited \(stopWait) for a close that never returned")
    // A later stop reports the same failure at once, without libbox: one that
    // reached libbox again would wait out the bound again.
    let laterStopBegan = ContinuousClock.now
    #expect(closeFailure(of: stopStalled) == stalledStop)
    let laterStopWait = laterStopBegan.duration(to: .now)
    #expect(laterStopWait < .milliseconds(500), "a later stop waited \(laterStopWait)")
  }
#endif
