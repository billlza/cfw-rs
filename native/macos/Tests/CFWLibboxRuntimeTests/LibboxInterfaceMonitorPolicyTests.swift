import Testing

@testable import CFWLibboxRuntime

private struct InterfaceCandidate: Equatable {
  let name: String
  let index: Int
}

@Test func registeredTunnelStopsBeingTheDefaultWithoutANewPath() {
  let path = [
    InterfaceCandidate(name: "utun12", index: 24),
    InterfaceCandidate(name: "en0", index: 14),
    InterfaceCandidate(name: "en1", index: 15),
  ]
  var policy = LibboxInterfaceMonitorPolicy()
  _ = policy.startSession()
  #expect(policy.eligibleInterfaces(path, named: \.name).first == path[0])

  policy.register("utun12")

  // Registration must also correct the already observed path, even when the
  // OS does not deliver another path change after the tunnel starts.
  #expect(policy.eligibleInterfaces(path, named: \.name) == Array(path.dropFirst()))
  #expect(policy.eligibleInterfaces(path, named: \.name).first == path[1])
}

@Test func interfaceOwnershipIsExactAndScopedToOneRuntime() {
  let path = [
    InterfaceCandidate(name: "utun12", index: 24),
    InterfaceCandidate(name: "utun120", index: 25),
    InterfaceCandidate(name: "en0", index: 14),
  ]
  var tunnel = LibboxInterfaceMonitorPolicy()
  let otherRuntime = LibboxInterfaceMonitorPolicy()
  tunnel.register("utun12")
  tunnel.register("utun12")

  #expect(tunnel.eligibleInterfaces(path, named: \.name).first == path[1])
  #expect(otherRuntime.eligibleInterfaces(path, named: \.name) == path)
}

@Test func anOwnedTunnelAloneDoesNotProvideADefaultEgress() {
  let path = [InterfaceCandidate(name: "utun12", index: 24)]
  var policy = LibboxInterfaceMonitorPolicy()
  policy.register("utun12")

  #expect(policy.eligibleInterfaces(path, named: \.name).isEmpty)
  #expect(policy.eligibleInterfaces(path, named: \.name).first == nil)
}

@Test func monitorRestartRejectsStaleUpdatesAndRetainsTunnelOwnership() {
  let path = [
    InterfaceCandidate(name: "utun12", index: 24),
    InterfaceCandidate(name: "en0", index: 14),
  ]
  var policy = LibboxInterfaceMonitorPolicy()
  policy.register("utun12")
  let oldSession = policy.startSession()
  #expect(policy.isCurrentSession(oldSession))

  policy.stopSession()
  #expect(!policy.isCurrentSession(oldSession))

  let currentSession = policy.startSession()
  #expect(!policy.isCurrentSession(oldSession))
  #expect(policy.isCurrentSession(currentSession))
  #expect(policy.eligibleInterfaces(path, named: \.name).first == path[1])
}
