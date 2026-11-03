import CFWSharedProtocol
import CryptoKit
import Foundation
import Security
import Testing

@testable import CFWAppleNetwork

// Registration and identity: a service record repaired or a missing bundle
// kept distinct, a snapshot that needs an approved registration, and process
// identities the kernel reports without privilege.
extension ProxyAgentHostClientTests {
  @Test func registrationRepairsNotFoundServiceRecord() throws {
    let service = FakeProxyAgentService([.notFound, .enabled])
    let controller = SMProxyAgentServiceController(service: service)
    try controller.ensureRegistered()
    #expect(service.registerCalls == 1)
    #expect(controller.registrationStatus() == .enabled)
  }

  @Test func registrationKeepsMissingBundleDistinctWhenNotFoundPersists() {
    let service = FakeProxyAgentService(
      [.notFound],
      registerError: ProxyAgentRegistrationTestError.denied
    )
    #expect(throws: ProxyAgentHostError.registrationUnavailable) {
      try SMProxyAgentServiceController(service: service).ensureRegistered()
    }
    #expect(service.registerCalls == 1)
  }

  @Test func snapshotRequiresApprovedRegistrationInsteadOfProjectingFalseOff() async throws {
    let awaitingApproval = try transport(status: .requiresApproval)
    await #expect(throws: ProxyAgentHostError.registrationRequiresApproval) {
      _ = try await awaitingApproval.snapshot()
    }

    for status in [ProxyAgentRegistrationStatus.notRegistered, .notFound] {
      let unavailable = try transport(status: status)
      await #expect(throws: ProxyAgentHostError.registrationUnavailable) {
        _ = try await unavailable.snapshot()
      }
    }
  }

  @Test func kernelProcessIdentityReadsTheCurrentUnprivilegedProcess() throws {
    let identity = try Installed40019ServiceProcessObserver.kernelProcessIdentity(getpid())
    #expect(identity.processIdentifier == getpid())
    #expect(identity.effectiveUserIdentifier == geteuid())
    #expect(identity.realUserIdentifier == getuid())
    #expect(identity.startSeconds > 0)
    #expect(identity.startMicroseconds < 1_000_000)
  }

  @Test func kernelProcessIdentityReadsRootLaunchdWithoutPrivilege() throws {
    let identity = try Installed40019ServiceProcessObserver.kernelProcessIdentity(1)
    #expect(identity.processIdentifier == 1)
    #expect(identity.effectiveUserIdentifier == 0)
    #expect(identity.realUserIdentifier == 0)
    #expect(identity.startSeconds > 0)
    #expect(identity.startMicroseconds < 1_000_000)
  }

  /// The kernel reader is shared (`KernelProcessTable`, tested with
  /// CFWSharedProtocol); this observer rejects a pid with no process.
  /// An ended child is never reported as running: its pid names no process,
  /// or a later one with another start time.
  @Test func kernelProcessIdentityRejectsAnEndedProcess() throws {
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["60"]
    try child.run()
    let pid = child.processIdentifier
    let running = try Installed40019ServiceProcessObserver.kernelProcessIdentity(pid)
    child.terminate()
    child.waitUntilExit()
    switch Result(catching: { try Installed40019ServiceProcessObserver.kernelProcessIdentity(pid) })
    {
    case .failure:
      break
    case .success(let later):
      #expect(
        later.startSeconds != running.startSeconds
          || later.startMicroseconds != running.startMicroseconds,
        "the ended child was reported as running")
    }
  }
}
