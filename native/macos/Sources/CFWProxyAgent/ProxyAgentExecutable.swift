import CFWCredentialTransport
import CFWCredentialVault
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation

enum ProxyAgentRuntimeError: Error {
  case runLoopExited
}

public enum ProxyAgentExecutable {
  public static func run() throws -> Never {
    let identityPolicy = try CodeIdentityPolicy.fromMainBundle()
    guard
      let machServiceName = Bundle.main.object(
        forInfoDictionaryKey: "CFWProxyAgentMachServiceName"
      ) as? String,
      !machServiceName.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWProxyAgentMachServiceName")
    }
    guard
      let journalKeychainAccessGroup = Bundle.main.object(
        forInfoDictionaryKey: "CFWProxyJournalKeychainAccessGroup"
      ) as? String,
      !journalKeychainAccessGroup.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWProxyJournalKeychainAccessGroup")
    }
    guard
      let credentialKeychainAccessGroup = Bundle.main.object(
        forInfoDictionaryKey: "CFWCredentialKeychainAccessGroup"
      ) as? String,
      !credentialKeychainAccessGroup.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWCredentialKeychainAccessGroup")
    }
    guard
      let appGroupIdentifier = Bundle.main.object(
        forInfoDictionaryKey: "CFWAppGroupIdentifier"
      ) as? String,
      !appGroupIdentifier.isEmpty
    else {
      throw CodeIdentityError.missingBundleSetting("CFWAppGroupIdentifier")
    }

    let configurationStore = try AppGroupConfigurationStore(
      appGroupIdentifier: appGroupIdentifier
    )
    let engineLeaseStore = CrossProcessEngineLeaseStore()
    let journalStore = try KeychainProxyOwnershipJournalStore(
      keychainAccessGroup: journalKeychainAccessGroup
    )
    let credentialVault = try CredentialVault(accessGroup: credentialKeychainAccessGroup)
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareConfiguration: { descriptor in
          let lease = try engineLeaseStore.acquire()
          do {
            return PreparedProxyConfiguration(
              configuration: try configurationStore.load(descriptor),
              lease: ProxyMachineEngineLease(lease)
            )
          } catch {
            lease.release()
            throw error
          }
        },
        resolveConfiguration: { template, descriptor in
          var material = try credentialVault.resolve(slots: descriptor.credentialSlots)
          defer { material.erase() }
          return try CredentialInjector.inject(
            template: template,
            slots: descriptor.credentialSlots,
            material: material
          )
        },
        recoverCleanupLease: { _ in
          ProxyMachineEngineLease(try engineLeaseStore.acquire())
        },
        engineFactory: LibboxProxyEngineFactory(),
        preferences: SCPreferencesSystemProxyPreferences(),
        journalStore: journalStore,
        readinessTimeout: 10
      )
    )
    let service = ProxyAgentService(
      lifecycle: lifecycle,
      configurationChecker: SourceBuiltLibboxConfigurationChecker()
    )

    let delegate = ProxyAgentListenerDelegate(
      identityPolicy: identityPolicy,
      service: service
    )
    let listener = NSXPCListener(machServiceName: machServiceName)
    identityPolicy.configure(listener)
    listener.delegate = delegate
    listener.resume()
    RunLoop.current.run()
    throw ProxyAgentRuntimeError.runLoopExited
  }
}

private final class ProxyMachineEngineLease: ProxyEngineLeaseHolding, @unchecked Sendable {
  private let lease: CrossProcessEngineLease

  init(_ lease: CrossProcessEngineLease) {
    self.lease = lease
  }

  func release() {
    lease.release()
  }

  func markStopFailed() {
    // Retain both socket descriptors until a later cleanup succeeds or the
    // process exits. Releasing after an unproven engine stop could permit a
    // second libbox data plane.
  }
}
