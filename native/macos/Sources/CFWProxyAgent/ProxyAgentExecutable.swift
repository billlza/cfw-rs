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
    let journalStore = try KeychainProxyOwnershipJournalStore(
      keychainAccessGroup: journalKeychainAccessGroup
    )
    let credentialVault = try CredentialVault(accessGroup: credentialKeychainAccessGroup)
    // Machine-wide Proxy/Tunnel/multi-user exclusion is owned by the Global Authority
    // lease, not a provider-local rendezvous: the data-plane lifecycle holds only an
    // unleased local ownership handle. There is no `CrossProcessEngineLeaseStore` in
    // the ProxyAgent Release path.
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareConfiguration: { descriptor in
          PreparedProxyConfiguration(
            configuration: try configurationStore.load(descriptor),
            lease: UnleasedProxyOwnership()
          )
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
        recoverCleanupLease: { _ in UnleasedProxyOwnership() },
        engineFactory: LibboxProxyEngineFactory(),
        preferences: SCPreferencesSystemProxyPreferences(),
        journalStore: journalStore,
        readinessTimeout: 10
      )
    )
    // The Authority owner coordinator binds an Authority owner capability before any
    // libbox or System Proxy mutation, attests exact ready/stopped state with the
    // exact operation context and effective proxy observation, and forces a stop on
    // revocation. It fails closed with a typed Authority error until the authenticated
    // Host→ProxyAgent capability channel and Authority owner XPC client are wired.
    let owner = ProxySystemProxyOwnerCoordinator(
      authority: FailClosedProxyOwnerAuthorityClient(),
      capabilitySource: FailClosedProxyOwnerCapabilitySource(),
      observer: FailClosedEffectiveSystemProxyObserver(),
      lifecycle: lifecycle,
      revocation: ProxyRevocationChannel()
    )
    let service = ProxyAgentService(
      lifecycle: owner,
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
