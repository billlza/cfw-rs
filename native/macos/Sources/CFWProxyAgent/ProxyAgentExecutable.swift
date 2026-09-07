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
    let journalStore = try KeychainProxyOwnershipJournalStore(
      keychainAccessGroup: journalKeychainAccessGroup
    )
    let preferences = SCPreferencesSystemProxyPreferences()
    let credentialVault = try CredentialVault(accessGroup: credentialKeychainAccessGroup)
    // Machine-wide Proxy/Tunnel/multi-user exclusion is owned by the Global Authority
    // lease, not a provider-local rendezvous: the data-plane lifecycle holds only an
    // unleased local ownership handle. There is no `CrossProcessEngineLeaseStore` in
    // the ProxyAgent Release path.
    let lifecycle = ProxySessionLifecycle(
      dependencies: ProxySessionDependencies(
        prepareOwnership: { descriptor in
          _ = descriptor
          return PreparedProxyOwnership(lease: UnleasedProxyOwnership())
        },
        resolveConfiguration: { template, descriptor in
          var material = try credentialVault.resolve(
            audience: descriptor.credentialAudience,
            slots: descriptor.credentialSlots
          )
          defer { material.erase() }
          return try CredentialInjector.inject(
            template: template,
            slots: descriptor.credentialSlots,
            material: material
          )
        },
        recoverCleanupLease: { _ in UnleasedProxyOwnership() },
        engineFactory: LibboxProxyEngineFactory(),
        preferences: preferences,
        journalStore: journalStore,
        readinessTimeout: 10
      )
    )
    // The Authority owner coordinator binds an Authority owner capability before any
    // libbox or System Proxy mutation, attests exact ready/stopped state with the
    // exact operation context and effective proxy observation, and forces a stop on
    // revocation. The authenticated Host→ProxyAgent capability channel and the
    // role-scoped Authority owner XPC client are the only production start path.
    let revocation = ProxyRevocationChannel()
    let authorityRemote = NSXPCGlobalAuthorityRemote(
      role: .proxyAgent,
      onEvent: { event in
        switch event {
        case .revoke, .stop: revocation.revoke()
        case .snapshot: break
        }
      },
      onDisconnect: { revocation.revoke() })
    let owner = ProxySystemProxyOwnerCoordinator(
      authority: BoundedAuthorityXPCClient(remote: authorityRemote),
      observer: JournalBackedEffectiveSystemProxyObserver(
        preferences: preferences,
        journalStore: journalStore),
      lifecycle: lifecycle,
      revocation: revocation
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
