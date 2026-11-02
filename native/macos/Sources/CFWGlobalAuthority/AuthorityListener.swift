import CFWSharedProtocol
import Darwin
import Foundation
import OSLog
@preconcurrency import SystemConfiguration

import struct CryptoKit.SHA256

public enum AuthorityConnectionAdmission {
  public static func authorizeBeforeExport(
    authorize: () throws -> PeerIdentity,
    export: (PeerIdentity) -> Void
  ) -> Bool {
    do {
      let peer = try authorize()
      export(peer)
      return true
    } catch {
      return false
    }
  }
}

private final class AuthorityWeakConnectionBox: @unchecked Sendable {
  weak var connection: NSXPCConnection?
  init(_ connection: NSXPCConnection) { self.connection = connection }
}

private final class AuthorityConnectionTermination: @unchecked Sendable {
  private let lock = NSLock()
  private var terminated = false
  private let peerID: UUID
  private let role: AuthorityRole
  private let core: GlobalAuthorityServiceCore
  private let events: AuthorityEventHub
  private let liveness: AuthorityLivenessSupervisor

  init(
    peerID: UUID,
    role: AuthorityRole,
    core: GlobalAuthorityServiceCore,
    events: AuthorityEventHub,
    liveness: AuthorityLivenessSupervisor
  ) {
    self.peerID = peerID
    self.role = role
    self.core = core
    self.events = events
    self.liveness = liveness
  }

  func terminate() {
    let shouldTerminate = lock.withLock {
      guard !terminated else { return false }
      terminated = true
      return true
    }
    guard shouldTerminate else { return }
    events.remove(peerID: peerID)
    guard role != .host,
      core.ownerPeerID() == peerID,
      !core.ownerHasAttestedStopped
    else { return }
    do {
      _ = try liveness.forceStop(.connectionLoss)
    } catch {
      fatalError("Global Authority could not persist owner connection loss: \(error)")
    }
  }
}

private final class AuthorityProductionLivenessRuntime: @unchecked Sendable {
  let supervisor: AuthorityLivenessSupervisor
  private let timer: DispatchSourceTimer
  private let consoleSessionMonitor: ConsoleSessionChangeMonitor

  init(supervisor: AuthorityLivenessSupervisor) {
    self.supervisor = supervisor
    let monitor = ConsoleSessionChangeMonitor(
      queue: DispatchQueue(
        label: "com.bill.clashformac.global-authority.console-session"),
      handler: {
        do {
          _ = try supervisor.observeConsoleSessionChange()
        } catch {
          fatalError("Global Authority could not persist console-session change: \(error)")
        }
      })
    guard let monitor else {
      fatalError("Global Authority could not monitor the console session.")
    }
    consoleSessionMonitor = monitor
    timer = DispatchSource.makeTimerSource(
      queue: DispatchQueue(label: "com.bill.clashformac.global-authority.liveness"))
    timer.schedule(
      deadline: .now() + .seconds(1),
      repeating: .seconds(1),
      leeway: .milliseconds(100))
    timer.setEventHandler { [supervisor] in
      do {
        _ = try supervisor.observeConsoleUser()
        _ = try supervisor.evaluate()
      } catch {
        fatalError("Global Authority liveness evaluation failed: \(error)")
      }
    }
    timer.activate()
  }

  deinit { timer.cancel() }
}

private final class ConsoleSessionChangeHandlerBox: @unchecked Sendable {
  let handler: @Sendable () -> Void
  init(handler: @escaping @Sendable () -> Void) { self.handler = handler }
}

private final class ConsoleSessionChangeMonitor: @unchecked Sendable {
  private let handlerBox: ConsoleSessionChangeHandlerBox
  private let store: SCDynamicStore

  init?(
    queue: DispatchQueue,
    handler: @escaping @Sendable () -> Void
  ) {
    let handlerBox = ConsoleSessionChangeHandlerBox(handler: handler)
    var context = SCDynamicStoreContext(
      version: 0,
      info: Unmanaged.passUnretained(handlerBox).toOpaque(),
      retain: nil,
      release: nil,
      copyDescription: nil)
    let consoleUserKey = SCDynamicStoreKeyCreateConsoleUser(nil)
    guard
      let store = SCDynamicStoreCreate(
        nil,
        "Clash for Mac Global Authority console monitor" as CFString,
        { _, _, info in
          guard let info else { return }
          Unmanaged<ConsoleSessionChangeHandlerBox>
            .fromOpaque(info).takeUnretainedValue().handler()
        },
        &context),
      SCDynamicStoreSetNotificationKeys(
        store, [consoleUserKey] as CFArray, nil),
      SCDynamicStoreSetDispatchQueue(store, queue)
    else { return nil }
    self.handlerBox = handlerBox
    self.store = store
  }

  deinit {
    SCDynamicStoreSetDispatchQueue(store, nil)
    withExtendedLifetime(handlerBox) {}
  }
}

public final class AuthenticatedGlobalAuthorityListenerDelegate: NSObject,
  NSXPCListenerDelegate, @unchecked Sendable
{
  public typealias Authorize =
    @Sendable (
      AuthorityRole, pid_t, uid_t, UInt32, uid_t?, ProxyAgentLeaseRequirement
    ) throws -> PeerIdentity

  private let role: AuthorityRole
  private let core: GlobalAuthorityServiceCore
  private let concurrency: AuthorityConcurrencyGate
  private let events: AuthorityEventHub
  private let livenessRuntime: AuthorityProductionLivenessRuntime
  private let authorize: Authorize

  private init(
    role: AuthorityRole,
    core: GlobalAuthorityServiceCore,
    concurrency: AuthorityConcurrencyGate,
    events: AuthorityEventHub,
    livenessRuntime: AuthorityProductionLivenessRuntime,
    authorize: @escaping Authorize
  ) {
    self.role = role
    self.core = core
    self.concurrency = concurrency
    self.events = events
    self.livenessRuntime = livenessRuntime
    self.authorize = authorize
  }

  public static func production() throws
    -> [AuthorityRole: AuthenticatedGlobalAuthorityListenerDelegate]
  {
    let journal = try DescriptorRelativeAuthorityJournalStore()
    let reducer = try GlobalAuthorityReducer.reconciled(from: journal.recover())
    let core = GlobalAuthorityServiceCore(reducer: reducer, journal: journal)
    let concurrency = AuthorityConcurrencyGate()
    let events = AuthorityEventHub()
    let livenessRuntime = AuthorityProductionLivenessRuntime(
      supervisor: AuthorityLivenessSupervisor(core: core, events: events))
    let authorizer = RoleScopedConnectionPeerAuthorizer()
    return Dictionary(
      uniqueKeysWithValues: AuthorityRole.allCases.map { role in
        (
          role,
          Self(
            role: role,
            core: core,
            concurrency: concurrency,
            events: events,
            livenessRuntime: livenessRuntime
          ) { role, pid, euid, auditSessionID, ownerUID, agentLease in
            try authorizer.authorize(
              role: role,
              processIdentifier: pid,
              effectiveUserIdentifier: euid,
              auditSessionIdentifier: auditSessionID,
              leaseOwnerUID: ownerUID,
              agentLease: agentLease)
          }
        )
      })
  }

  public func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection connection: NSXPCConnection
  ) -> Bool {
    let pid = connection.processIdentifier
    let euid = connection.effectiveUserIdentifier
    let auditSessionID = UInt32(
      bitPattern: connection.auditSessionIdentifier)
    let preObservation = core.releaseObservationState()
    var admittedPeer: PeerIdentity?
    let admitted = AuthorityConnectionAdmission.authorizeBeforeExport(
      authorize: {
        // A ProxyAgent whose lease ended may still connect to ask after it;
        // each call then needs what that call needs.
        try authorize(role, pid, euid, auditSessionID, core.leaseOwnerUID, .ownedLeaseOrNone)
      },
      export: { admittedPeer = $0 })
    let postObservation = core.releaseObservationState()
    guard admitted, let peer = admittedPeer else {
      guard
        recordPeerAuthorizationDecision(
          pid: pid,
          euid: euid,
          auditSessionID: auditSessionID,
          peer: nil,
          preObservation: preObservation,
          postObservation: postObservation)
      else {
        fputs("global authority release observation failed\n", stderr)
        connection.invalidate()
        return false
      }
      connection.invalidate()
      return false
    }
    guard
      recordPeerAuthorizationDecision(
        pid: pid,
        euid: euid,
        auditSessionID: auditSessionID,
        peer: peer,
        preObservation: preObservation,
        postObservation: postObservation)
    else {
      fputs("global authority release observation failed\n", stderr)
      connection.invalidate()
      return false
    }

    let peerID = UUID()
    let service = AuthenticatedAuthorityPeerService(
      peerID: peerID, peer: peer,
      reauthorize: { [authorize, core] agentLease in
        try authorize(
          peer.role, peer.pid, peer.euid, peer.auditSessionID,
          core.leaseOwnerUID, agentLease)
      }, core: core, concurrency: concurrency, events: events,
      liveness: livenessRuntime.supervisor,
      recordOperationDecision: {
        try ReleaseObservationLogger.emitAuthorityOperationDecision($0)
      })
    connection.remoteObjectInterface = NSXPCInterface(
      with: CFWGlobalAuthorityEventSinkProtocol.self)
    let sink = connection.remoteObjectProxy as? CFWGlobalAuthorityEventSinkProtocol
    let connectionBox = AuthorityWeakConnectionBox(connection)
    let channel = AuthorityPeerEventChannel(
      sink: sink, invalidate: { connectionBox.connection?.invalidate() })
    events.register(channel, peerID: peerID)
    connection.exportedInterface = NSXPCInterface(
      with: CFWGlobalAuthorityXPCProtocol.self)
    connection.exportedObject = service
    let termination = AuthorityConnectionTermination(
      peerID: peerID, role: peer.role, core: core,
      events: events, liveness: livenessRuntime.supervisor)
    connection.interruptionHandler = {
      connectionBox.connection?.invalidate()
    }
    connection.invalidationHandler = { termination.terminate() }
    connection.activate()
    return true
  }

  private func recordPeerAuthorizationDecision(
    pid: pid_t,
    euid: uid_t,
    auditSessionID: UInt32,
    peer: PeerIdentity?,
    preObservation: (state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?),
    postObservation: (state: AuthorityState, revision: UInt64, leaseOwnerUID: uid_t?)
  ) -> Bool {
    do {
      let preDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: preObservation.state,
        revision: preObservation.revision,
        leaseOwnerUID: preObservation.leaseOwnerUID)
      let postDigest = try ReleaseObservationLogger.authorityStateSHA256(
        state: postObservation.state,
        revision: postObservation.revision,
        leaseOwnerUID: postObservation.leaseOwnerUID)
      let accepted = peer != nil
      let decision = try ReleaseObservationPeerDecision(
        role: role,
        peerPID: pid,
        effectiveUserIdentifier: UInt32(euid),
        auditSessionIdentifier: auditSessionID,
        connectionIdentitySHA256: peer?.connectionIdentityDigest.hex,
        accepted: accepted,
        actualCode: accepted ? .accepted : .globalAuthorityIdentityRejected,
        preStateSHA256: preDigest,
        postStateSHA256: postDigest,
        cleanupState: postObservation.state)
      try ReleaseObservationLogger.emitAuthorityPeerDecision(decision)
      return true
    } catch {
      return false
    }
  }
}
