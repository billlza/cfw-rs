import CFWCredentialTransport
import CFWLibboxRuntime
import CFWSharedProtocol
import Foundation
import Security
import SystemConfiguration
import Testing

@testable import CFWProxyAgentCore

// Authorization of the proxy preferences: restoration an owner asks for, rights
// kept across transactions, and failures that keep them for cleanup or fail
// closed.
private struct AuthorizationOnlyOwner: ProxySystemProxyOwning {
  func start(
    configuration: SensitiveDataBuffer, descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not start an engine")
    completionHandler(.failure(.lifecycleConflict))
  }
  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not stop an engine")
    completionHandler(.failure(.lifecycleConflict))
  }
  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    Issue.record("Authorization must not query the engine queue")
    completionHandler(.off)
  }
  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    Issue.record("Authorization that was not granted must not restore settings")
    completionHandler()
  }
  func restoreSettingsBeforeStop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not restore settings before a stop")
    completionHandler(.failure(.lifecycleConflict))
  }
  var callsLibbox: Bool { true }
  func retire(after failure: LibboxInstanceUnclosable) {
    Issue.record("Authorization must not retire the agent")
  }
}

/// Records, in order, the restore that granted rights start and the reply.
private final class RestoringOwner: ProxySystemProxyOwning, @unchecked Sendable {
  private let lock = NSLock()
  private var events: [String] = []

  func record(_ event: String) { lock.withLock { events.append(event) } }
  var values: [String] { lock.withLock { events } }

  func start(
    configuration: SensitiveDataBuffer, descriptor: ConfigurationDescriptor,
    authorization: ProxyOwnerAuthorization,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not start an engine")
    completionHandler(.failure(.lifecycleConflict))
  }
  func stop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not stop an engine")
    completionHandler(.failure(.lifecycleConflict))
  }
  func snapshot(completionHandler: @escaping @Sendable (EngineSnapshot) -> Void) {
    Issue.record("Authorization must not query the engine queue")
    completionHandler(.off)
  }
  func restoreSettingsAfterAuthorization(completionHandler: @escaping @Sendable () -> Void) {
    record("restore-started")
    DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(50)) {
      self.record("restore-finished")
      completionHandler()
    }
  }
  func restoreSettingsBeforeStop(
    expectedConfiguration: ConfigurationDescriptor,
    completionHandler: @escaping @Sendable (Result<Void, ProxySessionLifecycleError>) -> Void
  ) {
    Issue.record("Authorization must not restore settings before a stop")
    completionHandler(.failure(.lifecycleConflict))
  }
  var callsLibbox: Bool { true }
  func retire(after failure: LibboxInstanceUnclosable) {
    Issue.record("Authorization must not retire the agent")
  }
}

private struct AuthorizationJournalStore: ProxyOwnershipJournalStoring {
  let journal: ProxyOwnershipJournal?
  func load() throws -> ProxyOwnershipJournal? { journal }
  func save(_ journal: ProxyOwnershipJournal) throws {
    throw ProxyOwnershipJournalError.invalidJournal
  }
  func remove() throws { throw ProxyOwnershipJournalError.invalidJournal }
}

@Test(arguments: [true, false], [true, false])
func restorationAuthorizationRequiresAPendingJournalWithoutChangingRuntime(
  restorationOnly: Bool, hasJournal: Bool
) async throws {
  let recorder = AuthorizationOperationRecorder()
  let preferences = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder, rightsStatus: errAuthorizationDenied))
  let journal = hasJournal ? try proxyJournal(originalProxyEnabled: false) : nil
  let service = ProxyAgentService(
    lifecycle: AuthorizationOnlyOwner(),
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: preferences, journalStore: AuthorizationJournalStore(journal: journal))

  let error = await withCheckedContinuation { continuation in
    service.authorizeSystemProxy(restorationOnly: restorationOnly) {
      continuation.resume(returning: $0)
    }
  }

  if restorationOnly && !hasJournal {
    #expect(error == nil)
    #expect(recorder.interactionFlags.isEmpty)
  } else {
    #expect(error?.domain == SystemProxyAuthorizationFailure.domain)
    #expect(error?.code == SystemProxyAuthorizationFailure.denied.rawValue)
    #expect(recorder.interactionFlags == [true])
  }
  #expect(recorder.createPreferencesCount == 0)
}

/// Granted rights let the agent restore settings it could not restore before,
/// and the Host's next request sees the result: the reply waits for it.
@Test(arguments: [true, false])
func grantedAuthorizationRestoresLeftoverSettingsBeforeItReplies(
  restorationOnly: Bool
) async throws {
  let recorder = AuthorizationOperationRecorder()
  let preferences = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder))
  let owner = RestoringOwner()
  let service = ProxyAgentService(
    lifecycle: owner,
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: preferences,
    journalStore: AuthorizationJournalStore(journal: try proxyJournal(originalProxyEnabled: false)))

  let error = await withCheckedContinuation { continuation in
    service.authorizeSystemProxy(restorationOnly: restorationOnly) {
      owner.record("reply")
      continuation.resume(returning: $0)
    }
  }
  #expect(error == nil)
  #expect(recorder.interactionFlags == [true])
  #expect(owner.values == ["restore-started", "restore-finished", "reply"])
}

/// The Host may ask again as soon as a reply arrives, for example for the
/// quit-time prompt right after the Off prompt. The finished request no longer
/// counts as pending then.
@Test func authorizationAskedFromThePreviousReplyIsAdmitted() async throws {
  let recorder = AuthorizationOperationRecorder()
  let preferences = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder))
  let service = ProxyAgentService(
    lifecycle: RestoringOwner(),
    configurationChecker: SourceBuiltLibboxConfigurationChecker(),
    preferences: preferences,
    journalStore: AuthorizationJournalStore(journal: try proxyJournal(originalProxyEnabled: false)))

  let errors = await withCheckedContinuation { continuation in
    service.authorizeSystemProxy(restorationOnly: false) { first in
      service.authorizeSystemProxy(restorationOnly: true) { second in
        continuation.resume(returning: [first, second])
      }
    }
  }
  #expect(errors == [nil, nil])
  #expect(recorder.interactionFlags == [true, true])
}

@Test func authorizationIsRetainedAcrossTransactionsWithoutRevokingSharedRights() throws {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder)
  )

  try subject.authorizeForStart()
  let value = try subject.withAuthorizedPreferences { _ in 42 }
  let repeated = try subject.withAuthorizedPreferences { _ in 43 }

  #expect(value == 42)
  #expect(repeated == 43)
  #expect(recorder.createCount == 1)
  #expect(recorder.createPreferencesCount == 2)
  #expect(recorder.interactionFlags == [true])
  #expect(recorder.freeFlags.isEmpty)
  try subject.releaseAuthorization()
  #expect(recorder.freeFlags == [[]])
}

@Test func applyingProxyWithoutAuthorizationRejectsBeforeOpeningPreferencesOrLocking() throws {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder, rightsStatus: errAuthorizationInteractionNotAllowed)
  )
  let journal = try proxyJournal(originalProxyEnabled: false)

  #expect(
    throws: SystemProxyPreferencesError.authorizationDenied(errAuthorizationInteractionNotAllowed)
  ) {
    try subject.apply(journal)
  }
  #expect(recorder.interactionFlags == [false])
  #expect(recorder.createPreferencesCount == 0)
}

@Test func operationFailureKeepsAuthorizationAvailableForCleanup() throws {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(recorder: recorder)
  )

  #expect(throws: SystemProxyPreferencesError.applyFailed(611)) {
    try subject.withAuthorizedPreferences { _ in
      throw SystemProxyPreferencesError.applyFailed(611)
    }
  }
  #expect(recorder.freeFlags.isEmpty)
  try subject.releaseAuthorization()
  #expect(recorder.freeFlags == [[]])
}

@Test func authorizationCreationFailuresAreTypedAndDoNotCreatePreferences() {
  let denied: OSStatus = errAuthorizationDenied
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      creationStatus: denied
    )
  )

  #expect(throws: SystemProxyPreferencesError.authorizationCreationFailed(denied)) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  #expect(recorder.createPreferencesCount == 0)
  #expect(recorder.freeFlags.isEmpty)
}

@Test func missingAuthorizationReferenceFailsClosed() {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      returnsReference: false
    )
  )

  #expect(throws: SystemProxyPreferencesError.authorizationReferenceUnavailable) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  #expect(recorder.createPreferencesCount == 0)
  #expect(recorder.freeFlags.isEmpty)
}

@Test func unavailablePreferencesKeepTheirOriginalErrorAndCanReleaseAuthorization() throws {
  let recorder = AuthorizationOperationRecorder()
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      createsPreferences: false
    )
  )

  #expect(throws: SystemProxyPreferencesError.preferencesUnavailable) {
    try subject.withAuthorizedPreferences { _ in () }
  }
  try subject.releaseAuthorization()
  #expect(recorder.freeFlags == [[]])
}

@Test func operationAndAuthorizationReleaseFailuresRemainDistinct() {
  let recorder = AuthorizationOperationRecorder()
  let releaseFailure: OSStatus = errAuthorizationInternal
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder,
      releaseStatus: releaseFailure
    )
  )

  #expect(throws: SystemProxyPreferencesError.applyFailed(612)) {
    try subject.withAuthorizedPreferences { _ in
      throw SystemProxyPreferencesError.applyFailed(612)
    }
  }
  #expect(
    throws: SystemProxyPreferencesError.authorizationReleaseFailed(
      code: releaseFailure, originalError: nil)
  ) {
    try subject.releaseAuthorization()
  }
  #expect(recorder.freeFlags == [[]])
}

@Test func readOnlyPreferencesNeedNoGrantButWritesFailWithoutPrompting() throws {
  let recorder = AuthorizationOperationRecorder()
  let preferencesRecorder = PreferencesOperationRecorder(applyResults: [])
  let subject = SCPreferencesSystemProxyPreferences(
    operations: testingOperations(recorder: preferencesRecorder),
    authorizationOperations: testingAuthorizationOperations(
      recorder: recorder, rightsStatus: errAuthorizationInteractionNotAllowed))
  #expect(
    throws: SystemProxyPreferencesError.authorizationDenied(
      errAuthorizationInteractionNotAllowed)
  ) {
    try subject.withAuthorizedPreferences { preferences in
      _ = try subject.publishRestoration(preferences, changed: true, conflicts: [])
    }
  }
  #expect(recorder.interactionFlags == [false])
  #expect(recorder.createPreferencesCount == 1)
  #expect(preferencesRecorder.commitCount == 0)
  #expect(preferencesRecorder.applyCount == 0)
  try subject.releaseAuthorization()
}
