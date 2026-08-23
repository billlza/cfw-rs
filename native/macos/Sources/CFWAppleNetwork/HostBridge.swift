import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
@preconcurrency import SystemExtensions

private struct TunnelManagerList: @unchecked Sendable {
  let values: [NETunnelProviderManager]
}

public enum NetworkExtensionFailureDisposition: Equatable, Sendable {
  case permissionDenied
  case unavailable
}

/// Stable, bounded provenance for an NSError returned by NetworkExtension.
/// Policy is derived only from the official domain/code pair; localized text is
/// retained solely as a bounded diagnostic and never drives classification.
public struct NetworkExtensionOperationFailure: Codable, Equatable, Sendable {
  public static let maximumDomainLength = 128
  public static let maximumDiagnosticLength = 256

  public let domain: String
  public let code: Int
  public let diagnostic: String

  public init(_ error: Error) {
    let error = error as NSError
    self.init(
      domain: error.domain,
      code: error.code,
      diagnostic: error.localizedDescription
    )
  }

  public init(domain: String, code: Int, diagnostic: String) {
    self.domain = Self.bounded(domain, maximumLength: Self.maximumDomainLength)
    self.code = code
    self.diagnostic = Self.bounded(
      diagnostic,
      maximumLength: Self.maximumDiagnosticLength
    )
  }

  public var disposition: NetworkExtensionFailureDisposition {
    if domain == NSPOSIXErrorDomain,
      code == Int(POSIXErrorCode.EACCES.rawValue)
        || code == Int(POSIXErrorCode.EPERM.rawValue)
    {
      return .permissionDenied
    }
    if domain == NSCocoaErrorDomain,
      code == CocoaError.Code.fileReadNoPermission.rawValue
        || code == CocoaError.Code.fileWriteNoPermission.rawValue
    {
      return .permissionDenied
    }
    return .unavailable
  }

  private static func bounded(_ value: String, maximumLength: Int) -> String {
    var result = ""
    var byteCount = 0
    for scalar in value.unicodeScalars {
      let output: Unicode.Scalar =
        CharacterSet.controlCharacters.contains(scalar) ? " " : scalar
      let scalarBytes = String(output).utf8.count
      guard byteCount + scalarBytes <= maximumLength else { break }
      result.unicodeScalars.append(output)
      byteCount += scalarBytes
    }
    return result
  }
}

/// Schedules a callback deadline independently of the caller task. Production
/// uses a monotonic dispatch deadline; tests inject a manual scheduler so timeout
/// and late-callback races do not depend on wall-clock sleeps.
package struct CallbackDeadlineScheduler: Sendable {
  private let scheduleBody: @Sendable (@escaping @Sendable () -> Void) -> Void

  package init(timeout: Duration) {
    precondition(timeout > .zero, "Callback deadline must be positive")
    let components = timeout.components
    let seconds =
      Double(components.seconds) + Double(components.attoseconds) / 1_000_000_000_000_000_000
    precondition(seconds.isFinite && seconds > 0, "Callback deadline must be finite")
    scheduleBody = { action in
      DispatchQueue.global(qos: .utility).asyncAfter(
        deadline: .now() + seconds,
        execute: action
      )
    }
  }

  init(schedule: @escaping @Sendable (@escaping @Sendable () -> Void) -> Void) {
    scheduleBody = schedule
  }

  func schedule(_ action: @escaping @Sendable () -> Void) {
    scheduleBody(action)
  }
}

/// First-terminal-result gate for callback APIs that cannot be canceled. The
/// callback, deadline, and task-cancellation paths race through one lock and
/// therefore resume the checked continuation exactly once.
final class CallbackContinuationGate<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Value, Error>?
  private var completedResult: Result<Value, Error>?
  private var operationStarted = false

  func install(_ continuation: CheckedContinuation<Value, Error>) {
    lock.lock()
    if let completedResult {
      lock.unlock()
      continuation.resume(with: completedResult)
      return
    }
    precondition(self.continuation == nil, "Provider response continuation installed twice")
    self.continuation = continuation
    lock.unlock()
  }

  /// Atomically claims the right to invoke the callback API. Cancellation or an
  /// injected synchronous deadline that wins first prevents the side effect.
  func beginOperation() -> Bool {
    lock.lock()
    guard completedResult == nil, !operationStarted else {
      lock.unlock()
      return false
    }
    operationStarted = true
    lock.unlock()
    return true
  }

  func finish(_ result: Result<Value, Error>) {
    lock.lock()
    guard completedResult == nil else {
      lock.unlock()
      return
    }
    completedResult = result
    let continuation = continuation
    self.continuation = nil
    lock.unlock()
    continuation?.resume(with: result)
  }
}

typealias ProviderResponseGate = CallbackContinuationGate<Data>

/// Adapts a single callback operation to async/await with an internal deadline.
/// The deadline is owned by the Swift boundary rather than a Rust waiter, so a
/// missing framework callback cannot retain a coordinator mutation forever.
package func awaitBoundedCallback<Value: Sendable>(
  deadline: CallbackDeadlineScheduler,
  timeoutError: any Error,
  operation:
    @escaping (
      @escaping @Sendable (Result<Value, Error>) -> Void
    ) -> Void
) async throws -> Value {
  let gate = CallbackContinuationGate<Value>()
  return try await withTaskCancellationHandler {
    try await withCheckedThrowingContinuation { continuation in
      gate.install(continuation)
      guard !Task.isCancelled else {
        gate.finish(.failure(CancellationError()))
        return
      }
      deadline.schedule {
        gate.finish(.failure(timeoutError))
      }
      guard gate.beginOperation() else { return }
      operation { result in
        gate.finish(result)
      }
    }
  } onCancel: {
    gate.finish(.failure(CancellationError()))
  }
}

final class PreferenceSaveWait: @unchecked Sendable {
  let operationID: UUID
  let stageID: UUID
  private let operation: PreferenceMutationOperation
  private let journal: PreferenceMutationJournal
  private let timeoutError: AppleNetworkError
  private let failureError: @Sendable (NetworkExtensionOperationFailure) -> AppleNetworkError
  private let gate = CallbackContinuationGate<Void>()
  private let lock = NSLock()
  private var submitted = false

  init(
    operationID: UUID,
    stageID: UUID,
    operation: PreferenceMutationOperation,
    journal: PreferenceMutationJournal,
    timeoutError: AppleNetworkError,
    failureError: @escaping @Sendable (NetworkExtensionOperationFailure) -> AppleNetworkError
  ) {
    self.operationID = operationID
    self.stageID = stageID
    self.operation = operation
    self.journal = journal
    self.timeoutError = timeoutError
    self.failureError = failureError
  }

  var wasSubmitted: Bool { lock.withLock { submitted } }

  func install(_ continuation: CheckedContinuation<Void, Error>) {
    gate.install(continuation)
  }

  func beginSubmission() -> Bool {
    guard gate.beginOperation() else { return false }
    do {
      try journal.markSubmitted(
        operationID: operationID,
        stageID: stageID,
        operation: operation
      )
      lock.withLock { submitted = true }
      return true
    } catch {
      gate.finish(.failure(error))
      return false
    }
  }

  func timeout() {
    gate.finish(.failure(timeoutError))
  }

  func cancel() {
    gate.finish(.failure(CancellationError()))
  }

  func finish(_ error: Error?) {
    let outcome: PreferenceSaveCallbackOutcome
    if let error {
      outcome = .failed(NetworkExtensionOperationFailure(error))
    } else {
      outcome = .succeeded
    }
    do {
      let disposition = try journal.recordCallback(
        operationID: operationID,
        stageID: stageID,
        operation: operation,
        outcome: outcome
      )
      guard disposition == .recorded else {
        // A timeout/cancellation that already won the gate may safely ignore an
        // obsolete late callback. If this callback still owns the live waiter,
        // the gate accepts this failure instead of projecting an unjournaled
        // Network Extension success.
        gate.finish(.failure(AppleNetworkError.preferenceMutationUncertain))
        return
      }
      switch outcome {
      case .succeeded:
        gate.finish(.success(()))
      case .failed(let failure):
        gate.finish(.failure(failureError(failure)))
      }
    } catch {
      gate.finish(.failure(error))
    }
  }
}

enum IdentityBoundInstallAction: Equatable, Sendable {
  case submit
  case reattach
  case completed
  case rejected
  case retirementCapacityExceeded
}

final class IdentityBoundContinuation<Request: AnyObject, Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var activeRequest: Request?
  private var continuation: CheckedContinuation<Value, Error>?
  private var waitID: UUID?
  private var requestSubmitted = false
  private var completedResult: Result<Value, Error>?
  private var pendingWaitResult: Result<Value, Error>?
  private var intermediateResultDelivered = false
  private var retiredRequests: [ObjectIdentifier: Request] = [:]
  private let maximumRetiredRequests = 1

  func install(
    request: Request,
    waitID: UUID,
    continuation: CheckedContinuation<Value, Error>
  ) -> IdentityBoundInstallAction {
    lock.lock()
    if let completedResult {
      self.completedResult = nil
      lock.unlock()
      continuation.resume(with: completedResult)
      return .completed
    }
    if let pendingWaitResult {
      self.pendingWaitResult = nil
      lock.unlock()
      continuation.resume(with: pendingWaitResult)
      return .completed
    }
    if activeRequest != nil {
      guard self.continuation == nil else {
        lock.unlock()
        return .rejected
      }
      self.waitID = waitID
      self.continuation = continuation
      lock.unlock()
      return .reattach
    }
    if retiredRequests.count >= maximumRetiredRequests {
      lock.unlock()
      return .retirementCapacityExceeded
    }
    activeRequest = request
    self.waitID = waitID
    self.continuation = continuation
    requestSubmitted = false
    intermediateResultDelivered = false
    lock.unlock()
    return .submit
  }

  func beginSubmission(request: Request, waitID: UUID) -> Bool {
    lock.lock()
    guard activeRequest === request, self.waitID == waitID,
      continuation != nil, !requestSubmitted
    else {
      lock.unlock()
      return false
    }
    requestSubmitted = true
    lock.unlock()
    return true
  }

  func finish(request: Request, result: Result<Value, Error>) {
    lock.lock()
    guard activeRequest === request else {
      retiredRequests.removeValue(forKey: ObjectIdentifier(request))
      lock.unlock()
      return
    }
    activeRequest = nil
    let continuation = continuation
    self.continuation = nil
    waitID = nil
    requestSubmitted = false
    pendingWaitResult = nil
    intermediateResultDelivered = false
    if continuation == nil {
      completedResult = result
    }
    lock.unlock()
    continuation?.resume(with: result)
  }

  func finishWaitKeepingRequest(waitID: UUID, result: Result<Value, Error>) {
    lock.lock()
    guard self.waitID == waitID, continuation != nil else {
      lock.unlock()
      return
    }
    let continuation = continuation
    self.continuation = nil
    self.waitID = nil
    if !requestSubmitted {
      activeRequest = nil
    }
    lock.unlock()
    continuation?.resume(with: result)
  }

  /// Completes only the caller's wait while retaining the operating-system
  /// request identity until its terminal delegate callback arrives.
  @discardableResult
  func completeWaitKeepingRequest(request: Request, value: Value) -> Bool {
    lock.lock()
    guard activeRequest === request, !intermediateResultDelivered else {
      lock.unlock()
      return false
    }
    intermediateResultDelivered = true
    let continuation = continuation
    self.continuation = nil
    waitID = nil
    if continuation == nil {
      pendingWaitResult = .success(value)
    }
    lock.unlock()
    continuation?.resume(returning: value)
    return true
  }

  /// Retires one exact submitted request for an explicit cancel command. The OS
  /// request cannot be withdrawn; while it remains unresolved, the single-entry
  /// retirement bound rejects another submission instead of accumulating
  /// uncancellable requests. Its terminal callback releases the capacity only.
  func cancelActiveWait() {
    lock.lock()
    let continuation = continuation
    if let activeRequest, requestSubmitted {
      precondition(
        retiredRequests.count < maximumRetiredRequests,
        "System Extension retired-request capacity invariant"
      )
      retiredRequests[ObjectIdentifier(activeRequest)] = activeRequest
    }
    activeRequest = nil
    self.continuation = nil
    waitID = nil
    requestSubmitted = false
    completedResult = nil
    pendingWaitResult = nil
    intermediateResultDelivered = false
    lock.unlock()
    continuation?.resume(throwing: CancellationError())
  }

  var retiredRequestCount: Int { lock.withLock { retiredRequests.count } }

}

public enum SystemExtensionInstallResult: Equatable, Sendable {
  case completed
  case awaitingApproval
  case requiresRestart
}

public enum AppleNetworkError: Error, Equatable, Sendable {
  case installationAlreadyInProgress
  case systemExtensionRequestCapacityExceeded
  case systemExtensionInstallationTimedOut
  case unknownSystemExtensionResult(Int)
  case systemExtensionInstallationFailed(domain: String, code: Int, message: String)
  case preferenceLoadFailed(NetworkExtensionOperationFailure)
  case preferenceLoadTimedOut
  case preferenceSaveFailed(NetworkExtensionOperationFailure)
  case preferenceSaveTimedOut
  case preferenceMutationUncertain
  case preferenceMutationJournalUnavailable(String)
  case preferenceRemoveFailed(NetworkExtensionOperationFailure)
  case preferenceRemoveTimedOut
  case duplicateTunnelManagers(Int)
  case globalAuthorityUnavailable
  case invalidConfigurationSlot
  case systemExtensionStateTransportFailed(String)
  case systemExtensionStateTransportTimedOut
  case tunnelStartFailed(String)
  case tunnelStartCleanupFailed(start: String, cleanup: String)
  case tunnelStopTimedOut
  case staleStopRequest
  case providerDidNotRespond
  case providerMessageTimedOut
  case providerMessageFailed(String)
  case providerResponseMismatch
  case providerFailure(EngineFailure)
  case managedManagerVerificationFailed(String)
  /// Compensation observed a managed-preference change it must not overwrite
  /// (external/administrator edit or a missing prior value); leaves Quarantined.
  case compensationConflict(String)
  /// Compensation could not prove cleanup within its bounded budget (stop timeout
  /// or an unverifiable restored result); leaves Quarantined.
  case cleanupUnproven(String)
}

/// Bounded, non-secret inputs the Host hands to the Global Authority when it
/// prepares a Tunnel start. The configuration and credential bytes travel to the
/// Authority over its typed XPC prepare call and are never written to preferences
/// or `startVPNTunnel(options:)`.
public struct HostTunnelStartPreparation: Sendable {
  public let descriptor: ConfigurationDescriptor
  public let configuration: Data
  public let credentialPayload: Data?

  public init(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?
  ) {
    self.descriptor = descriptor
    self.configuration = configuration
    self.credentialPayload = credentialPayload
  }
}

/// The single-use opaque Start Ticket, bounded non-secret descriptor, and exact
/// Authority operation identity. No configuration or credential bytes are
/// returned to the Host.
public struct HostPreparedTunnelStart: Sendable {
  public let ticket: StartTicket
  public let descriptor: ConfigurationDescriptor
  public let operationID: UUID

  public init(
    ticket: StartTicket,
    descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) {
    self.ticket = ticket
    self.descriptor = descriptor
    self.operationID = operationID
  }
}

/// Injectable seam over the Global Authority prepare step. Implementations must
/// prepare with the Authority BEFORE any preference or network mutation and fail
/// closed with a typed Authority error when the Authority is unavailable or
/// unproven. There is no direct configuration/credential payload fallback.
public protocol TunnelStartPreparing: Sendable {
  func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart
}

/// Default production preparer used until the authenticated Host→Authority XPC
/// client is wired end to end. It fails closed so no Tunnel start can proceed
/// without a real Authority preparation and single-use ticket.
public struct FailClosedTunnelStartPreparer: TunnelStartPreparing {
  public init() {}

  public func prepareTunnelStart(
    _ preparation: HostTunnelStartPreparation
  ) async throws -> HostPreparedTunnelStart {
    throw AppleNetworkError.globalAuthorityUnavailable
  }
}

/// Injectable seam over the exact `NETunnelProviderManager` operations the
/// ticket-only start flow needs. Extracted so the flow is exercised with an
/// in-memory fake and requires no real NetworkExtension in tests.
protocol ManagedTunnelOperating: Sendable {
  /// Persists ONLY the descriptor-only preference contract to the managed
  /// manager, creating it when absent and explicitly disabling/clearing VPN On
  /// Demand. No configuration, credential, or on-demand rule bytes are written.
  func saveDescriptorOnly(
    _ descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) async throws
  /// Reloads the managed manager from preferences, verifies every bounded value
  /// against the durable receipt, and returns its descriptor.
  func reloadDescriptor() async throws -> ConfigurationDescriptor
  /// Starts the managed tunnel connection with ONLY the one-use start ticket.
  func startWithTicket(_ ticketBytes: Data) async throws
}

/// Ordered ticket-only Tunnel start: prepare with the Authority before any
/// preference mutation, save the descriptor-only manager, reload and verify the
/// exact bounded preference values, then start with only the single-use ticket.
/// Every Authority, XPC, and NetworkExtension side effect lives behind an
/// injected seam.
enum TicketOnlyTunnelStartFlow {
  static func run(
    descriptor: ConfigurationDescriptor,
    configuration: Data,
    credentialPayload: Data?,
    preparer: any TunnelStartPreparing,
    manager: any ManagedTunnelOperating,
    checkCancellation: @Sendable () throws -> Void = { try Task.checkCancellation() }
  ) async throws {
    try checkCancellation()
    guard descriptor.slot == .tunnel else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    // (1) Prepare with the Global Authority BEFORE any preference mutation. This
    // yields the single-use opaque ticket and the bounded non-secret descriptor.
    let prepared = try await preparer.prepareTunnelStart(
      HostTunnelStartPreparation(
        descriptor: descriptor,
        configuration: configuration,
        credentialPayload: credentialPayload
      )
    )
    let ticket = prepared.ticket
    defer { ticket.erase() }
    let preparedDescriptor = prepared.descriptor
    guard preparedDescriptor.slot == .tunnel else {
      throw AppleNetworkError.invalidConfigurationSlot
    }
    try checkCancellation()

    // (2) Save only the descriptor-only provider configuration.
    try await manager.saveDescriptorOnly(
      preparedDescriptor,
      operationID: prepared.operationID)
    // Saving preferences is a committed external mutation and cannot be canceled
    // through NetworkExtension. Honor cancellation before reloading and, critically,
    // before starting the data plane.
    try checkCancellation()

    // (3) Reload and verify the exact bounded managed-manager round trip.
    let reloaded = try await manager.reloadDescriptor()
    guard reloaded == preparedDescriptor else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "Reloaded managed tunnel descriptor does not match the prepared descriptor."
      )
    }
    try checkCancellation()

    // (4) Start with ONLY the one-use ticket. No configuration or credential bytes.
    var ticketBytes = try ticket.withUnsafeBytes { Data($0) }
    defer { ticketBytes.resetBytes(in: ticketBytes.startIndex..<ticketBytes.endIndex) }
    try await manager.startWithTicket(ticketBytes)
  }
}

public protocol SystemExtensionInstalling: Sendable {
  func install() async throws -> SystemExtensionInstallResult
  /// Abandons only local wait/request identity. Public SystemExtensions API
  /// does not provide a way to withdraw a submitted activation request; its
  /// eventual callback is ignored and cannot affect a newer request.
  func cancelInstallationWait()
}

/// Uses only the public SystemExtensions API. The host supplies a callback so
/// it can surface the OS approval state without treating approval as success.
public final class OSSystemExtensionInstaller: NSObject, SystemExtensionInstalling,
  OSSystemExtensionRequestDelegate, @unchecked Sendable
{
  public typealias ApprovalHandler = @Sendable () -> Void

  private let extensionIdentifier: String
  private let approvalHandler: ApprovalHandler
  private let requestDeadline: CallbackDeadlineScheduler
  private let continuationGate =
    IdentityBoundContinuation<OSSystemExtensionRequest, SystemExtensionInstallResult>()

  public init(
    extensionIdentifier: String,
    approvalHandler: @escaping ApprovalHandler,
    requestTimeout: Duration = .seconds(10)
  ) {
    self.extensionIdentifier = extensionIdentifier
    self.approvalHandler = approvalHandler
    requestDeadline = CallbackDeadlineScheduler(timeout: requestTimeout)
  }

  public func install() async throws -> SystemExtensionInstallResult {
    try Task.checkCancellation()
    let request = OSSystemExtensionRequest.activationRequest(
      forExtensionWithIdentifier: extensionIdentifier,
      queue: .main
    )
    let waitID = UUID()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        guard !Task.isCancelled else {
          continuation.resume(throwing: CancellationError())
          return
        }
        let action = continuationGate.install(
          request: request,
          waitID: waitID,
          continuation: continuation
        )
        guard action != .rejected else {
          continuation.resume(throwing: AppleNetworkError.installationAlreadyInProgress)
          return
        }
        guard action != .retirementCapacityExceeded else {
          continuation.resume(
            throwing: AppleNetworkError.systemExtensionRequestCapacityExceeded
          )
          return
        }
        guard action != .completed else { return }

        requestDeadline.schedule {
          self.continuationGate.finishWaitKeepingRequest(
            waitID: waitID,
            result: .failure(AppleNetworkError.systemExtensionInstallationTimedOut)
          )
        }
        guard action == .submit else { return }
        guard continuationGate.beginSubmission(request: request, waitID: waitID) else {
          return
        }

        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
      }
    } onCancel: {
      cancelWaitingTask(waitID)
    }
  }

  public func cancelInstallationWait() {
    continuationGate.cancelActiveWait()
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    let mapped: SystemExtensionInstallResult
    switch result {
    case .completed:
      mapped = .completed
    case .willCompleteAfterReboot:
      mapped = .requiresRestart
    @unknown default:
      finish(
        request,
        .failure(
          AppleNetworkError.unknownSystemExtensionResult(result.rawValue)
        )
      )
      return
    }
    finish(request, .success(mapped))
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFailWithError error: Error
  ) {
    let failure = NetworkExtensionOperationFailure(error)
    finish(
      request,
      .failure(
        AppleNetworkError.systemExtensionInstallationFailed(
          domain: failure.domain,
          code: failure.code,
          message: failure.diagnostic
        )
      )
    )
  }

  public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    if continuationGate.completeWaitKeepingRequest(
      request: request,
      value: .awaitingApproval
    ) {
      approvalHandler()
    }
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension extension: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    Self.replacementAction(
      existingBundleVersion: existing.bundleVersion,
      candidateBundleVersion: `extension`.bundleVersion
    )
  }

  static func replacementAction(
    existingBundleVersion: String,
    candidateBundleVersion: String
  ) -> OSSystemExtensionRequest.ReplacementAction {
    guard
      let existing = canonicalReleaseBundleVersion(existingBundleVersion),
      let candidate = canonicalReleaseBundleVersion(candidateBundleVersion),
      candidate > existing
    else {
      return .cancel
    }
    return .replace
  }

  /// Release builds use the repository-wide canonical `CFBundleVersion`
  /// contract: one positive signed-64-bit base-10 integer, with no leading zero. Foundation's
  /// numeric string comparison orders malformed/suffixed values such as `abc`
  /// or `42.8b1`, so it must not decide a privileged extension replacement.
  private static func canonicalReleaseBundleVersion(_ value: String) -> Int64? {
    guard !value.isEmpty, value.utf8.count <= 19, value.utf8.first != 48,
      value.utf8.allSatisfy({ (48...57).contains($0) }),
      let parsed = Int64(value), parsed > 0
    else {
      return nil
    }
    return parsed
  }

  private func finish(
    _ request: OSSystemExtensionRequest,
    _ result: Result<SystemExtensionInstallResult, Error>
  ) {
    continuationGate.finish(request: request, result: result)
  }

  private func cancelWaitingTask(_ waitID: UUID) {
    continuationGate.finishWaitKeepingRequest(
      waitID: waitID,
      result: .failure(CancellationError())
    )
  }
}

public protocol TunnelHostBridging: Sendable {
  func installTunnel() async throws -> SystemExtensionInstallResult
  func cancelTunnelInstallationWait() async
  func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws
  func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws
  func snapshot() async throws -> EngineSnapshot
  /// Public NetworkExtension state used only by the Global Authority restart
  /// reconciliation barrier. Unknown or transitional values must not prove Off.
  func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus
  func hasManagedTunnelConfiguration() async throws -> Bool
  func managedTunnelConfiguration() async throws -> ConfigurationDescriptor?
  /// Returns the exact durable write-ahead descriptor recovered at Host startup.
  /// A non-nil value blocks every new native mutation until compensation succeeds.
  func pendingPreferenceMutationConfiguration() async throws -> ConfigurationDescriptor?
  /// Revokes or stop-orders the exact Authority generation and compare-and-
  /// restores/removes its durable manager. This step deliberately retains the
  /// write-ahead receipt.
  func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool
  /// Clears an idempotently compensated receipt only after a final fresh reload
  /// proves the exact prior/nil state and OS Off.
  func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws
  /// Commits a successful start only after the durable manager and connected
  /// runtime still match the exact write-ahead receipt.
  func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws
}

extension TunnelHostBridging {
  public func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus {
    .unknown
  }
}

private struct ClosureAuthorityPreparationRevoker: AuthorityPreparationRevoking {
  let body: @Sendable () async throws -> Void

  func revokePreparation() async throws {
    try await body()
  }
}

/// Serializes all NETunnelProviderManager mutations in one actor. It never
/// reports TunnelActive from NEVPNStatus alone: the connected provider must
/// return a typed snapshot whose configuration digest matches preferences.
public actor NetworkExtensionHostBridge: TunnelHostBridging, ManagedTunnelOperating,
  ManagedTunnelPreferences
{
  private let providerBundleIdentifier: String
  private let installer: any SystemExtensionInstalling
  private let preparer: any TunnelStartPreparing
  private let callbackDeadline: CallbackDeadlineScheduler
  private let preferenceMutationJournal: PreferenceMutationJournal
  private var inFlightManager: NETunnelProviderManager?

  public init(
    providerBundleIdentifier: String,
    installer: any SystemExtensionInstalling,
    preparer: any TunnelStartPreparing = FailClosedTunnelStartPreparer(),
    preferenceMutationKeychainAccessGroup: String,
    callbackTimeout: Duration = .seconds(5)
  ) throws {
    self.providerBundleIdentifier = providerBundleIdentifier
    self.installer = installer
    self.preparer = preparer
    callbackDeadline = CallbackDeadlineScheduler(timeout: callbackTimeout)
    do {
      preferenceMutationJournal = try PreferenceMutationJournal(
        store: KeychainTunnelPreferenceMutationJournalStore(
          keychainAccessGroup: preferenceMutationKeychainAccessGroup
        )
      )
    } catch {
      throw AppleNetworkError.preferenceMutationJournalUnavailable(
        "The Host-only Keychain receipt could not be loaded."
      )
    }
  }

  /// Builds the single-key `startVPNTunnel(options:)` dictionary carrying only the
  /// bounded, opaque start ticket. Exposed for focused ticket-only option tests.
  static func ticketStartOptions(_ ticketBytes: Data) -> [String: NSData] {
    [NativeProtocolConstants.tunnelStartTicketOptionKey: ticketBytes as NSData]
  }

  public func installTunnel() async throws -> SystemExtensionInstallResult {
    try await installer.install()
  }

  public func cancelTunnelInstallationWait() async {
    // This intentionally does not call stopTunnel. Approval/activation is a
    // SystemExtensions control-plane operation, not a running VPN session,
    // and Apple exposes no public cancellation API once a request is submitted.
    installer.cancelInstallationWait()
  }

  public func startTunnel(
    configuration: Data,
    descriptor: ConfigurationDescriptor,
    credentialPayload: Data?
  ) async throws {
    // Prepare with the Global Authority before any preference mutation, persist only
    // the descriptor-only manager, verify the exact reloaded preferences, and start
    // with only the single-use ticket. There is no direct configuration/credential
    // payload path: `startVPNTunnel(options:)` carries only the ticket.
    do {
      try await TicketOnlyTunnelStartFlow.run(
        descriptor: descriptor,
        configuration: configuration,
        credentialPayload: credentialPayload,
        preparer: preparer,
        manager: self
      )
    } catch {
      // A timed-out load/save callback may still arrive, but its manager object
      // must never be reused by a later mutation. A retry reloads the durable
      // preference store and reconciles what the OS actually committed.
      inFlightManager = nil
      throw error
    }
  }

  // MARK: - ManagedTunnelOperating (NetworkExtension-backed)

  func saveDescriptorOnly(
    _ descriptor: ConfigurationDescriptor,
    operationID: UUID
  ) async throws {
    let (manager, createdManager) = try await loadOrCreateManager()
    guard try managedConnectionStatus(manager).isStopped else {
      throw AppleNetworkError.cleanupUnproven(
        "Managed tunnel preferences cannot be replaced while the OS connection is active."
      )
    }
    let priorValues = createdManager ? nil : try Self.managedPreferenceValues(manager)
    let writtenValues = ManagedTunnelPreferenceValues(
      descriptor: descriptor,
      providerBundleIdentifier: providerBundleIdentifier,
      serverAddress: "Clash for Mac",
      isEnabled: true,
      localizedDescription: "Clash for Mac Tunnel"
    )
    let receipt = TunnelPreferenceMutationReceipt(
      operationID: operationID,
      createdManager: createdManager,
      priorValues: priorValues,
      writtenValues: writtenValues
    )
    // Always replace the protocol object. Reusing a legacy protocol would retain
    // inherited credential, proxy, sleep, route, or on-demand state that is outside
    // the descriptor-only preference contract.
    try Self.applyDescriptorOnlyPreferences(writtenValues, to: manager)
    try await save(manager, receipt: receipt)
    inFlightManager = manager
  }

  func reloadDescriptor() async throws -> ConfigurationDescriptor {
    guard let manager = inFlightManager else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "No managed tunnel manager is staged for reload verification."
      )
    }
    try await reload(manager)
    let reloaded = try Self.managedPreferenceValues(manager)
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: reloaded.descriptor,
        requireSettledCurrentProcessMutation: true
      ),
      reloaded == receipt.writtenValues
    else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "Reloaded managed tunnel preferences do not match the durable write receipt."
      )
    }
    return reloaded.descriptor
  }

  func startWithTicket(_ ticketBytes: Data) async throws {
    guard let manager = inFlightManager else {
      throw AppleNetworkError.managedManagerVerificationFailed(
        "No managed tunnel manager is staged for start."
      )
    }
    defer { inFlightManager = nil }
    do {
      try manager.connection.startVPNTunnel(options: Self.ticketStartOptions(ticketBytes))
    } catch let startError {
      if startError is CancellationError {
        throw startError
      }
      throw AppleNetworkError.tunnelStartFailed(startError.localizedDescription)
    }
  }

  public func stopTunnel(expectedConfiguration: ConfigurationDescriptor) async throws {
    guard let manager = try await soleManager() else {
      throw AppleNetworkError.staleStopRequest
    }
    guard try manager.configurationDescriptor() == expectedConfiguration else {
      throw AppleNetworkError.staleStopRequest
    }
    manager.connection.stopVPNTunnel()

    let clock = ContinuousClock()
    let deadline = clock.now.advanced(by: .seconds(5))
    while clock.now < deadline {
      switch manager.connection.status {
      case .disconnected, .invalid:
        return
      default:
        try await Task.sleep(for: .milliseconds(100))
      }
    }
    throw AppleNetworkError.tunnelStopTimedOut
  }

  public func snapshot() async throws -> EngineSnapshot {
    try Task.checkCancellation()
    guard let manager = try await soleManager() else {
      return .off
    }
    try Task.checkCancellation()
    switch manager.connection.status {
    case .invalid, .disconnected:
      return .off
    case .connecting, .reasserting:
      return .tunnelStarting(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .disconnecting:
      return .tunnelStopping(
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    case .connected:
      return try await providerSnapshot(manager)
    @unknown default:
      return .tunnelFailed(
        EngineFailure(
          code: "unknown-nevpn-status",
          message: "NetworkExtension returned an unknown VPN status.",
          isRetryable: false
        ),
        configuration: try manager.configurationDescriptor(),
        sequence: 0
      )
    }
  }

  public func recoveryManagedTunnelStatus() async throws -> RecoveryManagedTunnelStatus {
    try Task.checkCancellation()
    guard let manager = try await soleManager() else {
      return .invalid
    }
    try Task.checkCancellation()
    switch manager.connection.status {
    case .disconnected:
      return .disconnected
    case .invalid:
      return .invalid
    case .connecting, .reasserting:
      return .connecting
    case .connected:
      return .connected
    case .disconnecting:
      return .unknown
    @unknown default:
      return .unknown
    }
  }

  public func hasManagedTunnelConfiguration() async throws -> Bool {
    try await soleManager() != nil
  }

  public func managedTunnelConfiguration() async throws -> ConfigurationDescriptor? {
    guard let manager = try await soleManager() else {
      return nil
    }
    return try manager.configurationDescriptor()
  }

  public func pendingPreferenceMutationConfiguration() async throws
    -> ConfigurationDescriptor?
  {
    try preferenceMutationJournal.pendingDescriptor()
  }

  public func compensatePendingPreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor,
    revokePreparation: @escaping @Sendable () async throws -> Void
  ) async throws -> Bool {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else {
      return false
    }

    try await TunnelPreferenceCompensation.run(
      receipt: receipt,
      authority: ClosureAuthorityPreparationRevoker(body: revokePreparation),
      preferences: self
    )
    inFlightManager = nil
    return true
  }

  public func finishPreferenceCompensation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else { return }
    guard try await loadCurrentValues() == receipt.expectedRestoredValues,
      try await connectionStatus().isStopped
    else {
      throw AppleNetworkError.cleanupUnproven(
        "Tunnel preference compensation is not durably restored and Off."
      )
    }
    try preferenceMutationJournal.clear(operationID: receipt.operationID)
    inFlightManager = nil
  }

  public func completePreferenceMutation(
    expectedConfiguration: ConfigurationDescriptor
  ) async throws {
    guard
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: expectedConfiguration,
        requireSettledCurrentProcessMutation: true
      )
    else {
      throw AppleNetworkError.cleanupUnproven(
        "A Tunnel start reached readiness without its durable preference receipt."
      )
    }

    let manager = try await soleManager()
    guard let manager,
      try Self.managedPreferenceValues(manager) == receipt.writtenValues,
      try managedConnectionStatus(manager) == .connected
    else {
      throw AppleNetworkError.cleanupUnproven(
        "The ready Tunnel no longer matches its durable preference receipt."
      )
    }
    try preferenceMutationJournal.clear(operationID: receipt.operationID)
    inFlightManager = nil
  }

  // MARK: - ManagedTunnelPreferences (durable compensation)

  public func loadCurrentValues() async throws -> ManagedTunnelPreferenceValues? {
    try await soleManager().map(Self.managedPreferenceValues)
  }

  public func connectionStatus() async throws -> ManagedTunnelConnectionStatus {
    guard let manager = try await soleManager() else { return .invalid }
    return try managedConnectionStatus(manager)
  }

  public func stop() async throws {
    guard let manager = try await soleManager() else { return }
    manager.connection.stopVPNTunnel()
  }

  public func apply(_ values: ManagedTunnelPreferenceValues) async throws {
    guard let manager = try await soleManager(),
      let descriptor = try preferenceMutationJournal.pendingDescriptor(),
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: descriptor,
        requireSettledCurrentProcessMutation: false
      ),
      try Self.managedPreferenceValues(manager) == receipt.writtenValues
    else {
      throw AppleNetworkError.compensationConflict(
        "Managed tunnel preferences changed before the restore save."
      )
    }

    let stageID = try preferenceMutationJournal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationSave
    )

    try Self.applyDescriptorOnlyPreferences(values, to: manager)
    try await saveCompensation(
      manager,
      operationID: receipt.operationID,
      stageID: stageID
    )
    try await reload(manager)
    guard try Self.managedPreferenceValues(manager) == values else {
      throw AppleNetworkError.cleanupUnproven(
        "Reloaded managed tunnel preferences do not match the compensation receipt."
      )
    }
    inFlightManager = nil
  }

  public func removeManager() async throws {
    guard let manager = try await soleManager(),
      let descriptor = try preferenceMutationJournal.pendingDescriptor(),
      let receipt = try preferenceMutationJournal.pendingReceipt(
        expectedDescriptor: descriptor,
        requireSettledCurrentProcessMutation: false
      ),
      try Self.managedPreferenceValues(manager) == receipt.writtenValues
    else {
      throw AppleNetworkError.compensationConflict(
        "Managed tunnel preferences changed before manager removal."
      )
    }

    let stageID = try preferenceMutationJournal.prepareCompensation(
      operationID: receipt.operationID,
      operation: .compensationRemove
    )
    let wait = PreferenceSaveWait(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .compensationRemove,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceRemoveTimedOut,
      failureError: AppleNetworkError.preferenceRemoveFailed
    )
    try await awaitPreferenceMutationCallback(wait) { callback in
      manager.removeFromPreferences(completionHandler: callback)
    }
    inFlightManager = nil
  }

  private func providerSnapshot(_ manager: NETunnelProviderManager) async throws -> EngineSnapshot {
    guard let session = manager.connection as? NETunnelProviderSession else {
      throw AppleNetworkError.providerDidNotRespond
    }
    let command = try NativeCommand(kind: .snapshot)
    let request = RequestEnvelope(command: command)
    let requestData = try ProtocolCodec.encode(request)
    let responseData: Data = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.providerMessageTimedOut
    ) { finish in
      do {
        try session.sendProviderMessage(requestData) { data in
          guard let data else {
            finish(.failure(AppleNetworkError.providerDidNotRespond))
            return
          }
          finish(.success(data))
        }
      } catch {
        finish(
          .failure(
            AppleNetworkError.providerMessageFailed(error.localizedDescription)
          )
        )
      }
    }
    let response = try ProtocolCodec.decodeResponse(responseData)
    guard response.requestID == request.requestID else {
      throw AppleNetworkError.providerResponseMismatch
    }
    if let failure = response.failure {
      throw AppleNetworkError.providerFailure(failure)
    }
    guard let providerSnapshot = response.result?.snapshot,
      providerSnapshot.configuration == (try manager.configurationDescriptor()),
      providerSnapshot.state.kind == .tunnelActive
        || providerSnapshot.state.kind == .failed
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return providerSnapshot
  }

  private func loadOrCreateManager() async throws -> (NETunnelProviderManager, Bool) {
    if let manager = try await soleManager() {
      let values = try Self.managedPreferenceValues(manager)
      guard values.providerBundleIdentifier == providerBundleIdentifier else {
        throw AppleNetworkError.compensationConflict(
          "The calling application's managed tunnel has an unexpected provider identity."
        )
      }
      return (manager, false)
    }
    return (NETunnelProviderManager(), true)
  }

  private func soleManager() async throws -> NETunnelProviderManager? {
    let managerList: TunnelManagerList = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { finish in
      NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if let error {
          finish(
            .failure(
              AppleNetworkError.preferenceLoadFailed(
                NetworkExtensionOperationFailure(error)
              )
            )
          )
        } else {
          finish(.success(TunnelManagerList(values: managers ?? [])))
        }
      }
    }
    return try Self.classifyManagerInventory(managerList.values)
  }

  static func classifyManagerInventory(
    _ managers: [NETunnelProviderManager]
  ) throws -> NETunnelProviderManager? {
    guard managers.count <= 1 else {
      throw AppleNetworkError.duplicateTunnelManagers(managers.count)
    }
    return managers.first
  }

  private func save(
    _ manager: NETunnelProviderManager,
    receipt: TunnelPreferenceMutationReceipt
  ) async throws {
    let stageID = try preferenceMutationJournal.begin(receipt)
    let wait = PreferenceSaveWait(
      operationID: receipt.operationID,
      stageID: stageID,
      operation: .originalSave,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceSaveTimedOut,
      failureError: AppleNetworkError.preferenceSaveFailed
    )
    do {
      let _: Void = try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          wait.install(continuation)
          guard !Task.isCancelled else {
            wait.cancel()
            return
          }
          callbackDeadline.schedule { wait.timeout() }
          guard wait.beginSubmission() else { return }
          manager.saveToPreferences { error in
            wait.finish(error)
          }
        }
      } onCancel: {
        wait.cancel()
      }
    } catch {
      if !wait.wasSubmitted {
        try preferenceMutationJournal.abandonUnsubmitted(
          operationID: receipt.operationID,
          stageID: stageID)
      }
      throw error
    }
  }

  private func reload(_ manager: NETunnelProviderManager) async throws {
    let _: Void = try await awaitBoundedCallback(
      deadline: callbackDeadline,
      timeoutError: AppleNetworkError.preferenceLoadTimedOut
    ) { finish in
      manager.loadFromPreferences { error in
        if let error {
          finish(
            .failure(
              AppleNetworkError.preferenceLoadFailed(
                NetworkExtensionOperationFailure(error)
              )
            )
          )
        } else {
          finish(.success(()))
        }
      }
    }
  }

  private func saveCompensation(
    _ manager: NETunnelProviderManager,
    operationID: UUID,
    stageID: UUID
  ) async throws {
    let wait = PreferenceSaveWait(
      operationID: operationID,
      stageID: stageID,
      operation: .compensationSave,
      journal: preferenceMutationJournal,
      timeoutError: .preferenceSaveTimedOut,
      failureError: AppleNetworkError.preferenceSaveFailed
    )
    try await awaitPreferenceMutationCallback(wait) { callback in
      manager.saveToPreferences(completionHandler: callback)
    }
  }

  private func awaitPreferenceMutationCallback(
    _ wait: PreferenceSaveWait,
    submission: @escaping @Sendable (@escaping @Sendable (Error?) -> Void) -> Void
  ) async throws {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        wait.install(continuation)
        guard !Task.isCancelled else {
          wait.cancel()
          return
        }
        callbackDeadline.schedule { wait.timeout() }
        guard wait.beginSubmission() else { return }
        submission { error in wait.finish(error) }
      }
    } onCancel: {
      wait.cancel()
    }
  }

  static func managedPreferenceValues(
    _ manager: NETunnelProviderManager
  ) throws -> ManagedTunnelPreferenceValues {
    let hasOnDemandRules = manager.onDemandRules?.isEmpty == false
    guard !manager.isOnDemandEnabled, !hasOnDemandRules else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel contains unauthorized on-demand settings."
      )
    }
    guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol,
      let providerBundleIdentifier = tunnelProtocol.providerBundleIdentifier,
      !providerBundleIdentifier.isEmpty
    else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel protocol cannot be decoded completely."
      )
    }
    let protocolSettings = Self.protocolSettings(tunnelProtocol)
    guard protocolSettings.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel contains unauthorized protocol fields."
      )
    }
    let descriptor: ConfigurationDescriptor
    do {
      descriptor = try manager.configurationDescriptor()
    } catch {
      throw AppleNetworkError.compensationConflict(
        "The calling application's managed tunnel descriptor cannot be decoded completely."
      )
    }
    return ManagedTunnelPreferenceValues(
      descriptor: descriptor,
      providerBundleIdentifier: providerBundleIdentifier,
      serverAddress: tunnelProtocol.serverAddress,
      isEnabled: manager.isEnabled,
      isOnDemandEnabled: manager.isOnDemandEnabled,
      hasOnDemandRules: hasOnDemandRules,
      localizedDescription: manager.localizedDescription,
      protocolSettings: protocolSettings
    )
  }

  static func applyDescriptorOnlyPreferences(
    _ values: ManagedTunnelPreferenceValues,
    to manager: NETunnelProviderManager
  ) throws {
    guard values.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "A managed tunnel receipt contains unauthorized manager or protocol settings."
      )
    }
    manager.protocolConfiguration = try Self.descriptorOnlyProtocol(for: values)
    manager.localizedDescription = values.localizedDescription
    manager.isEnabled = values.isEnabled
    manager.isOnDemandEnabled = false
    manager.onDemandRules = nil
  }

  static func descriptorOnlyProtocol(
    for values: ManagedTunnelPreferenceValues
  ) throws -> NETunnelProviderProtocol {
    guard values.isDescriptorOnly else {
      throw AppleNetworkError.compensationConflict(
        "A managed tunnel receipt contains unauthorized manager or protocol settings."
      )
    }
    let tunnelProtocol = NETunnelProviderProtocol()
    tunnelProtocol.providerBundleIdentifier = values.providerBundleIdentifier
    tunnelProtocol.serverAddress = values.serverAddress
    tunnelProtocol.providerConfiguration = try values.descriptor.providerConfiguration()
    tunnelProtocol.username = nil
    tunnelProtocol.passwordReference = nil
    tunnelProtocol.identityReference = nil
    tunnelProtocol.identityData = nil
    tunnelProtocol.identityDataPassword = nil
    tunnelProtocol.proxySettings = nil
    tunnelProtocol.disconnectOnSleep = false
    tunnelProtocol.includeAllNetworks = false
    tunnelProtocol.excludeLocalNetworks = false
    tunnelProtocol.excludeCellularServices = false
    tunnelProtocol.excludeAPNs = false
    tunnelProtocol.excludeDeviceCommunication = false
    tunnelProtocol.enforceRoutes = false
    return tunnelProtocol
  }

  static func protocolSettings(
    _ tunnelProtocol: NETunnelProviderProtocol
  ) -> ManagedTunnelProtocolSettings {
    ManagedTunnelProtocolSettings(
      usernamePresent: tunnelProtocol.username != nil,
      passwordReferencePresent: tunnelProtocol.passwordReference != nil,
      identityReferencePresent: tunnelProtocol.identityReference != nil,
      identityDataPresent: tunnelProtocol.identityData != nil,
      identityDataPasswordPresent: tunnelProtocol.identityDataPassword != nil,
      proxySettingsPresent: tunnelProtocol.proxySettings != nil,
      disconnectOnSleep: tunnelProtocol.disconnectOnSleep,
      includeAllNetworks: tunnelProtocol.includeAllNetworks,
      excludeLocalNetworks: tunnelProtocol.excludeLocalNetworks,
      excludeCellularServices: tunnelProtocol.excludeCellularServices,
      excludeAPNs: tunnelProtocol.excludeAPNs,
      excludeDeviceCommunication: tunnelProtocol.excludeDeviceCommunication,
      enforceRoutes: tunnelProtocol.enforceRoutes
    )
  }

  private func managedConnectionStatus(
    _ manager: NETunnelProviderManager
  ) throws -> ManagedTunnelConnectionStatus {
    switch manager.connection.status {
    case .invalid: return .invalid
    case .disconnected: return .disconnected
    case .connecting: return .connecting
    case .connected: return .connected
    case .reasserting: return .reasserting
    case .disconnecting: return .disconnecting
    @unknown default:
      throw AppleNetworkError.cleanupUnproven(
        "NetworkExtension returned an unknown status during preference reconciliation."
      )
    }
  }
}

extension ConfigurationDescriptor {
  func providerConfiguration() throws -> [String: Any] {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let credentialSlotsData = try encoder.encode(credentialSlots)
    return [
      "schemaVersion": String(NativeProtocolConstants.schemaVersion),
      "slot": slot.rawValue,
      "installationID": installationID.uuidString.lowercased(),
      "credentialProfileID": credentialAudience.profileID.uuidString.lowercased(),
      "credentialProfileDigest": credentialAudience.profileDigest.hex,
      "epoch": String(epoch),
      "generation": String(generation),
      "byteCount": String(byteCount),
      "sha256": sha256.hex,
      "identitySha256": identitySHA256.hex,
      "credentialSlots": credentialSlotsData,
    ].merging(tunnelProviderConfiguration) { _, new in new }
  }

  private var tunnelProviderConfiguration: [String: Any] {
    guard let tunnelOptions else {
      return [:]
    }
    return [
      "ipv6Enabled": tunnelOptions.ipv6Enabled ? "true" : "false",
      "bypassPrivateNetworks": tunnelOptions.bypassPrivateNetworks ? "true" : "false",
      "directIPv4Hosts": tunnelOptions.directIPv4Hosts,
      "mtu": String(tunnelOptions.mtu),
    ]
  }
}

extension NETunnelProviderManager {
  fileprivate func configurationDescriptor() throws -> ConfigurationDescriptor {
    guard
      let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?
        .providerConfiguration,
      let schemaVersionValue = configuration["schemaVersion"] as? String,
      let schemaVersion = UInt16(schemaVersionValue),
      schemaVersion == NativeProtocolConstants.schemaVersion,
      let slotRawValue = configuration["slot"] as? String,
      let slot = ConfigurationSlot(rawValue: slotRawValue),
      slot == .tunnel,
      let tunnelOptions = try Self.decodeTunnelOptions(
        configuration,
        slot: slot
      ),
      let installationIDValue = configuration["installationID"] as? String,
      let installationID = UUID(uuidString: installationIDValue),
      installationIDValue == installationID.uuidString.lowercased(),
      let credentialProfileIDValue = configuration["credentialProfileID"] as? String,
      let credentialProfileID = UUID(uuidString: credentialProfileIDValue),
      credentialProfileIDValue == credentialProfileID.uuidString.lowercased(),
      let credentialProfileDigest = configuration["credentialProfileDigest"] as? String,
      let epochValue = configuration["epoch"] as? String,
      let epoch = UInt64(epochValue),
      let generationValue = configuration["generation"] as? String,
      let generation = UInt64(generationValue),
      let byteCountValue = configuration["byteCount"] as? String,
      let byteCount = UInt64(byteCountValue),
      let digest = configuration["sha256"] as? String,
      let identityDigest = configuration["identitySha256"] as? String,
      let credentialSlotsData = configuration["credentialSlots"] as? Data,
      let credentialSlots = try? JSONDecoder().decode(
        [CredentialSlot].self,
        from: credentialSlotsData
      )
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    let descriptor = try ConfigurationDescriptor(
      slot: slot,
      tunnelOptions: tunnelOptions,
      credentialAudience: CredentialAudience(
        profileID: credentialProfileID,
        profileDigest: try SHA256Digest(hex: credentialProfileDigest)
      ),
      installationID: installationID,
      epoch: epoch,
      generation: generation,
      byteCount: byteCount,
      sha256: SHA256Digest(hex: digest),
      identitySHA256: SHA256Digest(hex: identityDigest),
      credentialSlots: credentialSlots
    )
    guard
      NSDictionary(dictionary: configuration).isEqual(
        to: try descriptor.providerConfiguration()
      )
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    return descriptor
  }

  private static func decodeTunnelOptions(
    _ configuration: [String: Any],
    slot: ConfigurationSlot
  ) throws -> TunnelNetworkOptions? {
    guard slot == .tunnel else {
      return nil
    }
    guard let ipv6Value = configuration["ipv6Enabled"] as? String,
      let bypassPrivateNetworksValue = configuration["bypassPrivateNetworks"] as? String,
      let directIPv4Hosts = configuration["directIPv4Hosts"] as? [String],
      let mtuValue = configuration["mtu"] as? String,
      let mtu = UInt16(mtuValue)
    else {
      throw AppleNetworkError.providerResponseMismatch
    }
    let ipv6Enabled: Bool
    switch ipv6Value {
    case "true":
      ipv6Enabled = true
    case "false":
      ipv6Enabled = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    let bypassPrivateNetworks: Bool
    switch bypassPrivateNetworksValue {
    case "true":
      bypassPrivateNetworks = true
    case "false":
      bypassPrivateNetworks = false
    default:
      throw AppleNetworkError.providerResponseMismatch
    }
    return try TunnelNetworkOptions(
      ipv6Enabled: ipv6Enabled,
      bypassPrivateNetworks: bypassPrivateNetworks,
      directIPv4Hosts: directIPv4Hosts,
      mtu: mtu
    )
  }
}
