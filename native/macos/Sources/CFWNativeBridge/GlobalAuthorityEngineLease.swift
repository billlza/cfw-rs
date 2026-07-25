import CFWSharedProtocol
import Foundation

/// Machine-wide Proxy/Tunnel/multi-user engine exclusion is enforced solely through
/// the Global Authority lease. This inspector reports availability from the
/// Authority's durable machine-wide state rather than any provider-local rendezvous:
/// a fresh owner may be admitted only when the Authority proves the global Off state.
///
/// It fails closed. Any Authority unavailability, recovery, protocol incompatibility,
/// or transport error surfaces as a typed Authority error to the coordinator instead
/// of being treated as "available", so an unproven boundary can never admit a second
/// engine owner.
struct GlobalAuthorityEngineLeaseInspector: NativeEngineLeaseInspecting {
  private let authority: any AuthorityClient

  init(authority: any AuthorityClient) {
    self.authority = authority
  }

  func isAvailable() async throws -> Bool {
    let snapshot = try await authority.snapshot()
    return snapshot.state == .off
  }

  /// Projects the durable Authority snapshot into the non-secret ownership
  /// observation used for exact activation agreement. The bound lease's
  /// `Operation_Context` and configuration digests are surfaced so the coordinator
  /// can require exact lease/context/digest/owner-ready agreement before declaring
  /// an owner Active. No secrets, tickets, or credentials are exposed.
  func authorityOwnership() async throws -> AuthorityOwnershipObservation {
    let snapshot = try await authority.snapshot()
    let lease = snapshot.leaseView.map { view in
      AuthorityLeaseAgreement(
        installationID: view.operation.root.installationID.rawValue,
        epoch: view.operation.root.epoch,
        generation: view.operation.root.generation,
        ownerUID: view.operation.ownerUID,
        mode: view.operation.mode,
        configSHA256: view.operation.configSHA256,
        identitySHA256: view.operation.identitySHA256,
        leaseState: view.state
      )
    }
    return AuthorityOwnershipObservation(state: snapshot.state, lease: lease)
  }
}
