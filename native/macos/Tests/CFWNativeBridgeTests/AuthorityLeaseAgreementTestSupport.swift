import Foundation

@testable import CFWAppleNetwork
@testable import CFWNativeBridge
@testable import CFWSharedProtocol

/// The Global Authority's lease agreement for a descriptor: its installation,
/// epoch, generation and digests, unless a test overrides one of them.
func agreement(
  for descriptor: ConfigurationDescriptor,
  mode: AuthorityMode,
  leaseState: AuthorityLeaseState = .active,
  epoch: UInt64? = nil,
  generation: UInt64? = nil,
  installationID: UUID? = nil,
  configSHA256: CFWSharedProtocol.SHA256Digest? = nil,
  identitySHA256: CFWSharedProtocol.SHA256Digest? = nil
) -> AuthorityLeaseAgreement {
  AuthorityLeaseAgreement(
    installationID: installationID ?? descriptor.installationID,
    epoch: epoch ?? descriptor.epoch,
    generation: generation ?? descriptor.generation,
    ownerUID: 501,
    mode: mode,
    configSHA256: configSHA256 ?? descriptor.sha256,
    identitySHA256: identitySHA256 ?? descriptor.identitySHA256,
    leaseState: leaseState
  )
}
