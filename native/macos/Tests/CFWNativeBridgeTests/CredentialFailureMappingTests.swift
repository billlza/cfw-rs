import CFWCredentialVault
import Testing

@testable import CFWNativeBridge

@Test func credentialVaultCorruptionUsesDedicatedFailureCode() {
  let failure = NativeBridgeCoordinator.map(CredentialVaultError.corrupt).responseFailure

  #expect(failure.code == .credentialVaultCorrupt)
  #expect(failure.message == "The credential vault data is corrupt.")
}

@Test func credentialAccessGroupRejectionDoesNotClaimCorruptVaultData() {
  let failure = NativeBridgeCoordinator.map(CredentialVaultError.invalidAccessGroup).responseFailure

  #expect(failure.code == .identityRejected)
  #expect(failure.message == "The native peer identity was rejected.")
}
