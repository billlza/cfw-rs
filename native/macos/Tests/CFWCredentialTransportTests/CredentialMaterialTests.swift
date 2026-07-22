import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Testing

@Test func emptyCredentialMaterialRoundTrips() throws {
  var decoded = try EphemeralCredentialCodec.decode(
    EphemeralCredentialCodec.encode(.empty)
  )
  #expect(decoded == .empty)
  decoded.erase()
}
