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

@Test func runtimeMaterialRejectsInvalidUUIDCredentialsBeforeInjection() throws {
  for (index, kind) in [CredentialKind.vmessUUID, .vlessUUID, .tuicUUID].enumerated() {
    let reference = CredentialReference(
      id: UUID(uuidString: "00000000-0000-4000-8000-00000000000\(index + 1)")!,
      kind: kind
    )
    #expect(throws: CredentialMaterialError.invalidSecret) {
      try CredentialMaterialEntry(reference: reference, secret: Data("not-a-uuid".utf8))
    }
    #expect(throws: CredentialMaterialError.invalidSecret) {
      try CredentialMaterialEntry(
        reference: reference,
        secret: Data("11111111-1111-4111-8111-11111111111A".utf8)
      )
    }
    _ = try CredentialMaterialEntry(
      reference: reference,
      secret: Data("11111111-1111-4111-8111-111111111111".utf8)
    )
  }
}

@Test func modernProtocolCredentialsRoundTripAndInjectIntoExactTargets() throws {
  let anytlsReference = CredentialReference(
    id: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    kind: .anytlsPassword
  )
  let tuicUUIDReference = CredentialReference(
    id: UUID(uuidString: "22222222-2222-4222-8222-222222222222")!,
    kind: .tuicUUID
  )
  let tuicPasswordReference = CredentialReference(
    id: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
    kind: .tuicPassword
  )
  let slots = [
    try CredentialSlot(
      reference: anytlsReference,
      target: .anytlsPassword,
      outboundIndex: 0,
      jsonPointer: "/outbounds/0/password"
    ),
    try CredentialSlot(
      reference: tuicUUIDReference,
      target: .tuicUUID,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/uuid"
    ),
    try CredentialSlot(
      reference: tuicPasswordReference,
      target: .tuicPassword,
      outboundIndex: 1,
      jsonPointer: "/outbounds/1/password"
    ),
  ]
  var material = try CredentialMaterial(entries: [
    CredentialMaterialEntry(
      reference: anytlsReference,
      secret: Data("anytls-secret".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicUUIDReference,
      secret: Data("44444444-4444-4444-8444-444444444444".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicPasswordReference,
      secret: Data("tuic-secret".utf8)
    ),
  ])
  let encoded = try EphemeralCredentialCodec.encode(material)
  var decoded = try EphemeralCredentialCodec.decode(encoded)
  material.erase()
  defer { decoded.erase() }

  let injected = try CredentialInjector.inject(
    template: Data(
      #"""
      {"outbounds":[{"password":"","type":"anytls"},{"password":"","type":"tuic","uuid":""}]}
      """#.utf8
    ),
    slots: slots,
    material: decoded
  )
  let root = try #require(JSONSerialization.jsonObject(with: injected) as? [String: Any])
  let outbounds = try #require(root["outbounds"] as? [[String: Any]])
  #expect(outbounds[0]["password"] as? String == "anytls-secret")
  #expect(outbounds[1]["uuid"] as? String == "44444444-4444-4444-8444-444444444444")
  #expect(outbounds[1]["password"] as? String == "tuic-secret")
}

@Test func modernProtocolCredentialInjectionFailsClosedOnIncompleteOrMismatchedState() throws {
  let anytlsReference = CredentialReference(
    id: UUID(uuidString: "11111111-1111-4111-8111-111111111111")!,
    kind: .anytlsPassword
  )
  let tuicUUIDID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
  let tuicPasswordReference = CredentialReference(
    id: UUID(uuidString: "33333333-3333-4333-8333-333333333333")!,
    kind: .tuicPassword
  )
  let anytlsSlot = try CredentialSlot(
    reference: anytlsReference,
    target: .anytlsPassword,
    outboundIndex: 0,
    jsonPointer: "/outbounds/0/password"
  )
  let tuicUUIDReference = CredentialReference(id: tuicUUIDID, kind: .tuicUUID)
  let tuicUUIDSlot = try CredentialSlot(
    reference: tuicUUIDReference,
    target: .tuicUUID,
    outboundIndex: 1,
    jsonPointer: "/outbounds/1/uuid"
  )
  let tuicPasswordSlot = try CredentialSlot(
    reference: tuicPasswordReference,
    target: .tuicPassword,
    outboundIndex: 1,
    jsonPointer: "/outbounds/1/password"
  )
  let template = Data(
    #"{"outbounds":[{"password":"","type":"anytls"},{"password":"","type":"tuic","uuid":""}]}"#.utf8
  )

  var missingTUICPassword = try CredentialMaterial(entries: [
    CredentialMaterialEntry(
      reference: anytlsReference,
      secret: Data("anytls-secret".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicUUIDReference,
      secret: Data("44444444-4444-4444-8444-444444444444".utf8)
    ),
  ])
  #expect(throws: CredentialMaterialError.missingReference(tuicPasswordReference.id)) {
    try CredentialInjector.inject(
      template: template,
      slots: [anytlsSlot, tuicUUIDSlot, tuicPasswordSlot],
      material: missingTUICPassword
    )
  }
  missingTUICPassword.erase()

  let mismatchedTUICReference = CredentialReference(id: tuicUUIDID, kind: .tuicPassword)
  var mismatchedTUICMaterial = try CredentialMaterial(entries: [
    CredentialMaterialEntry(
      reference: anytlsReference,
      secret: Data("anytls-secret".utf8)
    ),
    CredentialMaterialEntry(
      reference: mismatchedTUICReference,
      secret: Data("wrong-kind".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicPasswordReference,
      secret: Data("tuic-secret".utf8)
    ),
  ])
  #expect(throws: CredentialMaterialError.kindMismatch(tuicUUIDID)) {
    try CredentialInjector.inject(
      template: template,
      slots: [anytlsSlot, tuicUUIDSlot, tuicPasswordSlot],
      material: mismatchedTUICMaterial
    )
  }
  mismatchedTUICMaterial.erase()

  var completeMaterial = try CredentialMaterial(entries: [
    CredentialMaterialEntry(
      reference: anytlsReference,
      secret: Data("anytls-secret".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicUUIDReference,
      secret: Data("44444444-4444-4444-8444-444444444444".utf8)
    ),
    CredentialMaterialEntry(
      reference: tuicPasswordReference,
      secret: Data("tuic-secret".utf8)
    ),
  ])
  defer { completeMaterial.erase() }
  #expect(throws: CredentialMaterialError.nonEmptyPlaceholder("/outbounds/1/uuid")) {
    try CredentialInjector.inject(
      template: Data(
        #"""
        {"outbounds":[{"password":"","type":"anytls"},{"password":"","type":"tuic","uuid":"already-filled"}]}
        """#.utf8
      ),
      slots: [anytlsSlot, tuicUUIDSlot, tuicPasswordSlot],
      material: completeMaterial
    )
  }
}
