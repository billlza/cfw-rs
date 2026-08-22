import CFWLibboxRuntime
import Foundation
import Testing

private func systemProxyConfiguration(
  mixedPort: UInt16 = 7891,
  controllerPort: UInt16 = 9091
) -> Data {
  Data(
    """
    {
      "experimental": {
        "clash_api": {
          "external_controller": "127.0.0.1:\(controllerPort)",
          "secret": "runtime-secret"
        }
      },
      "inbounds": [
        {
          "type": "mixed",
          "tag": "cfw-system-proxy",
          "listen": "127.0.0.1",
          "listen_port": \(mixedPort)
        }
      ]
    }
    """.utf8
  )
}

private func packetTunnelConfiguration(controllerPort: UInt16 = 9091) -> Data {
  Data(
    """
    {
      "experimental": {
        "clash_api": {
          "external_controller": "127.0.0.1:\(controllerPort)",
          "secret": "runtime-secret"
        }
      },
      "inbounds": []
    }
    """.utf8
  )
}

@Test func startReceiptBindsTheExactApplicationOwnedEndpoints() throws {
  let receipt = try LibboxRuntimeStartReceipt.parse(
    configuration: systemProxyConfiguration(),
    role: .systemProxy
  )

  #expect(receipt.mixedListener?.host == "127.0.0.1")
  #expect(receipt.mixedListener?.port == 7891)
  #expect(receipt.controllerListener.host == "127.0.0.1")
  #expect(receipt.controllerListener.port == 9091)
}

@Test func startReceiptRejectsAControllerCollision() {
  #expect(throws: LibboxRuntimeError.invalidRuntimeEndpoints) {
    try LibboxRuntimeStartReceipt.parse(
      configuration: systemProxyConfiguration(mixedPort: 7891, controllerPort: 7891),
      role: .systemProxy
    )
  }
}

@Test func startReceiptRejectsAForeignListener() {
  let configuration = Data(
    """
    {
      "experimental": {
        "clash_api": {
          "external_controller": "0.0.0.0:9091",
          "secret": "runtime-secret"
        }
      },
      "inbounds": [
        {
          "type": "mixed",
          "tag": "cfw-system-proxy",
          "listen": "127.0.0.1",
          "listen_port": 7891
        }
      ]
    }
    """.utf8
  )

  #expect(throws: LibboxRuntimeError.invalidRuntimeEndpoints) {
    try LibboxRuntimeStartReceipt.parse(configuration: configuration, role: .systemProxy)
  }
}

@Test func endpointConflictRequiresTheExactRolePortAndRuntime() throws {
  let proxyReceipt = try LibboxRuntimeStartReceipt.parse(
    configuration: systemProxyConfiguration(mixedPort: 7892, controllerPort: 9092),
    role: .systemProxy
  )
  let tunnelReceipt = try LibboxRuntimeStartReceipt.parse(
    configuration: packetTunnelConfiguration(controllerPort: 9093),
    role: .packetTunnel
  )

  let mixedConflict = try LibboxRuntimeEndpointConflict.validated(
    kind: 1,
    port: 7892,
    mixedKind: 1,
    controllerKind: 2,
    receipt: proxyReceipt,
    runtimeRole: .systemProxy
  )
  #expect(mixedConflict.role == .mixed)
  #expect(mixedConflict.port == 7892)

  let controllerConflict = try LibboxRuntimeEndpointConflict.validated(
    kind: 2,
    port: 9093,
    mixedKind: 1,
    controllerKind: 2,
    receipt: tunnelReceipt,
    runtimeRole: .packetTunnel
  )
  #expect(controllerConflict.role == .controller)
  #expect(controllerConflict.port == 9093)
}

@Test func endpointConflictRejectsEveryMismatchedReport() throws {
  let receipt = try LibboxRuntimeStartReceipt.parse(
    configuration: packetTunnelConfiguration(controllerPort: 9093),
    role: .packetTunnel
  )
  let invalidReports: [(Int32, Int32, Int32, Int32)] = [
    (1, 9093, 1, 2),
    (2, 9092, 1, 2),
    (2, 0, 1, 2),
    (3, 9093, 1, 2),
    (1, 9093, 1, 1),
  ]
  for (kind, port, mixedKind, controllerKind) in invalidReports {
    #expect(throws: LibboxRuntimeError.invalidEndpointConflict(kind: kind, port: port)) {
      try LibboxRuntimeEndpointConflict.validated(
        kind: kind,
        port: port,
        mixedKind: mixedKind,
        controllerKind: controllerKind,
        receipt: receipt,
        runtimeRole: .packetTunnel
      )
    }
  }
}
