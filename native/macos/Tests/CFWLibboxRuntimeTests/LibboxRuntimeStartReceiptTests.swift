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
