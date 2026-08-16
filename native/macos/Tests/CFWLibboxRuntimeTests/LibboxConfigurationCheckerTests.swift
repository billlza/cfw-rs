import CFWLibboxRuntime
import Foundation
import Testing

#if canImport(Libbox)
  @Test func pinnedLibboxAcceptsProjectedLegacyVMessSelectorShape() throws {
    let configuration = Data(
      #"""
      {
        "log": { "level": "error" },
        "outbounds": [
          {
            "type": "vmess",
            "tag": "legacy-vmess-primary",
            "server": "1.1.1.1",
            "server_port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "security": "auto",
            "alter_id": 1
          },
          {
            "type": "vmess",
            "tag": "legacy-vmess-secondary",
            "server": "8.8.8.8",
            "server_port": 443,
            "uuid": "22222222-2222-4222-8222-222222222222",
            "security": "auto"
          },
          {
            "type": "selector",
            "tag": "cfw-proxy-selector",
            "outbounds": ["legacy-vmess-primary", "legacy-vmess-secondary"],
            "default": "legacy-vmess-primary",
            "interrupt_exist_connections": false
          }
        ],
        "route": { "final": "cfw-proxy-selector" }
      }
      """#.utf8
    )

    try SourceBuiltLibboxConfigurationChecker().check(configuration: configuration)
  }
#endif
