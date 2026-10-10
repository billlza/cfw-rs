import Testing

@testable import CFWLibboxRuntime

@Test func processLookupUsesOnlyConfiguredNamesAndPaths() throws {
  let policy = try LibboxProcessLookupPolicy.parse([
    "route": [
      "rules": [
        ["process_name": "curl"],
        [
          "type": "logical",
          "rules": [
            [
              "process_name": ["Example", "curl"],
              "process_path": "/Applications/Example.app/Contents/MacOS/Example",
            ]
          ],
        ],
        ["domain_suffix": "example.com"],
      ]
    ]
  ])
  #expect(policy.names == ["Example", "curl"])
  #expect(policy.paths == ["/Applications/Example.app/Contents/MacOS/Example"])
  #expect(try LibboxProcessLookupPolicy.parse([:]).names.isEmpty)
}

@Test func processLookupRejectsMalformedAndUnboundedPolicy() {
  for rules: Any in [
    ["not a rule"],
    [["process_name": 4]],
    [["process_name": ""]],
    [["process_name": "bad\nname"]],
    [["process_path": String(repeating: "x", count: 2_049)]],
    Array(repeating: ["process_name": "curl"], count: 32_769),
  ] {
    #expect(throws: LibboxProcessLookupPolicyError.invalidRuleShape) {
      try LibboxProcessLookupPolicy.parse(["route": ["rules": rules]])
    }
  }
  var rules: [[String: Any]] = [["process_name": "curl"]]
  for _ in 0..<9 { rules = [["rules": rules]] }
  #expect(throws: LibboxProcessLookupPolicyError.invalidRuleShape) {
    try LibboxProcessLookupPolicy.parse(["route": ["rules": rules]])
  }
}
