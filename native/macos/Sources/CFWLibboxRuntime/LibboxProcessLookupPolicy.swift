import Foundation

enum LibboxProcessLookupPolicyError: Error, Equatable {
  case invalidRuleShape
}

/// The only process identities needed to evaluate the validated routing rules.
/// Limiting public libproc scans to these identities avoids inspecting every
/// descriptor of unrelated applications on each new connection.
struct LibboxProcessLookupPolicy: Equatable, Sendable {
  let names: [String]
  let paths: [String]

  static func parse(_ root: [String: Any]) throws -> Self {
    guard let routeValue = root["route"] else { return Self(names: [], paths: []) }
    guard let route = routeValue as? [String: Any] else {
      throw LibboxProcessLookupPolicyError.invalidRuleShape
    }
    guard let rules = route["rules"] else { return Self(names: [], paths: []) }
    var names = Set<String>()
    var paths = Set<String>()
    var remaining = 32_768
    try collect(rules, depth: 0, remaining: &remaining, names: &names, paths: &paths)
    return Self(names: names.sorted(), paths: paths.sorted())
  }

  private static func collect(
    _ value: Any, depth: Int, remaining: inout Int,
    names: inout Set<String>, paths: inout Set<String>
  ) throws {
    guard depth <= 8, let rules = value as? [[String: Any]], rules.count <= remaining else {
      throw LibboxProcessLookupPolicyError.invalidRuleShape
    }
    remaining -= rules.count
    for rule in rules {
      if let value = rule["process_name"] { names.formUnion(try strings(value)) }
      if let value = rule["process_path"] { paths.formUnion(try strings(value)) }
      if let nested = rule["rules"] {
        try collect(nested, depth: depth + 1, remaining: &remaining, names: &names, paths: &paths)
      }
    }
  }

  private static func strings(_ value: Any) throws -> [String] {
    let values: [String]
    if let single = value as? String {
      values = [single]
    } else if let list = value as? [String] {
      values = list
    } else {
      throw LibboxProcessLookupPolicyError.invalidRuleShape
    }
    guard
      values.allSatisfy({
        !$0.isEmpty && $0.utf8.count <= 2_048
          && !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
      })
    else {
      throw LibboxProcessLookupPolicyError.invalidRuleShape
    }
    return values
  }
}
