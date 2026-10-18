/// `^[a-z][a-z0-9-]{0,31}$`, compared as scalars so no combining sequence
/// or lookalike can stand in for an identifier the host knows. Every frame
/// family names its parts with these.
func isFrameIdentifier(_ text: String) -> Bool {
  let scalars = text.unicodeScalars
  guard let first = scalars.first, scalars.count <= 32, ("a"..."z").contains(first) else {
    return false
  }
  return scalars.allSatisfy {
    ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-"
  }
}
