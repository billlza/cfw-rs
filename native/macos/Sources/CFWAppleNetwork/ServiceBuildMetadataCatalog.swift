import Foundation

/// Original metadata of retained signed predecessors, used only after a strict
/// process check reports that its executable was replaced. Each candidate is
/// authenticated again by Security and pinned to its original CodeDirectory.
/// No entry grants XPC access or bypasses the strictly older-build handoff rule.
enum ServiceBuildMetadataCatalog {
  static func metadata(for service: CurrentAppService) throws -> [ServiceCodeMetadata] {
    try (service == .proxyAgent ? proxy : authority).map { try $0.decode() }
  }

  private struct Entry: Sendable {
    let cdHash: Data
    let infoPlistBase64: String

    func decode() throws -> ServiceCodeMetadata {
      let encoded = infoPlistBase64.replacingOccurrences(of: "\n", with: "")
      guard let infoPlist = Data(base64Encoded: encoded),
        !infoPlist.isEmpty, infoPlist.count <= 64 * 1024,
        let value = try PropertyListSerialization.propertyList(from: infoPlist, format: nil)
          as? [String: Any],
        let buildText = value["CFBundleVersion"] as? String
      else {
        throw CurrentAppServiceBuildError.identityUnavailable
      }
      // The version belongs to these original signed bytes. It is not a second
      // build-allocation authority, and remains untrusted until Security checks it.
      return try ServiceCodeMetadata(
        identity: .init(buildText: buildText, cdHash: cdHash), infoPlist: infoPlist)
    }
  }

  private static let proxy: [Entry] = [
    // Original Info.plist SHA-256:
    // 12eef3efb03c1dbfad4859f9040c2fb481a91840c60c52a5a5bee80f6a194bb6
    Entry(
      cdHash: Data([
        0x74, 0x4c, 0x3b, 0xf9, 0x6d, 0x3b, 0x8e, 0x46, 0xb0, 0xd3, 0x62, 0xb2, 0xe8, 0xaa, 0x85,
        0xf6, 0x22, 0x17, 0xe8, 0xc6,
      ]),
      infoPlistBase64: """
        PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8v
        QXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3Qt
        MS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+QnVpbGRNYWNoaW5lT1NCdWlsZDwv
        a2V5PgoJPHN0cmluZz4yNkIxMjM8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVEZXZlbG9wbWVudFJlZ2lvbjwva2V5
        PgoJPHN0cmluZz5lbjwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUV4ZWN1dGFibGU8L2tleT4KCTxzdHJpbmc+Q0ZX
        UHJveHlBZ2VudDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUlkZW50aWZpZXI8L2tleT4KCTxzdHJpbmc+Y29tLmJp
        bGwuY2xhc2hmb3JtYWMucHJveHktYWdlbnQ8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVJbmZvRGljdGlvbmFyeVZl
        cnNpb248L2tleT4KCTxzdHJpbmc+Ni4wPC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlTmFtZTwva2V5PgoJPHN0cmlu
        Zz5DRldQcm94eUFnZW50PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlUGFja2FnZVR5cGU8L2tleT4KCTxzdHJpbmc+
        QVBQTDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZVNob3J0VmVyc2lvblN0cmluZzwva2V5PgoJPHN0cmluZz4wLjUu
        MTwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZVN1cHBvcnRlZFBsYXRmb3Jtczwva2V5PgoJPGFycmF5PgoJCTxzdHJp
        bmc+TWFjT1NYPC9zdHJpbmc+Cgk8L2FycmF5PgoJPGtleT5DRkJ1bmRsZVZlcnNpb248L2tleT4KCTxzdHJpbmc+
        NTEwMDQ8L3N0cmluZz4KCTxrZXk+Q0ZXQXBwR3JvdXBJZGVudGlmaWVyPC9rZXk+Cgk8c3RyaW5nPllLVVBMN1o4
        NjkuZ3JvdXAuY29tLmJpbGwuY2xhc2hmb3JtYWM8L3N0cmluZz4KCTxrZXk+Q0ZXQ3JlZGVudGlhbEtleWNoYWlu
        QWNjZXNzR3JvdXA8L2tleT4KCTxzdHJpbmc+WUtVUEw3Wjg2OS5jb20uYmlsbC5jbGFzaGZvcm1hYy5jcmVkZW50
        aWFsczwvc3RyaW5nPgoJPGtleT5DRldFeHBlY3RlZEhvc3RCdW5kbGVJZGVudGlmaWVyPC9rZXk+Cgk8c3RyaW5n
        PmNvbS5iaWxsLmNsYXNoZm9ybWFjPC9zdHJpbmc+Cgk8a2V5PkNGV0V4cGVjdGVkVGVhbUlkZW50aWZpZXI8L2tl
        eT4KCTxzdHJpbmc+WUtVUEw3Wjg2OTwvc3RyaW5nPgoJPGtleT5DRldQcm94eUFnZW50TWFjaFNlcnZpY2VOYW1l
        PC9rZXk+Cgk8c3RyaW5nPmNvbS5iaWxsLmNsYXNoZm9ybWFjLnByb3h5LWFnZW50PC9zdHJpbmc+Cgk8a2V5PkNG
        V1Byb3h5Sm91cm5hbEtleWNoYWluQWNjZXNzR3JvdXA8L2tleT4KCTxzdHJpbmc+WUtVUEw3Wjg2OS5jb20uYmls
        bC5jbGFzaGZvcm1hYy5wcm94eS1hZ2VudDwvc3RyaW5nPgoJPGtleT5EVENvbXBpbGVyPC9rZXk+Cgk8c3RyaW5n
        PmNvbS5hcHBsZS5jb21waWxlcnMubGx2bS5jbGFuZy4xXzA8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybUJ1aWxk
        PC9rZXk+Cgk8c3RyaW5nPjI2QjExODwvc3RyaW5nPgoJPGtleT5EVFBsYXRmb3JtTmFtZTwva2V5PgoJPHN0cmlu
        Zz5tYWNvc3g8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybVZlcnNpb248L2tleT4KCTxzdHJpbmc+MjcuMjwvc3Ry
        aW5nPgoJPGtleT5EVFNES0J1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QjExODwvc3RyaW5nPgoJPGtleT5EVFNES05h
        bWU8L2tleT4KCTxzdHJpbmc+bWFjb3N4MjcuMjwvc3RyaW5nPgoJPGtleT5EVFhjb2RlPC9rZXk+Cgk8c3RyaW5n
        PjI3MjA8L3N0cmluZz4KCTxrZXk+RFRYY29kZUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI3QjUyPC9zdHJpbmc+Cgk8
        a2V5PkxTQmFja2dyb3VuZE9ubHk8L2tleT4KCTx0cnVlLz4KCTxrZXk+TFNNaW5pbXVtU3lzdGVtVmVyc2lvbjwv
        a2V5PgoJPHN0cmluZz4xNS4wPC9zdHJpbmc+Cgk8a2V5PkxTTXVsdGlwbGVJbnN0YW5jZXNQcm9oaWJpdGVkPC9r
        ZXk+Cgk8dHJ1ZS8+CjwvZGljdD4KPC9wbGlzdD4K
        """),
    // Original Info.plist SHA-256:
    // 6a14f77dd6a743e3bcf45c0d5f9e3ea21404080ba4327a0a96449d372780f397
    Entry(
      cdHash: Data([
        0x4e, 0x2c, 0x99, 0xd7, 0x61, 0x7d, 0x81, 0xe1, 0x99, 0x52, 0xe2, 0x97, 0xf9, 0x98, 0x65,
        0xf8, 0x33, 0xe4, 0x6c, 0x2c,
      ]),
      infoPlistBase64: """
        PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8v
        QXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3Qt
        MS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+QnVpbGRNYWNoaW5lT1NCdWlsZDwv
        a2V5PgoJPHN0cmluZz4yNkE0MzQ8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVEZXZlbG9wbWVudFJlZ2lvbjwva2V5
        PgoJPHN0cmluZz5lbjwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUV4ZWN1dGFibGU8L2tleT4KCTxzdHJpbmc+Q0ZX
        UHJveHlBZ2VudDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUlkZW50aWZpZXI8L2tleT4KCTxzdHJpbmc+Y29tLmJp
        bGwuY2xhc2hmb3JtYWMucHJveHktYWdlbnQ8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVJbmZvRGljdGlvbmFyeVZl
        cnNpb248L2tleT4KCTxzdHJpbmc+Ni4wPC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlTmFtZTwva2V5PgoJPHN0cmlu
        Zz5DRldQcm94eUFnZW50PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlUGFja2FnZVR5cGU8L2tleT4KCTxzdHJpbmc+
        QVBQTDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZVNob3J0VmVyc2lvblN0cmluZzwva2V5PgoJPHN0cmluZz4wLjUu
        MDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZVN1cHBvcnRlZFBsYXRmb3Jtczwva2V5PgoJPGFycmF5PgoJCTxzdHJp
        bmc+TWFjT1NYPC9zdHJpbmc+Cgk8L2FycmF5PgoJPGtleT5DRkJ1bmRsZVZlcnNpb248L2tleT4KCTxzdHJpbmc+
        NTAwMzA8L3N0cmluZz4KCTxrZXk+Q0ZXQXBwR3JvdXBJZGVudGlmaWVyPC9rZXk+Cgk8c3RyaW5nPllLVVBMN1o4
        NjkuZ3JvdXAuY29tLmJpbGwuY2xhc2hmb3JtYWM8L3N0cmluZz4KCTxrZXk+Q0ZXQ3JlZGVudGlhbEtleWNoYWlu
        QWNjZXNzR3JvdXA8L2tleT4KCTxzdHJpbmc+WUtVUEw3Wjg2OS5jb20uYmlsbC5jbGFzaGZvcm1hYy5jcmVkZW50
        aWFsczwvc3RyaW5nPgoJPGtleT5DRldFeHBlY3RlZEhvc3RCdW5kbGVJZGVudGlmaWVyPC9rZXk+Cgk8c3RyaW5n
        PmNvbS5iaWxsLmNsYXNoZm9ybWFjPC9zdHJpbmc+Cgk8a2V5PkNGV0V4cGVjdGVkVGVhbUlkZW50aWZpZXI8L2tl
        eT4KCTxzdHJpbmc+WUtVUEw3Wjg2OTwvc3RyaW5nPgoJPGtleT5DRldQcm94eUFnZW50TWFjaFNlcnZpY2VOYW1l
        PC9rZXk+Cgk8c3RyaW5nPmNvbS5iaWxsLmNsYXNoZm9ybWFjLnByb3h5LWFnZW50PC9zdHJpbmc+Cgk8a2V5PkNG
        V1Byb3h5Sm91cm5hbEtleWNoYWluQWNjZXNzR3JvdXA8L2tleT4KCTxzdHJpbmc+WUtVUEw3Wjg2OS5jb20uYmls
        bC5jbGFzaGZvcm1hYy5wcm94eS1hZ2VudDwvc3RyaW5nPgoJPGtleT5EVENvbXBpbGVyPC9rZXk+Cgk8c3RyaW5n
        PmNvbS5hcHBsZS5jb21waWxlcnMubGx2bS5jbGFuZy4xXzA8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybUJ1aWxk
        PC9rZXk+Cgk8c3RyaW5nPjI2QTQyNTwvc3RyaW5nPgoJPGtleT5EVFBsYXRmb3JtTmFtZTwva2V5PgoJPHN0cmlu
        Zz5tYWNvc3g8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybVZlcnNpb248L2tleT4KCTxzdHJpbmc+MjcuMDwvc3Ry
        aW5nPgoJPGtleT5EVFNES0J1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QTQyNTwvc3RyaW5nPgoJPGtleT5EVFNES05h
        bWU8L2tleT4KCTxzdHJpbmc+bWFjb3N4MjcuMDwvc3RyaW5nPgoJPGtleT5EVFhjb2RlPC9rZXk+Cgk8c3RyaW5n
        PjI3MTA8L3N0cmluZz4KCTxrZXk+RFRYY29kZUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI3QTkyNzU8L3N0cmluZz4K
        CTxrZXk+TFNCYWNrZ3JvdW5kT25seTwva2V5PgoJPHRydWUvPgoJPGtleT5MU01pbmltdW1TeXN0ZW1WZXJzaW9u
        PC9rZXk+Cgk8c3RyaW5nPjE1LjA8L3N0cmluZz4KCTxrZXk+TFNNdWx0aXBsZUluc3RhbmNlc1Byb2hpYml0ZWQ8
        L2tleT4KCTx0cnVlLz4KPC9kaWN0Pgo8L3BsaXN0Pgo=
        """),
  ]

  private static let authority: [Entry] = [
    // Original Info.plist SHA-256:
    // 4cc1e9b00a750b4b2a0e6ef2cd55b5898413a40c615094f578eb2d639d86a87c
    Entry(
      cdHash: Data([
        0x6d, 0xb4, 0xc9, 0x69, 0x7b, 0x10, 0x7d, 0x21, 0x17, 0x50, 0x19, 0xb5, 0x8b, 0x1a, 0x1b,
        0x8a, 0x1c, 0x76, 0x3e, 0x63,
      ]),
      infoPlistBase64: """
        PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8v
        QXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3Qt
        MS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+QnVpbGRNYWNoaW5lT1NCdWlsZDwv
        a2V5PgoJPHN0cmluZz4yNkIxMjM8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVEZXZlbG9wbWVudFJlZ2lvbjwva2V5
        PgoJPHN0cmluZz5lbjwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUV4ZWN1dGFibGU8L2tleT4KCTxzdHJpbmc+Q0ZX
        R2xvYmFsQXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlSWRlbnRpZmllcjwva2V5PgoJPHN0cmluZz5j
        b20uYmlsbC5jbGFzaGZvcm1hYy5nbG9iYWwtYXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlSW5mb0Rp
        Y3Rpb25hcnlWZXJzaW9uPC9rZXk+Cgk8c3RyaW5nPjYuMDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZU5hbWU8L2tl
        eT4KCTxzdHJpbmc+Q0ZXR2xvYmFsQXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlU2hvcnRWZXJzaW9u
        U3RyaW5nPC9rZXk+Cgk8c3RyaW5nPjAuNS4xPC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlU3VwcG9ydGVkUGxhdGZv
        cm1zPC9rZXk+Cgk8YXJyYXk+CgkJPHN0cmluZz5NYWNPU1g8L3N0cmluZz4KCTwvYXJyYXk+Cgk8a2V5PkNGQnVu
        ZGxlVmVyc2lvbjwva2V5PgoJPHN0cmluZz41MTAwNDwvc3RyaW5nPgoJPGtleT5EVENvbXBpbGVyPC9rZXk+Cgk8
        c3RyaW5nPmNvbS5hcHBsZS5jb21waWxlcnMubGx2bS5jbGFuZy4xXzA8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9y
        bUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QjExODwvc3RyaW5nPgoJPGtleT5EVFBsYXRmb3JtTmFtZTwva2V5PgoJ
        PHN0cmluZz5tYWNvc3g8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybVZlcnNpb248L2tleT4KCTxzdHJpbmc+Mjcu
        Mjwvc3RyaW5nPgoJPGtleT5EVFNES0J1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QjExODwvc3RyaW5nPgoJPGtleT5E
        VFNES05hbWU8L2tleT4KCTxzdHJpbmc+bWFjb3N4MjcuMjwvc3RyaW5nPgoJPGtleT5EVFhjb2RlPC9rZXk+Cgk8
        c3RyaW5nPjI3MjA8L3N0cmluZz4KCTxrZXk+RFRYY29kZUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI3QjUyPC9zdHJp
        bmc+Cgk8a2V5PkxTTWluaW11bVN5c3RlbVZlcnNpb248L2tleT4KCTxzdHJpbmc+MTUuMDwvc3RyaW5nPgo8L2Rp
        Y3Q+CjwvcGxpc3Q+Cg==
        """),
    // Original Info.plist SHA-256:
    // a686f2c89d2696d8f1fd87fa6694688b2d2a20d74afedcbd8844fff7fb6edb81
    Entry(
      cdHash: Data([
        0x8f, 0x95, 0xc6, 0xeb, 0xb3, 0x05, 0xf0, 0x10, 0xec, 0x4e, 0x1b, 0xde, 0x50, 0x93, 0x43,
        0x7d, 0x24, 0x74, 0xe1, 0x4a,
      ]),
      infoPlistBase64: """
        PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8v
        QXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3Qt
        MS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+QnVpbGRNYWNoaW5lT1NCdWlsZDwv
        a2V5PgoJPHN0cmluZz4yNkE0MzQ8L3N0cmluZz4KCTxrZXk+Q0ZCdW5kbGVEZXZlbG9wbWVudFJlZ2lvbjwva2V5
        PgoJPHN0cmluZz5lbjwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZUV4ZWN1dGFibGU8L2tleT4KCTxzdHJpbmc+Q0ZX
        R2xvYmFsQXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlSWRlbnRpZmllcjwva2V5PgoJPHN0cmluZz5j
        b20uYmlsbC5jbGFzaGZvcm1hYy5nbG9iYWwtYXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlSW5mb0Rp
        Y3Rpb25hcnlWZXJzaW9uPC9rZXk+Cgk8c3RyaW5nPjYuMDwvc3RyaW5nPgoJPGtleT5DRkJ1bmRsZU5hbWU8L2tl
        eT4KCTxzdHJpbmc+Q0ZXR2xvYmFsQXV0aG9yaXR5PC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlU2hvcnRWZXJzaW9u
        U3RyaW5nPC9rZXk+Cgk8c3RyaW5nPjAuNS4wPC9zdHJpbmc+Cgk8a2V5PkNGQnVuZGxlU3VwcG9ydGVkUGxhdGZv
        cm1zPC9rZXk+Cgk8YXJyYXk+CgkJPHN0cmluZz5NYWNPU1g8L3N0cmluZz4KCTwvYXJyYXk+Cgk8a2V5PkNGQnVu
        ZGxlVmVyc2lvbjwva2V5PgoJPHN0cmluZz41MDAzMDwvc3RyaW5nPgoJPGtleT5EVENvbXBpbGVyPC9rZXk+Cgk8
        c3RyaW5nPmNvbS5hcHBsZS5jb21waWxlcnMubGx2bS5jbGFuZy4xXzA8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9y
        bUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QTQyNTwvc3RyaW5nPgoJPGtleT5EVFBsYXRmb3JtTmFtZTwva2V5PgoJ
        PHN0cmluZz5tYWNvc3g8L3N0cmluZz4KCTxrZXk+RFRQbGF0Zm9ybVZlcnNpb248L2tleT4KCTxzdHJpbmc+Mjcu
        MDwvc3RyaW5nPgoJPGtleT5EVFNES0J1aWxkPC9rZXk+Cgk8c3RyaW5nPjI2QTQyNTwvc3RyaW5nPgoJPGtleT5E
        VFNES05hbWU8L2tleT4KCTxzdHJpbmc+bWFjb3N4MjcuMDwvc3RyaW5nPgoJPGtleT5EVFhjb2RlPC9rZXk+Cgk8
        c3RyaW5nPjI3MTA8L3N0cmluZz4KCTxrZXk+RFRYY29kZUJ1aWxkPC9rZXk+Cgk8c3RyaW5nPjI3QTkyNzU8L3N0
        cmluZz4KCTxrZXk+TFNNaW5pbXVtU3lzdGVtVmVyc2lvbjwva2V5PgoJPHN0cmluZz4xNS4wPC9zdHJpbmc+Cjwv
        ZGljdD4KPC9wbGlzdD4K
        """),
  ]

}
