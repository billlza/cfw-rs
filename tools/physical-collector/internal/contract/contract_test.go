package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestDecodeExactRejectsDuplicateUnknownTrailingAndDeepJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "duplicate", body: `{"schema_version":1,"schema_version":1,"candidate":{},"run":{}}`},
		{name: "unknown", body: `{"schema_version":1,"candidate":{},"run":{},"key_version":"attacker"}`},
		{name: "trailing", body: `{"schema_version":1,"candidate":{},"run":{}} {}`},
		{name: "nonfinite", body: `{"schema_version":NaN,"candidate":{},"run":{}}`},
		{name: "wrong-number-type", body: `{"schema_version":1.0,"candidate":{},"run":{}}`},
		{name: "deep", body: strings.Repeat(`{"x":`, MaxJSONDepth+2) + `0` + strings.Repeat(`}`, MaxJSONDepth+2)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var request NonceRequest
			if err := DecodeExact([]byte(test.body), &request); err == nil {
				t.Fatalf("DecodeExact accepted %s JSON", test.name)
			}
		})
	}
}

func TestCanonicalJSONMatchesRepositoryEncoding(t *testing.T) {
	t.Parallel()
	value := map[string]any{
		"z": "<&\u2028世界",
		"a": []any{int64(3), true, nil, map[string]any{"b": "x", "a": "y"}},
	}
	encoded, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":[3,true,null,{\"a\":\"y\",\"b\":\"x\"}],\"z\":\"<&\u2028世界\"}"
	if string(encoded) != want {
		t.Fatalf("canonical JSON mismatch\n got: %q\nwant: %q", encoded, want)
	}
}

func TestBuildReceiptPayloadUsesOnlyServerBindingAndSorts(t *testing.T) {
	t.Parallel()
	request := validReceiptRequest()
	request.Reports[0], request.Reports[3] = request.Reports[3], request.Reports[0]
	request.RawArtifacts[0], request.RawArtifacts[len(request.RawArtifacts)-1] = request.RawArtifacts[len(request.RawArtifacts)-1], request.RawArtifacts[0]
	binding := testBinding()
	payload, err := BuildReceiptPayload(request, binding, mustTime(t, "2026-07-29T04:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != ReceiptSchemaVersion || payload.TrustPolicySHA256 != binding.TrustPolicySHA256 {
		t.Fatal("receipt did not inject the fixed policy")
	}
	if payload.Collector.Algorithm != SignatureAlgorithm || payload.Collector.KeyVersion != binding.KMSKeyVersion || payload.Collector.SourceSHA256 != binding.CollectorSourceSHA256 {
		t.Fatal("receipt did not inject the fixed collector identity")
	}
	for index := 1; index < len(payload.Reports); index++ {
		if payload.Reports[index-1].Harness >= payload.Reports[index].Harness {
			t.Fatal("reports are not sorted by harness")
		}
	}
	for index := 1; index < len(payload.RawArtifacts); index++ {
		previous, current := payload.RawArtifacts[index-1], payload.RawArtifacts[index]
		if previous.Harness > current.Harness || (previous.Harness == current.Harness && previous.Subject >= current.Subject) {
			t.Fatal("raw artifacts are not sorted by harness and subject")
		}
	}
}

func TestBuildReceiptPayloadRejectsAttackMutations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*ReceiptRequest)
	}{
		{name: "wrong-os-build", mutate: func(request *ReceiptRequest) { request.Run.MacOSBuild = "24G999" }},
		{name: "not-clean", mutate: func(request *ReceiptRequest) { request.Run.CleanInstall = false }},
		{name: "nonce-not-256-bit", mutate: func(request *ReceiptRequest) { request.Run.RunNonce = "0" }},
		{name: "report-tool-substitution", mutate: func(request *ReceiptRequest) { request.Reports[0].ToolVersion = "attacker-v1" }},
		{name: "path-traversal", mutate: func(request *ReceiptRequest) { request.RawArtifacts[0].Descriptor.Path = "../escape.json" }},
		{name: "digest-reuse", mutate: func(request *ReceiptRequest) {
			request.RawArtifacts[1].Descriptor.SHA256 = request.RawArtifacts[0].Descriptor.SHA256
		}},
		{name: "kind-cross-harness", mutate: func(request *ReceiptRequest) { request.RawArtifacts[0].Descriptor.Kind = "adversarial-transcript" }},
		{name: "missing-lifecycle-proof", mutate: func(request *ReceiptRequest) { request.RawArtifacts = request.RawArtifacts[1:] }},
		{name: "future-completion", mutate: func(request *ReceiptRequest) { request.Run.CompletedAt = "2026-07-29T05:00:00Z" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validReceiptRequest()
			test.mutate(&request)
			if _, err := BuildReceiptPayload(request, testBinding(), mustTime(t, "2026-07-29T04:00:00Z")); err == nil {
				t.Fatalf("accepted attack mutation %s", test.name)
			}
		})
	}
}

func validReceiptRequest() ReceiptRequest {
	candidate := Candidate{
		Version: ProductVersion, BuildNumber: "40003",
		AppManifestSHA256: testSHA("app"), SignedAppTreeSHA256: testSHA("tree"),
		ArtifactHashManifestSHA256: testSHA("artifacts"), BuiltAt: "2026-07-29T00:00:00Z",
	}
	run := ReceiptRun{
		OS: "macos15", MacOSVersion: "15.7.8", MacOSBuild: "24G824",
		MachineSHA256: testSHA("machine"), CleanInstall: true,
		CapturedAt: "2026-07-29T01:00:00Z", CompletedAt: "2026-07-29T03:00:00Z",
		RunID: "run-40003-macos15", RunNonce: testSHA("nonce"),
	}
	harnesses := []struct {
		name, version, kind string
	}{
		{"lifecycle", "lifecycle-matrix-v3", "lifecycle-report"},
		{"packet", "packet-evidence-v3", "packet-report"},
		{"performance", "performance-gates-v2", "performance-report"},
		{"adversarial", "adversarial-clients-v2", "adversarial-report"},
	}
	reports := make([]ReportBinding, 0, len(harnesses))
	for index, harness := range harnesses {
		reports = append(reports, ReportBinding{
			Harness: harness.name, ToolVersion: harness.version,
			CapturedAt: "2026-07-29T01:10:00Z", CompletedAt: "2026-07-29T02:00:00Z", SignedAt: "2026-07-29T02:30:00Z",
			Descriptor: testDescriptor(harness.kind, "reports/"+harness.name+".json", index),
		})
	}
	lifecycle := []struct{ subject, kind, file string }{
		{"renderer-ready-v2:trace", "renderer-ready-trace", "renderer.json"},
		{"network-extension-approval:trace", "network-extension-trace", "ne-approval.json"},
		{"network-extension-denial:trace", "network-extension-trace", "ne-denial.json"},
		{"network-extension-pending:trace", "network-extension-trace", "ne-pending.json"},
		{"sleep-wake:trace", "sleep-wake-trace", "sleep-wake.json"},
		{"sleep-wake:packet", "packet-pcap", "sleep-wake.pcap"},
		{"wkwebview-850x603:metadata", "wkwebview-metadata", "pixels.json"},
		{"wkwebview-850x603:pixels", "wkwebview-rgba", "pixels.rgba"},
	}
	raw := make([]RawArtifactBinding, 0, len(lifecycle)+3)
	for index, artifact := range lifecycle {
		raw = append(raw, RawArtifactBinding{
			Harness: "lifecycle", Subject: artifact.subject,
			Descriptor: testDescriptor(artifact.kind, "raw/lifecycle/"+artifact.file, 100+index),
		})
	}
	raw = append(raw,
		RawArtifactBinding{Harness: "packet", Subject: "tcp-ipv4", Descriptor: testDescriptor("packet-pcap", "raw/packet/tcp-ipv4.pcap", 200)},
		RawArtifactBinding{Harness: "performance", Subject: "measurements", Descriptor: testDescriptor("performance-samples", "raw/performance/samples.json", 201)},
		RawArtifactBinding{Harness: "adversarial", Subject: "baseline", Descriptor: testDescriptor("adversarial-transcript", "raw/adversarial/baseline.json", 202)},
	)
	return ReceiptRequest{SchemaVersion: RequestSchemaVersion, Candidate: candidate, Run: run, Reports: reports, RawArtifacts: raw}
}

func testBinding() ServerBinding {
	return ServerBinding{
		TrustPolicySHA256: testSHA("policy"), CollectorVersion: CollectorVersion,
		CollectorSourceSHA256: testSHA("source"), CollectorExecutableSHA256: testSHA("executable"),
		KMSKeyVersion: "projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/physical-evidence/cryptoKeys/collector-receipts/cryptoKeyVersions/1",
		Algorithm:     SignatureAlgorithm,
	}
}

func testDescriptor(kind, file string, index int) Descriptor {
	return Descriptor{Kind: kind, Path: file, Size: int64(index + 1), SHA256: testSHA(file)}
}

func testSHA(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
