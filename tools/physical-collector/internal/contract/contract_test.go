package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
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

func TestBuildReceiptPayloadIncludesIdentityObservationSubjects(t *testing.T) {
	t.Parallel()
	request := validReceiptRequest()
	probes := []string{
		"inside-out-signatures",
		"team-id",
		"bundle-identifiers",
		"entitlements",
		"provisioning",
	}
	payload, err := BuildReceiptPayload(
		request,
		testBinding(),
		mustTime(t, "2026-07-29T04:00:00Z"),
	)
	if err != nil {
		t.Fatalf("identity observation subjects were rejected: %v", err)
	}
	seen := make(map[string]bool)
	for _, artifact := range payload.RawArtifacts {
		seen[artifact.Subject] = true
	}
	for _, probe := range probes {
		if !seen[probe+":observation"] {
			t.Fatalf("receipt omitted identity observation subject %q", probe)
		}
	}
}

func TestLifecycleV4RequiresExactSeventyTwoSubjectClosure(t *testing.T) {
	t.Parallel()
	request := validReceiptRequest()
	seen := make(map[string]string)
	for _, artifact := range request.RawArtifacts {
		if artifact.Harness == "lifecycle" {
			seen[artifact.Subject] = artifact.Descriptor.Kind
		}
	}
	if len(seen) != 72 {
		t.Fatalf("lifecycle raw closure has %d subjects, want 72", len(seen))
	}
	for _, probeID := range lifecycleProbeIDs {
		if seen[probeID] != "lifecycle-event" {
			t.Fatalf("probe %q lacks its proof-bound lifecycle event", probeID)
		}
		if seen[probeID+":observation"] != "lifecycle-observation" {
			t.Fatalf("probe %q lacks its proof-free lifecycle observation", probeID)
		}
	}
}

func TestReceiptArtifactCountAccepts269And271ButRejects272(t *testing.T) {
	t.Parallel()
	required := validReceiptRequest()
	if got := len(required.Reports) + len(required.RawArtifacts); got != 269 {
		t.Fatalf("required receipt has %d descriptors, want 269", got)
	}
	if _, err := BuildReceiptPayload(required, testBinding(), mustTime(t, "2026-07-29T04:00:00Z")); err != nil {
		t.Fatalf("required 269-descriptor receipt was rejected: %v", err)
	}
	maximum := validReceiptRequest()
	for index, subject := range []string{
		"stop-cleanup:restore-state",
		"ipv6-disabled-absence:restore-state",
	} {
		maximum.RawArtifacts = append(maximum.RawArtifacts, RawArtifactBinding{
			Harness: "packet",
			Subject: subject,
			Descriptor: testDescriptor(
				"packet-product-state-observation",
				"raw/packet/"+strings.ReplaceAll(subject, ":", "-")+".json",
				900+index,
			),
		})
	}
	if got := len(maximum.Reports) + len(maximum.RawArtifacts); got != MaxArtifactCount {
		t.Fatalf("maximal receipt has %d descriptors, want %d", got, MaxArtifactCount)
	}
	if _, err := BuildReceiptPayload(maximum, testBinding(), mustTime(t, "2026-07-29T04:00:00Z")); err != nil {
		t.Fatalf("maximal 271-descriptor receipt was rejected: %v", err)
	}
	oneTooMany := maximum
	oneTooMany.RawArtifacts = append(append([]RawArtifactBinding(nil), maximum.RawArtifacts...), RawArtifactBinding{
		Harness: "packet",
		Subject: "not-source-pinned",
		Descriptor: testDescriptor(
			"packet-product-state-observation",
			"raw/packet/not-source-pinned.json",
			999,
		),
	})
	if got := len(oneTooMany.Reports) + len(oneTooMany.RawArtifacts); got != 272 {
		t.Fatalf("overflow receipt has %d descriptors, want 272", got)
	}
	if _, err := BuildReceiptPayload(oneTooMany, testBinding(), mustTime(t, "2026-07-29T04:00:00Z")); err == nil || !strings.Contains(err.Error(), "exceeds 271") {
		t.Fatalf("272-descriptor receipt did not fail at the exact bound: %v", err)
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
		{name: "retired-lifecycle-v3", mutate: func(request *ReceiptRequest) {
			for index, report := range request.Reports {
				if report.Harness == "lifecycle" {
					request.Reports[index].ToolVersion = "lifecycle-matrix-v3"
					return
				}
			}
		}},
		{name: "path-traversal", mutate: func(request *ReceiptRequest) { request.RawArtifacts[0].Descriptor.Path = "../escape.json" }},
		{name: "digest-reuse", mutate: func(request *ReceiptRequest) {
			request.RawArtifacts[1].Descriptor.SHA256 = request.RawArtifacts[0].Descriptor.SHA256
		}},
		{name: "kind-cross-harness", mutate: func(request *ReceiptRequest) { request.RawArtifacts[0].Descriptor.Kind = "adversarial-transcript" }},
		{name: "wrong-lifecycle-kind", mutate: func(request *ReceiptRequest) { request.RawArtifacts[0].Descriptor.Kind = "network-extension-trace" }},
		{name: "missing-lifecycle-proof", mutate: func(request *ReceiptRequest) { request.RawArtifacts = request.RawArtifacts[1:] }},
		{name: "lifecycle-observation-relabeled-as-event", mutate: func(request *ReceiptRequest) {
			for index, artifact := range request.RawArtifacts {
				if artifact.Harness == "lifecycle" && artifact.Subject == "team-id:observation" {
					request.RawArtifacts[index].Descriptor.Kind = "lifecycle-event"
					return
				}
			}
		}},
		{name: "missing-lifecycle-observation", mutate: func(request *ReceiptRequest) {
			for index, artifact := range request.RawArtifacts {
				if artifact.Harness == "lifecycle" && artifact.Subject == "login:observation" {
					request.RawArtifacts = append(request.RawArtifacts[:index], request.RawArtifacts[index+1:]...)
					return
				}
			}
		}},
		{name: "unknown-lifecycle-subject", mutate: func(request *ReceiptRequest) {
			request.RawArtifacts = append(request.RawArtifacts, RawArtifactBinding{
				Harness: "lifecycle", Subject: "invented-success",
				Descriptor: testDescriptor("lifecycle-event", "raw/lifecycle/invented-success.json", 999),
			})
		}},
		{name: "missing-adversarial-precondition", mutate: func(request *ReceiptRequest) {
			for index, artifact := range request.RawArtifacts {
				if artifact.Harness == "adversarial" && artifact.Subject == "observation:wrong-team-id" {
					request.RawArtifacts = append(request.RawArtifacts[:index], request.RawArtifacts[index+1:]...)
					return
				}
			}
		}},
		{name: "adversarial-subject-kind-mismatch", mutate: func(request *ReceiptRequest) {
			for index, artifact := range request.RawArtifacts {
				if artifact.Harness == "adversarial" && artifact.Subject == "observation:wrong-team-id" {
					request.RawArtifacts[index].Descriptor.Kind = "adversarial-transcript"
					return
				}
			}
		}},
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
		Version: ProductVersion, BuildNumber: "40005",
		AppManifestSHA256: testSHA("app"), SignedAppTreeSHA256: testSHA("tree"),
		ArtifactHashManifestSHA256: testSHA("artifacts"), BuiltAt: "2026-07-29T00:00:00Z",
	}
	run := ReceiptRun{
		OS: "macos15", MacOSVersion: "15.7.8", MacOSBuild: "24G824",
		MachineSHA256: testSHA("machine"), CleanInstall: true,
		CapturedAt: "2026-07-29T01:00:00Z", CompletedAt: "2026-07-29T03:00:00Z",
		RunID: "run-40005-macos15", RunNonce: testSHA("nonce"),
	}
	harnesses := []struct {
		name, version, kind string
	}{
		{"lifecycle", "lifecycle-matrix-v4", "lifecycle-report"},
		{"packet", "packet-evidence-v4", "packet-report"},
		{"performance", "performance-gates-v3", "performance-report"},
		{"adversarial", "adversarial-clients-v3", "adversarial-report"},
	}
	reports := make([]ReportBinding, 0, len(harnesses))
	for index, harness := range harnesses {
		reports = append(reports, ReportBinding{
			Harness: harness.name, ToolVersion: harness.version,
			CapturedAt: "2026-07-29T01:10:00Z", CompletedAt: "2026-07-29T02:00:00Z", SignedAt: "2026-07-29T02:30:00Z",
			Descriptor: testDescriptor(harness.kind, "reports/"+harness.name+".json", index),
		})
	}
	lifecycleSubjects := make([]string, 0, len(requiredLifecycleSubjects))
	for subject := range requiredLifecycleSubjects {
		lifecycleSubjects = append(lifecycleSubjects, subject)
	}
	sort.Strings(lifecycleSubjects)
	raw := make([]RawArtifactBinding, 0, len(lifecycleSubjects)+3)
	for index, subject := range lifecycleSubjects {
		allowedKinds, ok := expectedLifecycleKinds(subject)
		if !ok {
			panic("source-pinned lifecycle subject has no artifact kind: " + subject)
		}
		kinds := make([]string, 0, len(allowedKinds))
		for kind := range allowedKinds {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		kind := kinds[0]
		file := strings.ReplaceAll(subject, ":", "-") + artifactKinds[kind].suffix
		raw = append(raw, RawArtifactBinding{
			Harness: "lifecycle", Subject: subject,
			Descriptor: testDescriptor(kind, "raw/lifecycle/"+file, 100+index),
		})
	}
	for index, caseID := range packetCaseIDs {
		base := 200 + index*4
		raw = append(raw,
			RawArtifactBinding{Harness: "packet", Subject: caseID, Descriptor: testDescriptor("packet-pcap", "raw/packet/"+caseID+".pcap", base)},
			RawArtifactBinding{Harness: "packet", Subject: caseID + ":product-state", Descriptor: testDescriptor("packet-product-state-observation", "raw/packet/"+caseID+"-state.json", base+1)},
			RawArtifactBinding{Harness: "packet", Subject: caseID + ":capture-provenance", Descriptor: testDescriptor("packet-capture-provenance", "raw/packet/"+caseID+"-provenance.json", base+2)},
			RawArtifactBinding{Harness: "packet", Subject: caseID + ":send-attempt", Descriptor: testDescriptor("packet-send-attempt", "raw/packet/"+caseID+"-attempt.json", base+3)},
		)
	}
	raw = append(raw,
		RawArtifactBinding{Harness: "performance", Subject: "sample-ledger", Descriptor: testDescriptor("performance-sample-ledger", "raw/performance/sample-ledger.json", 300)},
		RawArtifactBinding{Harness: "performance", Subject: "shaping-intent", Descriptor: testDescriptor("performance-shaping-transaction", "raw/performance/shaping-intent.json", 301)},
		RawArtifactBinding{Harness: "performance", Subject: "shaping-restoration", Descriptor: testDescriptor("performance-shaping-transaction", "raw/performance/shaping-restoration.json", 302)},
	)
	adversarialSubjects := make([]string, 0, len(RequiredAdversarialSubjects()))
	for subject := range RequiredAdversarialSubjects() {
		adversarialSubjects = append(adversarialSubjects, subject)
	}
	sort.Strings(adversarialSubjects)
	for index, subject := range adversarialSubjects {
		kind, ok := ExpectedAdversarialArtifactKind(subject)
		if !ok {
			panic("source-pinned adversarial subject has no artifact kind: " + subject)
		}
		file := strings.ReplaceAll(subject, ":", "-") + ".json"
		raw = append(raw, RawArtifactBinding{
			Harness: "adversarial", Subject: subject,
			Descriptor: testDescriptor(kind, "raw/adversarial/"+file, 400+index),
		})
	}
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
