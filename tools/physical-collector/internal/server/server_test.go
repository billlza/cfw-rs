package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/config"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/contract"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/ledger"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/signing"
)

type memoryRecord struct {
	issue           ledger.Issue
	status          string
	payloadSHA256   string
	attemptID       string
	signatureSHA256 string
	failureCode     string
}

type memoryLedger struct {
	mu           sync.Mutex
	records      map[string]*memoryRecord
	commitError  error
	abandonError error
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{records: make(map[string]*memoryRecord)}
}

func (store *memoryLedger) Issue(_ context.Context, issue ledger.Issue) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[issue.Nonce]; exists {
		return ledger.ErrConflict
	}
	store.records[issue.Nonce] = &memoryRecord{issue: issue, status: ledger.StatusIssued}
	return nil
}

func (store *memoryLedger) Claim(_ context.Context, claim ledger.Claim) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[claim.Nonce]
	if !exists {
		return ledger.ErrNotFound
	}
	if record.status != ledger.StatusIssued || record.issue.Kind != claim.Kind || record.issue.IntentSHA256 != claim.IntentSHA256 {
		return ledger.ErrConflict
	}
	if !claim.ClaimedAt.Before(record.issue.ExpiresAt) {
		return ledger.ErrExpired
	}
	record.status = ledger.StatusSigning
	record.payloadSHA256 = claim.PayloadSHA256
	record.attemptID = claim.AttemptID
	return nil
}

func (store *memoryLedger) Commit(_ context.Context, completion ledger.Completion) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.commitError != nil {
		return store.commitError
	}
	record, exists := store.records[completion.Nonce]
	if !exists || record.status != ledger.StatusSigning || record.payloadSHA256 != completion.PayloadSHA256 || record.attemptID != completion.AttemptID {
		return ledger.ErrConflict
	}
	record.status = ledger.StatusCommitted
	record.signatureSHA256 = completion.SignatureSHA256
	return nil
}

func (store *memoryLedger) Abandon(_ context.Context, abandonment ledger.Abandonment) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.abandonError != nil {
		return store.abandonError
	}
	record, exists := store.records[abandonment.Nonce]
	if !exists || record.status != ledger.StatusSigning || record.payloadSHA256 != abandonment.PayloadSHA256 || record.attemptID != abandonment.AttemptID {
		return ledger.ErrConflict
	}
	record.status = ledger.StatusAbandoned
	record.failureCode = abandonment.FailureCode
	return nil
}

func (store *memoryLedger) state(nonce string) (string, string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record := store.records[nonce]
	if record == nil {
		return "", ""
	}
	return record.status, record.failureCode
}

type fakeSigner struct {
	mu        sync.Mutex
	signature []byte
	err       error
	calls     int
	messages  [][]byte
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

func (signer *fakeSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	signer.mu.Lock()
	signer.calls++
	signer.messages = append(signer.messages, append([]byte(nil), message...))
	err := signer.err
	signature := append([]byte(nil), signer.signature...)
	started := signer.started
	release := signer.release
	signer.mu.Unlock()
	if started != nil {
		signer.startOnce.Do(func() { close(started) })
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func TestProductionRoutesDefaultClosed(t *testing.T) {
	store := newMemoryLedger()
	configValue := testConfig(config.RoleNonceIssuer, false)
	service := mustService(t, configValue, store, nil)
	response := performJSON(t, service, "/v1/nonces", []byte(`not-json`))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("production-disabled route returned %d", response.Code)
	}
	if len(store.records) != 0 {
		t.Fatal("production-disabled request changed the ledger")
	}
}

func TestHealthRouteUsesCloudRunCompatiblePath(t *testing.T) {
	store := newMemoryLedger()
	service := mustService(t, testConfig(config.RoleNonceIssuer, false), store, nil)

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health route returned %d", response.Code)
	}
	if response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("health route returned unexpected body %q", response.Body.String())
	}

	legacyRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	legacyResponse := httptest.NewRecorder()
	service.ServeHTTP(legacyResponse, legacyRequest)
	if legacyResponse.Code != http.StatusNotFound {
		t.Fatalf("reserved healthz route returned %d", legacyResponse.Code)
	}
	if len(store.records) != 0 {
		t.Fatal("health checks changed the ledger")
	}
}

func TestIssueAndSignReceiptReconstructsCanonicalPayload(t *testing.T) {
	store := newMemoryLedger()
	now := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	nonceRequest, receiptRequest := testRequests()

	issuer := mustService(t, testConfig(config.RoleNonceIssuer, true), store, nil)
	issuer.now = func() time.Time { return now }
	issuer.random = bytes.NewReader(bytes.Repeat([]byte{0x11}, 32))
	nonceBody, _ := json.Marshal(nonceRequest)
	nonceResponse := performJSON(t, issuer, "/v1/nonces", nonceBody)
	if nonceResponse.Code != http.StatusCreated {
		t.Fatalf("nonce issuance returned %d: %s", nonceResponse.Code, nonceResponse.Body.String())
	}
	var issued contract.NonceResponse
	if err := json.Unmarshal(nonceResponse.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	receiptRequest.Run.RunNonce = issued.RunNonce

	fake := &fakeSigner{signature: bytes.Repeat([]byte{0x42}, 384)}
	signerService := mustService(t, testConfig(config.RoleReceiptSigner, true), store, fake)
	signerService.now = func() time.Time { return now }
	signerService.random = bytes.NewReader(bytes.Repeat([]byte{0x22}, 16))
	receiptBody, _ := json.Marshal(receiptRequest)
	receiptResponse := performJSON(t, signerService, "/v1/receipts", receiptBody)
	if receiptResponse.Code != http.StatusOK {
		t.Fatalf("receipt signing returned %d: %s", receiptResponse.Code, receiptResponse.Body.String())
	}
	if fake.calls != 1 || len(fake.messages) != 1 {
		t.Fatal("receipt did not make exactly one signer call")
	}
	var signed map[string]any
	if err := json.Unmarshal(fake.messages[0], &signed); err != nil {
		t.Fatal(err)
	}
	if signed["trust_policy_sha256"] != testConfig(config.RoleReceiptSigner, true).TrustPolicySHA256 {
		t.Fatal("signed payload did not use the server policy")
	}
	collector, ok := signed["collector"].(map[string]any)
	if !ok || collector["key_version"] != testConfig(config.RoleReceiptSigner, true).KMSKeyVersion || collector["algorithm"] != contract.SignatureAlgorithm {
		t.Fatal("signed payload did not use the fixed server collector identity")
	}
	state, _ := store.state(issued.RunNonce)
	if state != ledger.StatusCommitted {
		t.Fatalf("ledger state is %q, expected COMMITTED", state)
	}
}

func TestReceiptRejectsSelectorsDuplicateKeysAndReplay(t *testing.T) {
	store := newMemoryLedger()
	service := mustService(t, testConfig(config.RoleReceiptSigner, true), store, &fakeSigner{signature: bytes.Repeat([]byte{1}, 384)})
	service.now = func() time.Time { return time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC) }
	service.random = bytes.NewReader(bytes.Repeat([]byte{2}, 64))

	selector := []byte(`{"schema_version":1,"candidate":{},"run":{},"reports":[],"raw_artifacts":[],"key_version":"attacker","algorithm":"RS256","policy":"attacker","digest":"attacker"}`)
	response := performJSON(t, service, "/v1/receipts", selector)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("caller-selected signing material returned %d", response.Code)
	}
	duplicate := []byte(`{"schema_version":1,"schema_version":1,"candidate":{},"run":{},"reports":[],"raw_artifacts":[]}`)
	response = performJSON(t, service, "/v1/receipts", duplicate)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON key returned %d", response.Code)
	}
}

func TestAmbiguousKMSFailureBurnsNonceAndForbidsReplay(t *testing.T) {
	store, signerService, issued, receiptBody := preparedSigningRequest(t)
	fake := signerService.signer.(*fakeSigner)
	fake.err = signing.ErrAmbiguous

	first := performJSON(t, signerService, "/v1/receipts", receiptBody)
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous KMS failure returned %d", first.Code)
	}
	state, failureCode := store.state(issued.RunNonce)
	if state != ledger.StatusAbandoned || failureCode != "kms_ambiguous" {
		t.Fatalf("ambiguous KMS failure left state=%q failure=%q", state, failureCode)
	}
	second := performJSON(t, signerService, "/v1/receipts", receiptBody)
	if second.Code != http.StatusConflict {
		t.Fatalf("replay after ambiguous KMS failure returned %d", second.Code)
	}
	if fake.calls != 1 {
		t.Fatalf("automatic re-sign occurred: %d calls", fake.calls)
	}
}

func TestCommitAmbiguityBurnsNonce(t *testing.T) {
	store, signerService, issued, receiptBody := preparedSigningRequest(t)
	store.commitError = errors.New("commit outcome unknown")
	response := performJSON(t, signerService, "/v1/receipts", receiptBody)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("commit ambiguity returned %d", response.Code)
	}
	state, failureCode := store.state(issued.RunNonce)
	if state != ledger.StatusAbandoned || failureCode != "commit_ambiguous" {
		t.Fatalf("commit ambiguity left state=%q failure=%q", state, failureCode)
	}
}

func TestConcurrentReplayCannotReachSignerTwice(t *testing.T) {
	_, service, _, receiptBody := preparedSigningRequest(t)
	fake := service.signer.(*fakeSigner)
	fake.started = make(chan struct{})
	fake.release = make(chan struct{})
	service.random = rand.Reader

	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		firstResult <- performJSON(t, service, "/v1/receipts", receiptBody)
	}()
	<-fake.started
	second := performJSON(t, service, "/v1/receipts", receiptBody)
	if second.Code != http.StatusConflict {
		t.Fatalf("concurrent replay returned %d", second.Code)
	}
	close(fake.release)
	first := <-firstResult
	if first.Code != http.StatusOK {
		t.Fatalf("winning request returned %d: %s", first.Code, first.Body.String())
	}
	fake.mu.Lock()
	calls := fake.calls
	fake.mu.Unlock()
	if calls != 1 {
		t.Fatalf("concurrent replay reached signer %d times", calls)
	}
}

func TestPreflightWorksWhileProductionClosedAndSignsOnlyFixedChallenge(t *testing.T) {
	store := newMemoryLedger()
	fake := &fakeSigner{signature: bytes.Repeat([]byte{0x7a}, 384)}
	service := mustService(t, testConfig(config.RoleReceiptSigner, false), store, fake)
	service.now = func() time.Time { return time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC) }
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x33}, 48))
	request := httptest.NewRequest(http.MethodPost, "/v1/preflight", nil)
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("preflight returned %d: %s", response.Code, response.Body.String())
	}
	if fake.calls != 1 || string(fake.messages[0]) != preflightChallenge {
		t.Fatal("preflight did not sign only the fixed domain-separated challenge")
	}
	var result contract.PreflightResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.LedgerState != ledger.StatusCommitted || result.KeyVersion != service.config.KMSKeyVersion {
		t.Fatal("preflight did not commit ledger and exact key identity")
	}
}

func preparedSigningRequest(t *testing.T) (*memoryLedger, *Service, contract.NonceResponse, []byte) {
	t.Helper()
	store := newMemoryLedger()
	now := time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)
	nonceRequest, receiptRequest := testRequests()
	issuer := mustService(t, testConfig(config.RoleNonceIssuer, true), store, nil)
	issuer.now = func() time.Time { return now }
	issuer.random = bytes.NewReader(bytes.Repeat([]byte{0x44}, 32))
	body, _ := json.Marshal(nonceRequest)
	response := performJSON(t, issuer, "/v1/nonces", body)
	if response.Code != http.StatusCreated {
		t.Fatalf("prepare nonce returned %d: %s", response.Code, response.Body.String())
	}
	var issued contract.NonceResponse
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	receiptRequest.Run.RunNonce = issued.RunNonce
	receiptBody, _ := json.Marshal(receiptRequest)
	fake := &fakeSigner{signature: bytes.Repeat([]byte{0x55}, 384)}
	service := mustService(t, testConfig(config.RoleReceiptSigner, true), store, fake)
	service.now = func() time.Time { return now }
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x66}, 32))
	return store, service, issued, receiptBody
}

func testRequests() (contract.NonceRequest, contract.ReceiptRequest) {
	candidate := contract.Candidate{
		Version: contract.ProductVersion, BuildNumber: "40005",
		AppManifestSHA256: serverSHA("app"), SignedAppTreeSHA256: serverSHA("tree"),
		ArtifactHashManifestSHA256: serverSHA("artifacts"), BuiltAt: "2026-07-29T00:00:00Z",
	}
	intent := contract.RunIntent{
		OS: "macos15", MacOSVersion: "15.7.8", MacOSBuild: "24G824",
		MachineSHA256: serverSHA("machine"), CleanInstall: true, RunID: "run-40005-macos15",
	}
	receipt := contract.ReceiptRequest{
		SchemaVersion: contract.RequestSchemaVersion, Candidate: candidate,
		Run: contract.ReceiptRun{
			OS: intent.OS, MacOSVersion: intent.MacOSVersion, MacOSBuild: intent.MacOSBuild,
			MachineSHA256: intent.MachineSHA256, CleanInstall: true,
			CapturedAt: "2026-07-29T01:00:00Z", CompletedAt: "2026-07-29T03:00:00Z", RunID: intent.RunID,
		},
	}
	reportSpecs := []struct{ harness, version, kind string }{
		{"lifecycle", "lifecycle-matrix-v4", "lifecycle-report"},
		{"packet", "packet-evidence-v4", "packet-report"},
		{"performance", "performance-gates-v3", "performance-report"},
		{"adversarial", "adversarial-clients-v3", "adversarial-report"},
	}
	for index, spec := range reportSpecs {
		receipt.Reports = append(receipt.Reports, contract.ReportBinding{
			Harness: spec.harness, ToolVersion: spec.version,
			CapturedAt: "2026-07-29T01:10:00Z", CompletedAt: "2026-07-29T02:00:00Z", SignedAt: "2026-07-29T02:30:00Z",
			Descriptor: serverDescriptor(spec.kind, "reports/"+spec.harness+".json", index),
		})
	}
	lifecycleSubjects := make([]string, 0, len(contract.RequiredLifecycleSubjects()))
	for subject := range contract.RequiredLifecycleSubjects() {
		lifecycleSubjects = append(lifecycleSubjects, subject)
	}
	sort.Strings(lifecycleSubjects)
	for index, subject := range lifecycleSubjects {
		allowedKinds, ok := contract.ExpectedLifecycleArtifactKinds(subject)
		if !ok {
			panic("source-pinned lifecycle subject lacks an artifact kind")
		}
		kinds := make([]string, 0, len(allowedKinds))
		for kind := range allowedKinds {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		kind := kinds[0]
		suffix := ".json"
		if kind == "packet-pcap" {
			suffix = ".pcap"
		} else if kind == "wkwebview-rgba" {
			suffix = ".rgba"
		}
		file := strings.ReplaceAll(subject, ":", "-") + suffix
		receipt.RawArtifacts = append(receipt.RawArtifacts, contract.RawArtifactBinding{Harness: "lifecycle", Subject: subject, Descriptor: serverDescriptor(kind, "raw/lifecycle/"+file, 100+index)})
	}
	packetCases := []string{
		"tcp-ipv4", "tcp-ipv6", "udp", "quic",
		"dns-a-primary", "dns-a-secondary", "dns-aaaa-primary", "dns-aaaa-secondary",
		"lan-bypass", "included-routes", "excluded-routes", "stop-cleanup",
		"ipv6-disabled-absence",
	}
	for index, caseID := range packetCases {
		base := 200 + index*4
		receipt.RawArtifacts = append(receipt.RawArtifacts,
			contract.RawArtifactBinding{Harness: "packet", Subject: caseID, Descriptor: serverDescriptor("packet-pcap", "raw/packet/"+caseID+".pcap", base)},
			contract.RawArtifactBinding{Harness: "packet", Subject: caseID + ":product-state", Descriptor: serverDescriptor("packet-product-state-observation", "raw/packet/"+caseID+"-state.json", base+1)},
			contract.RawArtifactBinding{Harness: "packet", Subject: caseID + ":capture-provenance", Descriptor: serverDescriptor("packet-capture-provenance", "raw/packet/"+caseID+"-provenance.json", base+2)},
			contract.RawArtifactBinding{Harness: "packet", Subject: caseID + ":send-attempt", Descriptor: serverDescriptor("packet-send-attempt", "raw/packet/"+caseID+"-attempt.json", base+3)},
		)
	}
	receipt.RawArtifacts = append(receipt.RawArtifacts,
		contract.RawArtifactBinding{Harness: "performance", Subject: "sample-ledger", Descriptor: serverDescriptor("performance-sample-ledger", "raw/performance/sample-ledger.json", 300)},
		contract.RawArtifactBinding{Harness: "performance", Subject: "shaping-intent", Descriptor: serverDescriptor("performance-shaping-transaction", "raw/performance/shaping-intent.json", 301)},
		contract.RawArtifactBinding{Harness: "performance", Subject: "shaping-restoration", Descriptor: serverDescriptor("performance-shaping-transaction", "raw/performance/shaping-restoration.json", 302)},
	)
	adversarialSubjects := make([]string, 0, len(contract.RequiredAdversarialSubjects()))
	for subject := range contract.RequiredAdversarialSubjects() {
		adversarialSubjects = append(adversarialSubjects, subject)
	}
	sort.Strings(adversarialSubjects)
	for index, subject := range adversarialSubjects {
		kind, ok := contract.ExpectedAdversarialArtifactKind(subject)
		if !ok {
			panic("source-pinned adversarial subject lacks an artifact kind")
		}
		file := strings.ReplaceAll(subject, ":", "-") + ".json"
		receipt.RawArtifacts = append(receipt.RawArtifacts, contract.RawArtifactBinding{
			Harness: "adversarial", Subject: subject,
			Descriptor: serverDescriptor(kind, "raw/adversarial/"+file, 400+index),
		})
	}
	return contract.NonceRequest{SchemaVersion: contract.RequestSchemaVersion, Candidate: candidate, Run: intent}, receipt
}

func testConfig(role config.Role, enabled bool) config.Config {
	return config.Config{
		Role: role, Port: 8080, ProjectID: "cfw-release-evidence-20260730", FirestoreDatabase: "physical-release-ledger",
		KMSKeyVersion:     "projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/physical-evidence/cryptoKeys/collector-receipts/cryptoKeyVersions/1",
		TrustPolicySHA256: serverSHA("policy"), CollectorVersion: contract.CollectorVersion,
		CollectorSourceSHA256: serverSHA("source"), CollectorExecutableSHA256: serverSHA("executable"),
		ProductionReceiptsEnabled: enabled,
	}
}

func mustService(t *testing.T, configValue config.Config, store ledger.Store, signer signing.Signer) *Service {
	t.Helper()
	service, err := New(configValue, store, signer)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func performJSON(t *testing.T, service http.Handler, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	service.ServeHTTP(response, request)
	return response
}

func serverDescriptor(kind, file string, index int) contract.Descriptor {
	return contract.Descriptor{Kind: kind, Path: file, Size: int64(index + 1), SHA256: serverSHA(file)}
}

func serverSHA(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
