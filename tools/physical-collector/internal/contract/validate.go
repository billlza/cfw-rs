package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	sha256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identifierPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	pathComponentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	buildPattern         = regexp.MustCompile(`^[1-9][0-9]*$`)
)

var requiredOS = map[string]struct {
	version string
	build   string
}{
	"macos15":       {version: "15.7.8", build: "24G824"},
	"current-macos": {version: "26.6", build: "25G72"},
}

var expectedHarnessVersions = map[string]string{
	"lifecycle":   "lifecycle-matrix-v4",
	"packet":      "packet-evidence-v4",
	"performance": "performance-gates-v3",
	"adversarial": "adversarial-clients-v3",
}

var reportKinds = map[string]string{
	"lifecycle":   "lifecycle-report",
	"packet":      "packet-report",
	"performance": "performance-report",
	"adversarial": "adversarial-report",
}

type artifactKind struct {
	suffix  string
	maximum int64
	report  bool
}

var artifactKinds = map[string]artifactKind{
	"packet-report":                     {suffix: ".json", maximum: 1 << 20, report: true},
	"lifecycle-report":                  {suffix: ".json", maximum: 1 << 20, report: true},
	"performance-report":                {suffix: ".json", maximum: 1 << 20, report: true},
	"adversarial-report":                {suffix: ".json", maximum: 1 << 20, report: true},
	"packet-pcap":                       {suffix: ".pcap", maximum: 32 << 20},
	"packet-pcapng":                     {suffix: ".pcapng", maximum: 32 << 20},
	"packet-product-state-observation":  {suffix: ".json", maximum: 1 << 20},
	"packet-capture-provenance":         {suffix: ".json", maximum: 256 << 10},
	"packet-send-attempt":               {suffix: ".json", maximum: 256 << 10},
	"lifecycle-observation":             {suffix: ".json", maximum: 1 << 20},
	"lifecycle-event":                   {suffix: ".json", maximum: 1 << 20},
	"renderer-ready-trace":              {suffix: ".json", maximum: 1 << 20},
	"network-extension-trace":           {suffix: ".json", maximum: 1 << 20},
	"sleep-wake-trace":                  {suffix: ".json", maximum: 1 << 20},
	"wkwebview-metadata":                {suffix: ".json", maximum: 256 << 10},
	"wkwebview-rgba":                    {suffix: ".rgba", maximum: 16 << 20},
	"performance-sample-ledger":         {suffix: ".json", maximum: 64 << 20},
	"performance-shaping-transaction":   {suffix: ".json", maximum: 16 << 20},
	"adversarial-case-observation":      {suffix: ".json", maximum: 1 << 20},
	"adversarial-secret-coverage":       {suffix: ".json", maximum: 1 << 20},
	"adversarial-signature-observation": {suffix: ".json", maximum: 256 << 10},
	"adversarial-transcript":            {suffix: ".json", maximum: 1 << 20},
}

var rawKindsByHarness = map[string]map[string]struct{}{
	"lifecycle": setOf(
		"lifecycle-observation", "lifecycle-event", "renderer-ready-trace", "network-extension-trace",
		"sleep-wake-trace", "packet-pcap", "wkwebview-metadata", "wkwebview-rgba",
	),
	"packet": setOf(
		"packet-pcap", "packet-pcapng", "packet-product-state-observation",
		"packet-capture-provenance", "packet-send-attempt",
	),
	"performance": setOf(
		"performance-sample-ledger", "performance-shaping-transaction",
	),
	"adversarial": setOf(
		"adversarial-case-observation", "adversarial-secret-coverage",
		"adversarial-signature-observation", "adversarial-transcript",
	),
}

var lifecycleProbeIDs = []string{
	"inside-out-signatures",
	"team-id",
	"bundle-identifiers",
	"entitlements",
	"provisioning",
	"daemon-registration-approval",
	"daemon-registration-denial",
	"system-extension-approval",
	"system-extension-pending",
	"system-extension-restart",
	"network-extension-approval",
	"network-extension-denial",
	"network-extension-pending",
	"renderer-ready-v2",
	"upgrade",
	"replacement",
	"downgrade-refusal",
	"install-cleanup",
	"uninstall-cleanup",
	"login",
	"logout",
	"lock",
	"fast-user-switching",
	"concurrent-starts",
	"cancellation",
	"sleep-wake",
	"wkwebview-850x603",
	"reboot-recovery",
	"host-crash",
	"global-authority-crash",
	"proxy-agent-crash",
	"provider-crash",
}

var lifecycleSpecialSubjects = setOf(
	"renderer-ready-v2:trace",
	"network-extension-approval:trace",
	"network-extension-denial:trace",
	"network-extension-pending:trace",
	"sleep-wake:trace",
	"sleep-wake:packet",
	"wkwebview-850x603:metadata",
	"wkwebview-850x603:pixels",
)

func makeRequiredLifecycleSubjects() map[string]struct{} {
	result := make(map[string]struct{}, len(lifecycleProbeIDs)*2+len(lifecycleSpecialSubjects))
	for _, probeID := range lifecycleProbeIDs {
		result[probeID] = struct{}{}
		result[probeID+":observation"] = struct{}{}
	}
	for subject := range lifecycleSpecialSubjects {
		result[subject] = struct{}{}
	}
	return result
}

var requiredLifecycleSubjects = makeRequiredLifecycleSubjects()

func RequiredLifecycleSubjects() map[string]struct{} {
	result := make(map[string]struct{}, len(requiredLifecycleSubjects))
	for subject := range requiredLifecycleSubjects {
		result[subject] = struct{}{}
	}
	return result
}

func ExpectedLifecycleArtifactKinds(subject string) (map[string]struct{}, bool) {
	kinds, ok := expectedLifecycleKinds(subject)
	if !ok {
		return nil, false
	}
	result := make(map[string]struct{}, len(kinds))
	for kind := range kinds {
		result[kind] = struct{}{}
	}
	return result, true
}

func lifecycleProbeSubject(subject string) bool {
	for _, probeID := range lifecycleProbeIDs {
		if subject == probeID {
			return true
		}
	}
	return false
}

func expectedLifecycleKinds(subject string) (map[string]struct{}, bool) {
	if _, required := requiredLifecycleSubjects[subject]; !required {
		return nil, false
	}
	switch subject {
	case "renderer-ready-v2:trace":
		return setOf("renderer-ready-trace"), true
	case "network-extension-approval:trace", "network-extension-denial:trace", "network-extension-pending:trace":
		return setOf("network-extension-trace"), true
	case "sleep-wake:trace":
		return setOf("sleep-wake-trace"), true
	case "sleep-wake:packet":
		return setOf("packet-pcap", "packet-pcapng"), true
	case "wkwebview-850x603:metadata":
		return setOf("wkwebview-metadata"), true
	case "wkwebview-850x603:pixels":
		return setOf("wkwebview-rgba"), true
	default:
		if strings.HasSuffix(subject, ":observation") && lifecycleProbeSubject(strings.TrimSuffix(subject, ":observation")) {
			return setOf("lifecycle-observation"), true
		}
		if lifecycleProbeSubject(subject) {
			return setOf("lifecycle-event"), true
		}
		return nil, false
	}
}

var packetCaseIDs = []string{
	"tcp-ipv4", "tcp-ipv6", "udp", "quic",
	"dns-a-primary", "dns-a-secondary", "dns-aaaa-primary", "dns-aaaa-secondary",
	"lan-bypass", "included-routes", "excluded-routes", "stop-cleanup",
	"ipv6-disabled-absence",
}

func requiredPacketSubjects() map[string]struct{} {
	result := make(map[string]struct{}, len(packetCaseIDs)*4)
	for _, caseID := range packetCaseIDs {
		result[caseID] = struct{}{}
		result[caseID+":product-state"] = struct{}{}
		result[caseID+":capture-provenance"] = struct{}{}
		result[caseID+":send-attempt"] = struct{}{}
	}
	return result
}

var optionalPacketSubjects = setOf(
	"stop-cleanup:restore-state", "ipv6-disabled-absence:restore-state",
)

var requiredPerformanceSubjects = setOf(
	"sample-ledger", "shaping-intent", "shaping-restoration",
)

func expectedPerformanceKind(subject string) (string, bool) {
	if _, ok := requiredPerformanceSubjects[subject]; !ok {
		return "", false
	}
	if subject == "sample-ledger" {
		return "performance-sample-ledger", true
	}
	return "performance-shaping-transaction", true
}

var adversarialCaseIDs = []string{
	"authority-journal-symlink", "authority-journal-tamper", "authority-journal-truncation",
	"deep-message", "duplicate-redemption", "event-queue-saturation",
	"fast-user-switching-race", "heartbeat-loss", "in-flight-saturation",
	"inactive-console-user", "late-callback", "noncanonical-message", "oversize-message",
	"replay-cursor-rollback", "replayed-operation", "replayed-start-ticket", "request-flood",
	"same-team-unknown-bundle", "secret-extraction-crash-records", "secret-extraction-evidence",
	"secret-extraction-journal", "secret-extraction-logs", "secret-extraction-preferences",
	"secret-extraction-snapshots", "stale-audit-evidence", "stale-pid-evidence",
	"wrong-audit-session", "wrong-bundle-identifier", "wrong-designated-requirement",
	"wrong-entitlement", "wrong-team-id", "wrong-uid",
}

var adversarialSecretCaseIDs = setOf(
	"secret-extraction-crash-records", "secret-extraction-evidence",
	"secret-extraction-journal", "secret-extraction-logs",
	"secret-extraction-preferences", "secret-extraction-snapshots",
)

func makeRequiredAdversarialSubjects() map[string]struct{} {
	result := make(map[string]struct{}, (len(adversarialCaseIDs)+1)*4+len(adversarialSecretCaseIDs))
	for _, caseID := range append([]string{"baseline"}, adversarialCaseIDs...) {
		result[caseID] = struct{}{}
		result["observation:"+caseID] = struct{}{}
		result["client-signature:"+caseID] = struct{}{}
		result["server-signature:"+caseID] = struct{}{}
		if _, secret := adversarialSecretCaseIDs[caseID]; secret {
			result["secret-coverage:"+caseID] = struct{}{}
		}
	}
	return result
}

var requiredAdversarialSubjects = makeRequiredAdversarialSubjects()

func RequiredAdversarialSubjects() map[string]struct{} {
	result := make(map[string]struct{}, len(requiredAdversarialSubjects))
	for subject := range requiredAdversarialSubjects {
		result[subject] = struct{}{}
	}
	return result
}

func ExpectedAdversarialArtifactKind(subject string) (string, bool) {
	if _, required := requiredAdversarialSubjects[subject]; !required {
		return "", false
	}
	switch {
	case strings.HasPrefix(subject, "observation:"):
		return "adversarial-case-observation", true
	case strings.HasPrefix(subject, "client-signature:"), strings.HasPrefix(subject, "server-signature:"):
		return "adversarial-signature-observation", true
	case strings.HasPrefix(subject, "secret-coverage:"):
		return "adversarial-secret-coverage", true
	default:
		return "adversarial-transcript", true
	}
}

var stableMatrixGA = time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)

func ValidateNonceRequest(request NonceRequest) error {
	if request.SchemaVersion != RequestSchemaVersion {
		return fmt.Errorf("schema_version must be %d", RequestSchemaVersion)
	}
	if err := validateCandidate(request.Candidate); err != nil {
		return err
	}
	return validateRunIntent(request.Run)
}

func BuildReceiptPayload(
	request ReceiptRequest,
	binding ServerBinding,
	signedAt time.Time,
) (ReceiptPayload, error) {
	if request.SchemaVersion != RequestSchemaVersion {
		return ReceiptPayload{}, fmt.Errorf("schema_version must be %d", RequestSchemaVersion)
	}
	if err := validateCandidate(request.Candidate); err != nil {
		return ReceiptPayload{}, err
	}
	intent := RunIntent{
		OS: request.Run.OS, MacOSVersion: request.Run.MacOSVersion,
		MacOSBuild: request.Run.MacOSBuild, MachineSHA256: request.Run.MachineSHA256,
		CleanInstall: request.Run.CleanInstall, RunID: request.Run.RunID,
	}
	if err := validateRunIntent(intent); err != nil {
		return ReceiptPayload{}, err
	}
	if !isSHA256(request.Run.RunNonce) {
		return ReceiptPayload{}, errors.New("run.run_nonce must be 256-bit lowercase hex")
	}
	builtAt, err := parseUTC(request.Candidate.BuiltAt, "candidate.built_at")
	if err != nil {
		return ReceiptPayload{}, err
	}
	capturedAt, err := parseUTC(request.Run.CapturedAt, "run.captured_at")
	if err != nil {
		return ReceiptPayload{}, err
	}
	completedAt, err := parseUTC(request.Run.CompletedAt, "run.completed_at")
	if err != nil {
		return ReceiptPayload{}, err
	}
	signedAt = signedAt.UTC().Truncate(time.Second)
	if capturedAt.Before(builtAt) || capturedAt.Before(stableMatrixGA) || completedAt.Before(capturedAt) || signedAt.Before(completedAt) {
		return ReceiptPayload{}, errors.New("run timestamps are stale, reversed, or after server signing time")
	}

	reports := append([]ReportBinding(nil), request.Reports...)
	raw := append([]RawArtifactBinding(nil), request.RawArtifacts...)
	if err := validateBindings(reports, raw, builtAt, capturedAt, completedAt, signedAt); err != nil {
		return ReceiptPayload{}, err
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].Harness < reports[j].Harness })
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].Harness == raw[j].Harness {
			return raw[i].Subject < raw[j].Subject
		}
		return raw[i].Harness < raw[j].Harness
	})

	return ReceiptPayload{
		SchemaVersion:     ReceiptSchemaVersion,
		TrustPolicySHA256: binding.TrustPolicySHA256,
		Candidate:         request.Candidate,
		Run: SignedRun{
			OS: request.Run.OS, MacOSVersion: request.Run.MacOSVersion,
			MacOSBuild: request.Run.MacOSBuild, MachineSHA256: request.Run.MachineSHA256,
			CleanInstall: request.Run.CleanInstall, CapturedAt: request.Run.CapturedAt,
			CompletedAt: request.Run.CompletedAt, SignedAt: formatUTC(signedAt),
			RunID: request.Run.RunID, RunNonce: request.Run.RunNonce,
		},
		Collector: CollectorBinding{
			Version:          binding.CollectorVersion,
			SourceSHA256:     binding.CollectorSourceSHA256,
			ExecutableSHA256: binding.CollectorExecutableSHA256,
			KeyVersion:       binding.KMSKeyVersion,
			Algorithm:        SignatureAlgorithm,
		},
		Reports:      reports,
		RawArtifacts: raw,
	}, nil
}

func HashCanonical(value any) (string, error) {
	encoded, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validateCandidate(candidate Candidate) error {
	if candidate.Version != ProductVersion {
		return fmt.Errorf("candidate.version must be %s", ProductVersion)
	}
	if !buildPattern.MatchString(candidate.BuildNumber) {
		return errors.New("candidate.build_number must be a canonical positive decimal integer")
	}
	build, err := strconv.ParseUint(candidate.BuildNumber, 10, 63)
	if err != nil || build > math.MaxInt64 {
		return errors.New("candidate.build_number exceeds the signed 64-bit bound")
	}
	for label, value := range map[string]string{
		"candidate.app_manifest_sha256":           candidate.AppManifestSHA256,
		"candidate.signed_app_tree_sha256":        candidate.SignedAppTreeSHA256,
		"candidate.artifact_hash_manifest_sha256": candidate.ArtifactHashManifestSHA256,
	} {
		if !isSHA256(value) {
			return fmt.Errorf("%s must be lowercase SHA-256", label)
		}
	}
	_, err = parseUTC(candidate.BuiltAt, "candidate.built_at")
	return err
}

func validateRunIntent(run RunIntent) error {
	expected, ok := requiredOS[run.OS]
	if !ok {
		return errors.New("run.os is not source-pinned")
	}
	if run.MacOSVersion != expected.version || run.MacOSBuild != expected.build {
		return errors.New("run macOS version/build differs from the source-pinned stable matrix")
	}
	if !isSHA256(run.MachineSHA256) {
		return errors.New("run.machine_sha256 must be lowercase SHA-256")
	}
	if !run.CleanInstall {
		return errors.New("run.clean_install must be true")
	}
	if !identifierPattern.MatchString(run.RunID) {
		return errors.New("run.run_id is not a canonical identifier")
	}
	return nil
}

func validateBindings(
	reports []ReportBinding,
	raw []RawArtifactBinding,
	builtAt, runCaptured, runCompleted, runSigned time.Time,
) error {
	if len(reports) != len(expectedHarnessVersions) {
		return errors.New("reports must contain exactly the four source-pinned harnesses")
	}
	if len(reports)+len(raw) > MaxArtifactCount {
		return fmt.Errorf("receipt exceeds %d artifact descriptors", MaxArtifactCount)
	}
	seenHarness := make(map[string]struct{})
	seenPath := make(map[string]struct{})
	seenDigest := make(map[string]struct{})
	var totalBytes int64
	for _, report := range reports {
		expectedVersion, ok := expectedHarnessVersions[report.Harness]
		if !ok {
			return fmt.Errorf("unknown report harness %q", report.Harness)
		}
		if _, exists := seenHarness[report.Harness]; exists {
			return fmt.Errorf("duplicate report harness %q", report.Harness)
		}
		seenHarness[report.Harness] = struct{}{}
		if report.ToolVersion != expectedVersion {
			return fmt.Errorf("report %q tool_version is not source-pinned", report.Harness)
		}
		if report.Descriptor.Kind != reportKinds[report.Harness] {
			return fmt.Errorf("report %q descriptor kind is invalid", report.Harness)
		}
		if err := validateReportTimes(report, builtAt, runCaptured, runCompleted, runSigned); err != nil {
			return err
		}
		if err := validateDescriptor(report.Descriptor); err != nil {
			return fmt.Errorf("report %q descriptor: %w", report.Harness, err)
		}
		if err := recordDescriptor(report.Descriptor, seenPath, seenDigest, &totalBytes); err != nil {
			return err
		}
	}

	seenRaw := make(map[string]struct{})
	harnessCounts := make(map[string]int)
	lifecycleSubjects := make(map[string]struct{})
	packetSubjects := make(map[string]struct{})
	performanceSubjects := make(map[string]struct{})
	adversarialSubjects := make(map[string]struct{})
	for _, artifact := range raw {
		allowedKinds, ok := rawKindsByHarness[artifact.Harness]
		if !ok {
			return fmt.Errorf("unknown raw artifact harness %q", artifact.Harness)
		}
		if _, ok := allowedKinds[artifact.Descriptor.Kind]; !ok {
			return fmt.Errorf("raw artifact kind %q is invalid for harness %q", artifact.Descriptor.Kind, artifact.Harness)
		}
		if artifact.Harness == "adversarial" {
			expectedKind, required := ExpectedAdversarialArtifactKind(artifact.Subject)
			if !required || artifact.Descriptor.Kind != expectedKind {
				return fmt.Errorf("raw adversarial subject %q has an invalid artifact kind", artifact.Subject)
			}
		}
		if artifact.Harness == "performance" {
			expectedKind, required := expectedPerformanceKind(artifact.Subject)
			if !required || artifact.Descriptor.Kind != expectedKind {
				return fmt.Errorf("raw performance subject %q has an invalid artifact kind", artifact.Subject)
			}
		}
		if artifact.Harness == "lifecycle" {
			expectedKinds, required := expectedLifecycleKinds(artifact.Subject)
			if !required {
				return fmt.Errorf("raw lifecycle subject %q is not source-pinned", artifact.Subject)
			}
			if _, valid := expectedKinds[artifact.Descriptor.Kind]; !valid {
				return fmt.Errorf("raw lifecycle subject %q has an invalid artifact kind", artifact.Subject)
			}
		}
		if err := boundedPrintable(artifact.Subject, 256); err != nil {
			return fmt.Errorf("raw artifact subject: %w", err)
		}
		identity := artifact.Harness + "\x00" + artifact.Subject
		if _, exists := seenRaw[identity]; exists {
			return fmt.Errorf("duplicate raw artifact subject %q for harness %q", artifact.Subject, artifact.Harness)
		}
		seenRaw[identity] = struct{}{}
		harnessCounts[artifact.Harness]++
		if artifact.Harness == "lifecycle" {
			lifecycleSubjects[artifact.Subject] = struct{}{}
		} else if artifact.Harness == "packet" {
			packetSubjects[artifact.Subject] = struct{}{}
		} else if artifact.Harness == "performance" {
			performanceSubjects[artifact.Subject] = struct{}{}
		} else if artifact.Harness == "adversarial" {
			adversarialSubjects[artifact.Subject] = struct{}{}
		}
		if err := validateDescriptor(artifact.Descriptor); err != nil {
			return fmt.Errorf("raw artifact %q descriptor: %w", artifact.Subject, err)
		}
		if err := recordDescriptor(artifact.Descriptor, seenPath, seenDigest, &totalBytes); err != nil {
			return err
		}
	}
	for harness := range expectedHarnessVersions {
		if harnessCounts[harness] == 0 {
			return fmt.Errorf("raw artifacts omit harness %q", harness)
		}
	}
	for subject := range requiredLifecycleSubjects {
		if _, ok := lifecycleSubjects[subject]; !ok {
			return fmt.Errorf("raw artifacts omit required lifecycle subject %q", subject)
		}
	}
	for subject := range lifecycleSubjects {
		if _, required := requiredLifecycleSubjects[subject]; !required {
			return fmt.Errorf("raw artifacts contain unknown lifecycle subject %q", subject)
		}
	}
	for subject := range requiredPacketSubjects() {
		if _, ok := packetSubjects[subject]; !ok {
			return fmt.Errorf("raw artifacts omit required packet subject %q", subject)
		}
	}
	for subject := range packetSubjects {
		if _, required := requiredPacketSubjects()[subject]; required {
			continue
		}
		if _, optional := optionalPacketSubjects[subject]; !optional {
			return fmt.Errorf("raw artifacts contain unknown packet subject %q", subject)
		}
	}
	for subject := range requiredAdversarialSubjects {
		if _, ok := adversarialSubjects[subject]; !ok {
			return fmt.Errorf("raw artifacts omit required adversarial subject %q", subject)
		}
	}
	for subject := range requiredPerformanceSubjects {
		if _, ok := performanceSubjects[subject]; !ok {
			return fmt.Errorf("raw artifacts omit required performance subject %q", subject)
		}
	}
	for subject := range performanceSubjects {
		if _, required := requiredPerformanceSubjects[subject]; !required {
			return fmt.Errorf("raw artifacts contain unknown performance subject %q", subject)
		}
	}
	for subject := range adversarialSubjects {
		if _, required := requiredAdversarialSubjects[subject]; !required {
			return fmt.Errorf("raw artifacts contain unknown adversarial subject %q", subject)
		}
	}
	if totalBytes > MaxArtifactBytes {
		return fmt.Errorf("receipt artifact bytes exceed %d", MaxArtifactBytes)
	}
	return nil
}

func validateReportTimes(report ReportBinding, builtAt, runCaptured, runCompleted, runSigned time.Time) error {
	captured, err := parseUTC(report.CapturedAt, "report.captured_at")
	if err != nil {
		return err
	}
	completed, err := parseUTC(report.CompletedAt, "report.completed_at")
	if err != nil {
		return err
	}
	signed, err := parseUTC(report.SignedAt, "report.signed_at")
	if err != nil {
		return err
	}
	if captured.Before(builtAt) || captured.Before(runCaptured) || completed.Before(captured) || signed.Before(completed) || completed.After(runCompleted) || signed.After(runSigned) {
		return fmt.Errorf("report %q timestamps are stale or reversed", report.Harness)
	}
	return nil
}

func validateDescriptor(descriptor Descriptor) error {
	spec, ok := artifactKinds[descriptor.Kind]
	if !ok {
		return fmt.Errorf("unknown artifact kind %q", descriptor.Kind)
	}
	if descriptor.Path == "" || strings.Contains(descriptor.Path, `\`) || len([]byte(descriptor.Path)) > MaxRelativePathBytes {
		return errors.New("path is not a bounded POSIX relative path")
	}
	if path.IsAbs(descriptor.Path) || path.Clean(descriptor.Path) != descriptor.Path {
		return errors.New("path is not canonical and relative")
	}
	for _, component := range strings.Split(descriptor.Path, "/") {
		if !pathComponentPattern.MatchString(component) {
			return errors.New("path has a non-canonical component")
		}
	}
	if !strings.HasSuffix(descriptor.Path, spec.suffix) {
		return errors.New("path extension does not match artifact kind")
	}
	if descriptor.Size < 1 || descriptor.Size > spec.maximum {
		return errors.New("size is outside the artifact kind bound")
	}
	if !isSHA256(descriptor.SHA256) {
		return errors.New("sha256 must be lowercase SHA-256")
	}
	return nil
}

func recordDescriptor(descriptor Descriptor, paths, digests map[string]struct{}, total *int64) error {
	if _, exists := paths[descriptor.Path]; exists {
		return fmt.Errorf("artifact path %q is reused", descriptor.Path)
	}
	if _, exists := digests[descriptor.SHA256]; exists {
		return fmt.Errorf("artifact digest %q is reused", descriptor.SHA256)
	}
	paths[descriptor.Path] = struct{}{}
	digests[descriptor.SHA256] = struct{}{}
	if descriptor.Size > MaxArtifactBytes-*total {
		return fmt.Errorf("receipt artifact bytes exceed %d", MaxArtifactBytes)
	}
	*total += descriptor.Size
	return nil
}

func parseUTC(value, label string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("%s must be a UTC timestamp ending in Z", label)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC {
		return time.Time{}, fmt.Errorf("%s is not canonical ISO-8601 UTC", label)
	}
	return parsed, nil
}

func formatUTC(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func boundedPrintable(value string, maximum int) error {
	if strings.TrimSpace(value) == "" || len([]byte(value)) > maximum {
		return errors.New("value is empty or exceeds its byte bound")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("value contains a control character")
		}
	}
	return nil
}

func isSHA256(value string) bool {
	return sha256Pattern.MatchString(value)
}

func setOf(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}
