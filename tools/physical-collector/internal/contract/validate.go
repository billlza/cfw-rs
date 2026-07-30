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
	"lifecycle":   "lifecycle-matrix-v3",
	"packet":      "packet-evidence-v3",
	"performance": "performance-gates-v2",
	"adversarial": "adversarial-clients-v2",
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
	"packet-report":             {suffix: ".json", maximum: 1 << 20, report: true},
	"lifecycle-report":          {suffix: ".json", maximum: 1 << 20, report: true},
	"performance-report":        {suffix: ".json", maximum: 1 << 20, report: true},
	"adversarial-report":        {suffix: ".json", maximum: 1 << 20, report: true},
	"packet-pcap":               {suffix: ".pcap", maximum: 32 << 20},
	"packet-pcapng":             {suffix: ".pcapng", maximum: 32 << 20},
	"packet-capture-provenance": {suffix: ".json", maximum: 256 << 10},
	"packet-send-attempt":       {suffix: ".json", maximum: 256 << 10},
	"lifecycle-event":           {suffix: ".json", maximum: 1 << 20},
	"renderer-ready-trace":      {suffix: ".json", maximum: 1 << 20},
	"network-extension-trace":   {suffix: ".json", maximum: 1 << 20},
	"sleep-wake-trace":          {suffix: ".json", maximum: 1 << 20},
	"wkwebview-metadata":        {suffix: ".json", maximum: 256 << 10},
	"wkwebview-rgba":            {suffix: ".rgba", maximum: 16 << 20},
	"performance-samples":       {suffix: ".json", maximum: 16 << 20},
	"adversarial-transcript":    {suffix: ".json", maximum: 1 << 20},
	"client-signature-evidence": {suffix: ".json", maximum: 256 << 10},
}

var rawKindsByHarness = map[string]map[string]struct{}{
	"lifecycle": setOf(
		"lifecycle-event", "renderer-ready-trace", "network-extension-trace",
		"sleep-wake-trace", "packet-pcap", "wkwebview-metadata", "wkwebview-rgba",
	),
	"packet": setOf(
		"packet-pcap", "packet-pcapng", "packet-capture-provenance", "packet-send-attempt",
	),
	"performance": setOf("performance-samples"),
	"adversarial": setOf("adversarial-transcript", "client-signature-evidence"),
}

var requiredLifecycleSubjects = setOf(
	"renderer-ready-v2:trace",
	"network-extension-approval:trace",
	"network-extension-denial:trace",
	"network-extension-pending:trace",
	"sleep-wake:trace",
	"sleep-wake:packet",
	"wkwebview-850x603:metadata",
	"wkwebview-850x603:pixels",
)

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
	for _, artifact := range raw {
		allowedKinds, ok := rawKindsByHarness[artifact.Harness]
		if !ok {
			return fmt.Errorf("unknown raw artifact harness %q", artifact.Harness)
		}
		if _, ok := allowedKinds[artifact.Descriptor.Kind]; !ok {
			return fmt.Errorf("raw artifact kind %q is invalid for harness %q", artifact.Descriptor.Kind, artifact.Harness)
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
