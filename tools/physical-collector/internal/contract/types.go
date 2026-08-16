package contract

const (
	RequestSchemaVersion = 1
	ReceiptSchemaVersion = 3
	ProductVersion       = "0.4.0"
	SignatureAlgorithm   = "PS256"
	CollectorVersion     = "physical-collector-v1"

	MaxRequestBytes = 1 << 20
	MaxJSONDepth    = 32
	// Four reports plus 265 required raw subjects, with at most two optional
	// Packet restore observations. A 272nd descriptor is never source-pinned.
	MaxArtifactCount     = 271
	MaxArtifactBytes     = 256 * 1024 * 1024
	MaxRelativePathBytes = 512
)

type Candidate struct {
	Version                    string `json:"version"`
	BuildNumber                string `json:"build_number"`
	AppManifestSHA256          string `json:"app_manifest_sha256"`
	SignedAppTreeSHA256        string `json:"signed_app_tree_sha256"`
	ArtifactHashManifestSHA256 string `json:"artifact_hash_manifest_sha256"`
	BuiltAt                    string `json:"built_at"`
}

type RunIntent struct {
	OS            string `json:"os"`
	MacOSVersion  string `json:"macos_version"`
	MacOSBuild    string `json:"macos_build"`
	MachineSHA256 string `json:"machine_sha256"`
	CleanInstall  bool   `json:"clean_install"`
	RunID         string `json:"run_id"`
}

type NonceRequest struct {
	SchemaVersion int       `json:"schema_version"`
	Candidate     Candidate `json:"candidate"`
	Run           RunIntent `json:"run"`
}

type NonceResponse struct {
	SchemaVersion int    `json:"schema_version"`
	RunNonce      string `json:"run_nonce"`
	ExpiresAt     string `json:"expires_at"`
}

type ReceiptRun struct {
	OS            string `json:"os"`
	MacOSVersion  string `json:"macos_version"`
	MacOSBuild    string `json:"macos_build"`
	MachineSHA256 string `json:"machine_sha256"`
	CleanInstall  bool   `json:"clean_install"`
	CapturedAt    string `json:"captured_at"`
	CompletedAt   string `json:"completed_at"`
	RunID         string `json:"run_id"`
	RunNonce      string `json:"run_nonce"`
}

type Descriptor struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type ReportBinding struct {
	Harness     string     `json:"harness"`
	ToolVersion string     `json:"tool_version"`
	CapturedAt  string     `json:"captured_at"`
	CompletedAt string     `json:"completed_at"`
	SignedAt    string     `json:"signed_at"`
	Descriptor  Descriptor `json:"descriptor"`
}

type RawArtifactBinding struct {
	Harness    string     `json:"harness"`
	Subject    string     `json:"subject"`
	Descriptor Descriptor `json:"descriptor"`
}

type ReceiptRequest struct {
	SchemaVersion int                  `json:"schema_version"`
	Candidate     Candidate            `json:"candidate"`
	Run           ReceiptRun           `json:"run"`
	Reports       []ReportBinding      `json:"reports"`
	RawArtifacts  []RawArtifactBinding `json:"raw_artifacts"`
}

type CollectorBinding struct {
	Version          string `json:"version"`
	SourceSHA256     string `json:"source_sha256"`
	ExecutableSHA256 string `json:"executable_sha256"`
	KeyVersion       string `json:"key_version"`
	Algorithm        string `json:"algorithm"`
}

type SignedRun struct {
	OS            string `json:"os"`
	MacOSVersion  string `json:"macos_version"`
	MacOSBuild    string `json:"macos_build"`
	MachineSHA256 string `json:"machine_sha256"`
	CleanInstall  bool   `json:"clean_install"`
	CapturedAt    string `json:"captured_at"`
	CompletedAt   string `json:"completed_at"`
	SignedAt      string `json:"signed_at"`
	RunID         string `json:"run_id"`
	RunNonce      string `json:"run_nonce"`
}

type ReceiptPayload struct {
	SchemaVersion     int                  `json:"schema_version"`
	TrustPolicySHA256 string               `json:"trust_policy_sha256"`
	Candidate         Candidate            `json:"candidate"`
	Run               SignedRun            `json:"run"`
	Collector         CollectorBinding     `json:"collector"`
	Reports           []ReportBinding      `json:"reports"`
	RawArtifacts      []RawArtifactBinding `json:"raw_artifacts"`
}

type ReceiptResponse struct {
	SchemaVersion int    `json:"schema_version"`
	SignedAt      string `json:"signed_at"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	Signature     string `json:"signature"`
}

type PreflightResponse struct {
	SchemaVersion   int    `json:"schema_version"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	SignatureSHA256 string `json:"signature_sha256"`
	Signature       string `json:"signature"`
	KeyVersion      string `json:"key_version"`
	LedgerState     string `json:"ledger_state"`
}

type ServerBinding struct {
	TrustPolicySHA256         string `json:"trust_policy_sha256"`
	CollectorVersion          string `json:"collector_version"`
	CollectorSourceSHA256     string `json:"collector_source_sha256"`
	CollectorExecutableSHA256 string `json:"collector_executable_sha256"`
	KMSKeyVersion             string `json:"kms_key_version"`
	Algorithm                 string `json:"algorithm"`
}

type ProductionIntent struct {
	Kind          string        `json:"kind"`
	SchemaVersion int           `json:"schema_version"`
	Candidate     Candidate     `json:"candidate"`
	Run           RunIntent     `json:"run"`
	Binding       ServerBinding `json:"binding"`
}

func IntentFromNonceRequest(request NonceRequest, binding ServerBinding) ProductionIntent {
	return ProductionIntent{
		Kind:          "production-receipt-v3",
		SchemaVersion: RequestSchemaVersion,
		Candidate:     request.Candidate,
		Run:           request.Run,
		Binding:       binding,
	}
}

func IntentFromReceiptRequest(request ReceiptRequest, binding ServerBinding) ProductionIntent {
	return ProductionIntent{
		Kind:          "production-receipt-v3",
		SchemaVersion: RequestSchemaVersion,
		Candidate:     request.Candidate,
		Run: RunIntent{
			OS:            request.Run.OS,
			MacOSVersion:  request.Run.MacOSVersion,
			MacOSBuild:    request.Run.MacOSBuild,
			MachineSHA256: request.Run.MachineSHA256,
			CleanInstall:  request.Run.CleanInstall,
			RunID:         request.Run.RunID,
		},
		Binding: binding,
	}
}
