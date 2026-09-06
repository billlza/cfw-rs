package config

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/contract"
)

type Role string

const (
	RoleNonceIssuer   Role = "nonce-issuer"
	RoleReceiptSigner Role = "receipt-signer"

	notConfiguredPolicySHA256 = "a616bbc91d72f25a904ae1d4c9c54ddad6106652c8997ca8b4131536b8f3bba4"
)

var (
	projectPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	keyVersionPattern = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/[a-z0-9-]{1,63}/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}/cryptoKeyVersions/[1-9][0-9]*$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Config struct {
	Role                      Role
	Port                      int
	ProjectID                 string
	FirestoreDatabase         string
	KMSKeyVersion             string
	TrustPolicySHA256         string
	CollectorVersion          string
	CollectorSourceSHA256     string
	CollectorExecutableSHA256 string
	KMSPublicKeySHA256        string
	PublicKey                 *rsa.PublicKey
	ProductionReceiptsEnabled bool
}

func Load() (Config, error) {
	role := Role(os.Getenv("CFW_COLLECTOR_ROLE"))
	if role != RoleNonceIssuer && role != RoleReceiptSigner {
		return Config{}, errors.New("CFW_COLLECTOR_ROLE must be nonce-issuer or receipt-signer")
	}
	port, err := loadPort()
	if err != nil {
		return Config{}, err
	}
	projectID, err := required("GOOGLE_CLOUD_PROJECT")
	if err != nil || !projectPattern.MatchString(projectID) {
		return Config{}, errors.New("GOOGLE_CLOUD_PROJECT is missing or invalid")
	}
	database, err := required("CFW_FIRESTORE_DATABASE")
	if err != nil || !identifierPattern.MatchString(strings.Trim(database, "()")) {
		return Config{}, errors.New("CFW_FIRESTORE_DATABASE is missing or invalid")
	}
	keyVersion, err := required("CFW_KMS_KEY_VERSION")
	if err != nil {
		return Config{}, err
	}
	keyMatch := keyVersionPattern.FindStringSubmatch(keyVersion)
	if len(keyMatch) != 2 || keyMatch[1] != projectID {
		return Config{}, errors.New("CFW_KMS_KEY_VERSION must be a complete version in GOOGLE_CLOUD_PROJECT")
	}

	trustPolicy, err := requiredSHA256("CFW_TRUST_POLICY_SHA256")
	if err != nil {
		return Config{}, err
	}
	collectorVersion, err := required("CFW_COLLECTOR_VERSION")
	if err != nil || collectorVersion != contract.CollectorVersion || !identifierPattern.MatchString(collectorVersion) {
		return Config{}, fmt.Errorf("CFW_COLLECTOR_VERSION must be %s", contract.CollectorVersion)
	}
	collectorSource, err := requiredSHA256("CFW_COLLECTOR_SOURCE_SHA256")
	if err != nil {
		return Config{}, err
	}
	collectorExecutable, err := requiredSHA256("CFW_COLLECTOR_EXECUTABLE_SHA256")
	if err != nil {
		return Config{}, err
	}
	publicKeySHA256, err := requiredSHA256("CFW_KMS_PUBLIC_KEY_SHA256")
	if err != nil {
		return Config{}, err
	}
	publicKey, err := loadPublicKey(publicKeySHA256)
	if err != nil {
		return Config{}, err
	}
	enabled, err := loadBool("CFW_PRODUCTION_RECEIPTS_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	if enabled && hmac.Equal([]byte(trustPolicy), []byte(notConfiguredPolicySHA256)) {
		return Config{}, errors.New("production receipts cannot use the source-pinned not-configured policy")
	}

	return Config{
		Role:                      role,
		Port:                      port,
		ProjectID:                 projectID,
		FirestoreDatabase:         database,
		KMSKeyVersion:             keyVersion,
		TrustPolicySHA256:         trustPolicy,
		CollectorVersion:          collectorVersion,
		CollectorSourceSHA256:     collectorSource,
		CollectorExecutableSHA256: collectorExecutable,
		KMSPublicKeySHA256:        publicKeySHA256,
		PublicKey:                 publicKey,
		ProductionReceiptsEnabled: enabled,
	}, nil
}

func (config Config) Binding() contract.ServerBinding {
	return contract.ServerBinding{
		TrustPolicySHA256:         config.TrustPolicySHA256,
		CollectorVersion:          config.CollectorVersion,
		CollectorSourceSHA256:     config.CollectorSourceSHA256,
		CollectorExecutableSHA256: config.CollectorExecutableSHA256,
		KMSKeyVersion:             config.KMSKeyVersion,
		Algorithm:                 contract.SignatureAlgorithm,
	}
}

func loadPort() (int, error) {
	value := os.Getenv("PORT")
	if value == "" {
		return 8080, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("PORT must be an integer from 1 through 65535")
	}
	return port, nil
}

func loadPublicKey(expectedSHA256 string) (*rsa.PublicKey, error) {
	encoded, err := required("CFW_KMS_PUBLIC_KEY_DER_BASE64")
	if err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(der) == 0 || len(der) > 4096 {
		return nil, errors.New("CFW_KMS_PUBLIC_KEY_DER_BASE64 is not bounded canonical base64")
	}
	digest := sha256.Sum256(der)
	expected, _ := hex.DecodeString(expectedSHA256)
	if !hmac.Equal(digest[:], expected) {
		return nil, errors.New("CFW_KMS_PUBLIC_KEY_DER_BASE64 does not match CFW_KMS_PUBLIC_KEY_SHA256")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("CFW_KMS_PUBLIC_KEY_DER_BASE64 is not DER SubjectPublicKeyInfo")
	}
	publicKey, ok := parsed.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 3072 || publicKey.E != 65537 {
		return nil, errors.New("CFW_KMS_PUBLIC_KEY_DER_BASE64 must contain RSA-3072 exponent 65537")
	}
	return publicKey, nil
}

func required(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%s is required and must not have surrounding whitespace", name)
	}
	return value, nil
}

func requiredSHA256(name string) (string, error) {
	value, err := required(name)
	if err != nil {
		return "", err
	}
	if !sha256Pattern.MatchString(value) {
		return "", fmt.Errorf("%s must be lowercase SHA-256", name)
	}
	return value, nil
}

func loadBool(name string, defaultValue bool) (bool, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return defaultValue, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be exactly true or false", name)
	}
}
