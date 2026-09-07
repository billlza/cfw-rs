package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/contract"
)

func TestLoadDefaultsProductionClosedAndValidatesKeyBinding(t *testing.T) {
	setValidEnvironment(t)
	configValue, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configValue.ProductionReceiptsEnabled {
		t.Fatal("production receipts defaulted open")
	}
	if configValue.Role != RoleReceiptSigner || configValue.PublicKey.N.BitLen() != 3072 {
		t.Fatal("validated configuration was not loaded")
	}
	if configValue.Binding().Algorithm != contract.SignatureAlgorithm {
		t.Fatal("algorithm was not fixed to PS256")
	}
}

func TestLoadRejectsProductionWithNotConfiguredPolicy(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("CFW_PRODUCTION_RECEIPTS_ENABLED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("production accepted the not-configured policy digest")
	}
}

func TestLoadRejectsCrossProjectKeyAndPublicKeyDigestDrift(t *testing.T) {
	t.Run("cross-project", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("CFW_KMS_KEY_VERSION", "projects/other-release-project/locations/asia-east1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")
		if _, err := Load(); err == nil {
			t.Fatal("accepted a key version from another project")
		}
	})
	t.Run("public-key-drift", func(t *testing.T) {
		setValidEnvironment(t)
		t.Setenv("CFW_KMS_PUBLIC_KEY_SHA256", strings.Repeat("0", 64))
		if _, err := Load(); err == nil {
			t.Fatal("accepted a public key digest mismatch")
		}
	})
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	t.Setenv("CFW_COLLECTOR_ROLE", string(RoleReceiptSigner))
	t.Setenv("GOOGLE_CLOUD_PROJECT", "cfw-release-evidence-20260730")
	t.Setenv("CFW_FIRESTORE_DATABASE", "physical-release-ledger")
	t.Setenv("CFW_KMS_KEY_VERSION", "projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/physical-evidence/cryptoKeys/collector-receipts/cryptoKeyVersions/1")
	t.Setenv("CFW_TRUST_POLICY_SHA256", notConfiguredPolicySHA256)
	t.Setenv("CFW_COLLECTOR_VERSION", contract.CollectorVersion)
	t.Setenv("CFW_COLLECTOR_SOURCE_SHA256", hex.EncodeToString(make([]byte, 32)))
	t.Setenv("CFW_COLLECTOR_EXECUTABLE_SHA256", hex.EncodeToString(make([]byte, 32)))
	t.Setenv("CFW_KMS_PUBLIC_KEY_SHA256", hex.EncodeToString(digest[:]))
	t.Setenv("CFW_KMS_PUBLIC_KEY_DER_BASE64", base64.StdEncoding.EncodeToString(der))
	t.Setenv("CFW_PRODUCTION_RECEIPTS_ENABLED", "false")
}
