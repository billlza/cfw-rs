package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certificateName = "certificate.der"
	privateKeyName  = "private-key.x963"
	manifestName    = "identity.json"
	serverName      = "cfm-transport-peer.invalid"
	maximumLifetime = 15 * time.Minute
)

type manifest struct {
	SchemaVersion     int    `json:"schema_version"`
	Document          string `json:"document"`
	ServerName        string `json:"server_name"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	CertificateSHA256 string `json:"certificate_sha256"`
	PrivateKeySHA256  string `json:"private_key_sha256"`
}

func main() {
	if len(os.Args) != 1 {
		fatal(errors.New("certificate generator accepts no arguments"))
	}
	if err := generate(time.Now().UTC()); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "physical transport peer identity generation failed: %v\n", err)
	os.Exit(1)
}

func generate(now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate P-256 key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate certificate serial: %w", err)
	}
	notBefore := now.Add(-30 * time.Second).Truncate(time.Second)
	notAfter := now.Add(maximumLifetime).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		DNSNames:              []string{serverName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create self-signed certificate: %w", err)
	}
	privateKey := x963PrivateKey(key)
	certificateDigest := sha256.Sum256(certificate)
	privateKeyDigest := sha256.Sum256(privateKey)
	receipt := manifest{
		SchemaVersion:     1,
		Document:          "cfm-ios-transport-peer-identity-v1",
		ServerName:        serverName,
		NotBefore:         notBefore.Format(time.RFC3339),
		NotAfter:          notAfter.Format(time.RFC3339),
		CertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		PrivateKeySHA256:  hex.EncodeToString(privateKeyDigest[:]),
	}
	manifestBytes, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("encode identity manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	files := []struct {
		name string
		data []byte
	}{
		{certificateName, certificate},
		{privateKeyName, privateKey},
		{manifestName, manifestBytes},
	}
	for _, file := range files {
		if err := writeExclusive(file.name, file.data); err != nil {
			return err
		}
	}
	return syncDirectory(".")
}

func x963PrivateKey(key *ecdsa.PrivateKey) []byte {
	coordinateBytes := (key.Curve.Params().BitSize + 7) / 8
	output := make([]byte, 1+3*coordinateBytes)
	output[0] = 4
	key.X.FillBytes(output[1 : 1+coordinateBytes])
	key.Y.FillBytes(output[1+coordinateBytes : 1+2*coordinateBytes])
	key.D.FillBytes(output[1+2*coordinateBytes:])
	return output
}

func writeExclusive(name string, data []byte) error {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("identity output name is unsafe")
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	writeErr := error(nil)
	if _, err := file.Write(data); err != nil {
		writeErr = fmt.Errorf("write %s: %w", name, err)
	} else if err := file.Sync(); err != nil {
		writeErr = fmt.Errorf("sync %s: %w", name, err)
	}
	if err := file.Close(); writeErr == nil && err != nil {
		writeErr = fmt.Errorf("close %s: %w", name, err)
	}
	return writeErr
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
