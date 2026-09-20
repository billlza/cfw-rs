package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"hash/crc32"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeKMSClient struct {
	privateKey *rsa.PrivateKey
	mutate     func(*kmspb.AsymmetricSignResponse)
	err        error
	calls      int
	request    *kmspb.AsymmetricSignRequest
}

func (client *fakeKMSClient) AsymmetricSign(_ context.Context, request *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	client.calls++
	client.request = request
	if client.err != nil {
		return nil, client.err
	}
	signature, err := rsa.SignPSS(rand.Reader, client.privateKey, crypto.SHA256, request.GetDigest().GetSha256(), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		return nil, err
	}
	response := &kmspb.AsymmetricSignResponse{
		Signature:            signature,
		SignatureCrc32C:      wrapperspb.Int64(int64(crc32.Checksum(signature, crc32.MakeTable(crc32.Castagnoli)))),
		VerifiedDigestCrc32C: true,
		Name:                 request.Name,
		ProtectionLevel:      kmspb.ProtectionLevel_HSM,
	}
	if client.mutate != nil {
		client.mutate(response)
	}
	return response, nil
}

func TestKMSSignChecksRequestAndResponseIntegrity(t *testing.T) {
	privateKey := mustRSAKey(t)
	client := &fakeKMSClient{privateKey: privateKey}
	keyVersion := "projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
	signer, err := NewKMS(client, keyVersion, &privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("canonical receipt payload")
	if _, err := signer.Sign(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 || client.request.Name != keyVersion || client.request.DigestCrc32C == nil {
		t.Fatal("KMS request did not bind exact version and digest CRC32C")
	}
	wantCRC := crc32.Checksum(client.request.GetDigest().GetSha256(), crc32.MakeTable(crc32.Castagnoli))
	if uint32(client.request.DigestCrc32C.Value) != wantCRC {
		t.Fatal("KMS request digest CRC32C is wrong")
	}
}

func TestKMSSignRejectsEveryIntegritySubstitutionWithoutRetry(t *testing.T) {
	privateKey := mustRSAKey(t)
	tests := []struct {
		name   string
		err    error
		mutate func(*kmspb.AsymmetricSignResponse)
	}{
		{name: "transport-error", err: errors.New("unavailable")},
		{name: "digest-not-verified", mutate: func(response *kmspb.AsymmetricSignResponse) { response.VerifiedDigestCrc32C = false }},
		{name: "wrong-name", mutate: func(response *kmspb.AsymmetricSignResponse) { response.Name += "-other" }},
		{name: "software", mutate: func(response *kmspb.AsymmetricSignResponse) {
			response.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE
		}},
		{name: "missing-signature-crc", mutate: func(response *kmspb.AsymmetricSignResponse) { response.SignatureCrc32C = nil }},
		{name: "wrong-signature-crc", mutate: func(response *kmspb.AsymmetricSignResponse) { response.SignatureCrc32C.Value++ }},
		{name: "signature-drift", mutate: func(response *kmspb.AsymmetricSignResponse) {
			response.Signature[0] ^= 1
			response.SignatureCrc32C.Value = int64(crc32.Checksum(response.Signature, crc32.MakeTable(crc32.Castagnoli)))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeKMSClient{privateKey: privateKey, err: test.err, mutate: test.mutate}
			signer, err := NewKMS(client, "projects/cfw-release-evidence-20260730/locations/asia-east1/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", &privateKey.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := signer.Sign(context.Background(), []byte("payload")); !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("expected ErrAmbiguous, got %v", err)
			}
			if client.calls != 1 {
				t.Fatalf("KMS was called %d times; automatic retry is forbidden", client.calls)
			}
		})
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}
