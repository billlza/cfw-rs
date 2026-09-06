package signing

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const kmsRequestTimeout = 15 * time.Second

type AsymmetricSignClient interface {
	AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest, ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
}

type KMS struct {
	client     AsymmetricSignClient
	keyVersion string
	publicKey  *rsa.PublicKey
}

func NewKMS(client AsymmetricSignClient, keyVersion string, publicKey *rsa.PublicKey) (*KMS, error) {
	if client == nil {
		return nil, errors.New("KMS client is nil")
	}
	if keyVersion == "" {
		return nil, errors.New("KMS key version is empty")
	}
	if publicKey == nil || publicKey.N.BitLen() != 3072 || publicKey.E != 65537 {
		return nil, errors.New("KMS verifier must be RSA-3072 exponent 65537")
	}
	return &KMS{client: client, keyVersion: keyVersion, publicKey: publicKey}, nil
}

func (signer *KMS) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if len(message) == 0 {
		return nil, errors.New("refusing to sign an empty message")
	}
	digest := sha256.Sum256(message)
	castagnoli := crc32.MakeTable(crc32.Castagnoli)
	digestCRC32C := crc32.Checksum(digest[:], castagnoli)
	request := &kmspb.AsymmetricSignRequest{
		Name:         signer.keyVersion,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC32C)),
	}

	callContext, cancel := context.WithTimeout(ctx, kmsRequestTimeout)
	defer cancel()
	response, err := signer.client.AsymmetricSign(
		callContext,
		request,
		gax.WithRetry(func() gax.Retryer { return nil }),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: Cloud KMS request failed", ErrAmbiguous)
	}
	if response == nil {
		return nil, fmt.Errorf("%w: Cloud KMS returned an empty response", ErrAmbiguous)
	}
	if !response.VerifiedDigestCrc32C {
		return nil, fmt.Errorf("%w: verifiedDigestCrc32c is false", ErrAmbiguous)
	}
	if response.Name != signer.keyVersion {
		return nil, fmt.Errorf("%w: Cloud KMS response name differs from the exact key version", ErrAmbiguous)
	}
	if response.ProtectionLevel != kmspb.ProtectionLevel_HSM {
		return nil, fmt.Errorf("%w: Cloud KMS response protection level is not HSM", ErrAmbiguous)
	}
	if len(response.Signature) != 384 {
		return nil, fmt.Errorf("%w: Cloud KMS signature is not 384 bytes", ErrAmbiguous)
	}
	if response.SignatureCrc32C == nil {
		return nil, fmt.Errorf("%w: Cloud KMS signatureCrc32c is absent", ErrAmbiguous)
	}
	signatureCRC32C := crc32.Checksum(response.Signature, castagnoli)
	if response.SignatureCrc32C.Value < 0 || uint32(response.SignatureCrc32C.Value) != signatureCRC32C {
		return nil, fmt.Errorf("%w: Cloud KMS signatureCrc32c mismatch", ErrAmbiguous)
	}
	if err := rsa.VerifyPSS(
		signer.publicKey,
		crypto.SHA256,
		digest[:],
		response.Signature,
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
	); err != nil {
		return nil, fmt.Errorf("%w: local rsa.VerifyPSS rejected the Cloud KMS signature", ErrAmbiguous)
	}
	return append([]byte(nil), response.Signature...), nil
}
