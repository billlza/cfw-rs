package signing

import (
	"context"
	"errors"
)

var ErrAmbiguous = errors.New("KMS signing outcome is ambiguous; automatic re-sign is forbidden")

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}
