package ledger

import (
	"context"
	"errors"
	"time"
)

const (
	CollectionName = "physical_receipt_nonces_v1"

	StatusIssued    = "ISSUED"
	StatusSigning   = "SIGNING"
	StatusCommitted = "COMMITTED"
	StatusAbandoned = "ABANDONED"

	KindProduction = "production-receipt-v3"
	KindPreflight  = "kms-ledger-preflight-v1"
)

var (
	ErrNotFound = errors.New("nonce ledger record does not exist")
	ErrConflict = errors.New("nonce ledger conditional transition failed")
	ErrExpired  = errors.New("nonce ledger record expired")
	ErrCorrupt  = errors.New("nonce ledger record is malformed")
)

type Issue struct {
	Nonce        string
	Kind         string
	IntentSHA256 string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

type Claim struct {
	Nonce         string
	Kind          string
	IntentSHA256  string
	PayloadSHA256 string
	AttemptID     string
	ClaimedAt     time.Time
}

type Completion struct {
	Nonce           string
	PayloadSHA256   string
	AttemptID       string
	SignatureSHA256 string
	CompletedAt     time.Time
}

type Abandonment struct {
	Nonce         string
	PayloadSHA256 string
	AttemptID     string
	FailureCode   string
	AbandonedAt   time.Time
}

type Store interface {
	Issue(context.Context, Issue) error
	Claim(context.Context, Claim) error
	Commit(context.Context, Completion) error
	Abandon(context.Context, Abandonment) error
}
