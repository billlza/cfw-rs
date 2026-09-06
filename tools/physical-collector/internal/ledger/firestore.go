package ledger

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const ledgerSchemaVersion = 1

var (
	noncePattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	ledgerFields      = map[string]struct{}{
		"schema_version": {}, "kind": {}, "status": {}, "nonce": {},
		"intent_sha256": {}, "payload_sha256": {}, "attempt_id": {},
		"signature_sha256": {}, "issued_at": {}, "expires_at": {},
		"signing_at": {}, "committed_at": {}, "abandoned_at": {},
		"failure_code": {},
	}
)

type document struct {
	SchemaVersion   int        `firestore:"schema_version"`
	Kind            string     `firestore:"kind"`
	Status          string     `firestore:"status"`
	Nonce           string     `firestore:"nonce"`
	IntentSHA256    string     `firestore:"intent_sha256"`
	PayloadSHA256   string     `firestore:"payload_sha256"`
	AttemptID       string     `firestore:"attempt_id"`
	SignatureSHA256 string     `firestore:"signature_sha256"`
	IssuedAt        time.Time  `firestore:"issued_at"`
	ExpiresAt       time.Time  `firestore:"expires_at"`
	SigningAt       *time.Time `firestore:"signing_at"`
	CommittedAt     *time.Time `firestore:"committed_at"`
	AbandonedAt     *time.Time `firestore:"abandoned_at"`
	FailureCode     string     `firestore:"failure_code"`
}

type Firestore struct {
	client     *firestore.Client
	collection *firestore.CollectionRef
}

func NewFirestore(client *firestore.Client) (*Firestore, error) {
	if client == nil {
		return nil, errors.New("Firestore client is nil")
	}
	return &Firestore{client: client, collection: client.Collection(CollectionName)}, nil
}

func (store *Firestore) Issue(ctx context.Context, issue Issue) error {
	if err := validateIssue(issue); err != nil {
		return err
	}
	_, err := store.collection.Doc(issue.Nonce).Create(ctx, document{
		SchemaVersion:   ledgerSchemaVersion,
		Kind:            issue.Kind,
		Status:          StatusIssued,
		Nonce:           issue.Nonce,
		IntentSHA256:    issue.IntentSHA256,
		PayloadSHA256:   "",
		AttemptID:       "",
		SignatureSHA256: "",
		IssuedAt:        issue.IssuedAt.UTC(),
		ExpiresAt:       issue.ExpiresAt.UTC(),
		SigningAt:       nil,
		CommittedAt:     nil,
		AbandonedAt:     nil,
		FailureCode:     "",
	})
	if err != nil {
		return fmt.Errorf("create nonce ledger record: %w", err)
	}
	return nil
}

func (store *Firestore) Claim(ctx context.Context, claim Claim) error {
	if err := validateClaim(claim); err != nil {
		return err
	}
	docRef := store.collection.Doc(claim.Nonce)
	return store.client.RunTransaction(ctx, func(ctx context.Context, transaction *firestore.Transaction) error {
		snapshot, err := transaction.Get(docRef)
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return ErrNotFound
			}
			return fmt.Errorf("read nonce ledger record: %w", err)
		}
		current, err := decodeDocument(snapshot)
		if err != nil {
			return err
		}
		if current.Status != StatusIssued || current.Kind != claim.Kind || current.Nonce != claim.Nonce || current.IntentSHA256 != claim.IntentSHA256 {
			return ErrConflict
		}
		if !claim.ClaimedAt.Before(current.ExpiresAt) {
			return ErrExpired
		}
		return transaction.Update(docRef, []firestore.Update{
			{Path: "status", Value: StatusSigning},
			{Path: "payload_sha256", Value: claim.PayloadSHA256},
			{Path: "attempt_id", Value: claim.AttemptID},
			{Path: "signing_at", Value: claim.ClaimedAt.UTC()},
		})
	}, firestore.MaxAttempts(5))
}

func (store *Firestore) Commit(ctx context.Context, completion Completion) error {
	if err := validateCompletion(completion); err != nil {
		return err
	}
	docRef := store.collection.Doc(completion.Nonce)
	return store.client.RunTransaction(ctx, func(ctx context.Context, transaction *firestore.Transaction) error {
		snapshot, err := transaction.Get(docRef)
		if err != nil {
			return fmt.Errorf("read nonce ledger record for commit: %w", err)
		}
		current, err := decodeDocument(snapshot)
		if err != nil {
			return err
		}
		if current.Status != StatusSigning || current.PayloadSHA256 != completion.PayloadSHA256 || current.AttemptID != completion.AttemptID {
			return ErrConflict
		}
		return transaction.Update(docRef, []firestore.Update{
			{Path: "status", Value: StatusCommitted},
			{Path: "signature_sha256", Value: completion.SignatureSHA256},
			{Path: "committed_at", Value: completion.CompletedAt.UTC()},
		})
	}, firestore.MaxAttempts(5))
}

func (store *Firestore) Abandon(ctx context.Context, abandonment Abandonment) error {
	if err := validateAbandonment(abandonment); err != nil {
		return err
	}
	docRef := store.collection.Doc(abandonment.Nonce)
	return store.client.RunTransaction(ctx, func(ctx context.Context, transaction *firestore.Transaction) error {
		snapshot, err := transaction.Get(docRef)
		if err != nil {
			return fmt.Errorf("read nonce ledger record for abandonment: %w", err)
		}
		current, err := decodeDocument(snapshot)
		if err != nil {
			return err
		}
		if current.Status != StatusSigning || current.PayloadSHA256 != abandonment.PayloadSHA256 || current.AttemptID != abandonment.AttemptID {
			return ErrConflict
		}
		return transaction.Update(docRef, []firestore.Update{
			{Path: "status", Value: StatusAbandoned},
			{Path: "abandoned_at", Value: abandonment.AbandonedAt.UTC()},
			{Path: "failure_code", Value: abandonment.FailureCode},
		})
	}, firestore.MaxAttempts(5))
}

func decodeDocument(snapshot *firestore.DocumentSnapshot) (document, error) {
	data := snapshot.Data()
	if len(data) != len(ledgerFields) {
		return document{}, ErrCorrupt
	}
	for field := range data {
		if _, ok := ledgerFields[field]; !ok {
			return document{}, ErrCorrupt
		}
	}
	var result document
	if err := snapshot.DataTo(&result); err != nil {
		return document{}, fmt.Errorf("decode nonce ledger record: %w", err)
	}
	if result.SchemaVersion != ledgerSchemaVersion || !noncePattern.MatchString(result.Nonce) || !noncePattern.MatchString(result.IntentSHA256) {
		return document{}, ErrCorrupt
	}
	if result.Kind != KindProduction && result.Kind != KindPreflight {
		return document{}, ErrCorrupt
	}
	switch result.Status {
	case StatusIssued:
		if result.PayloadSHA256 != "" || result.AttemptID != "" || result.SignatureSHA256 != "" || result.FailureCode != "" || result.SigningAt != nil || result.CommittedAt != nil || result.AbandonedAt != nil {
			return document{}, ErrCorrupt
		}
	case StatusSigning:
		if !noncePattern.MatchString(result.PayloadSHA256) || !identifierPattern.MatchString(result.AttemptID) || result.SignatureSHA256 != "" || result.FailureCode != "" || result.SigningAt == nil || result.CommittedAt != nil || result.AbandonedAt != nil {
			return document{}, ErrCorrupt
		}
	case StatusCommitted:
		if !noncePattern.MatchString(result.PayloadSHA256) || !noncePattern.MatchString(result.SignatureSHA256) || !identifierPattern.MatchString(result.AttemptID) || result.SigningAt == nil || result.CommittedAt == nil || result.AbandonedAt != nil || result.FailureCode != "" {
			return document{}, ErrCorrupt
		}
	case StatusAbandoned:
		if !noncePattern.MatchString(result.PayloadSHA256) || !identifierPattern.MatchString(result.AttemptID) || result.SignatureSHA256 != "" || result.SigningAt == nil || result.AbandonedAt == nil || result.CommittedAt != nil || !identifierPattern.MatchString(result.FailureCode) {
			return document{}, ErrCorrupt
		}
	default:
		return document{}, ErrCorrupt
	}
	if !result.ExpiresAt.After(result.IssuedAt) {
		return document{}, ErrCorrupt
	}
	return result, nil
}

func validateIssue(issue Issue) error {
	if !noncePattern.MatchString(issue.Nonce) || !noncePattern.MatchString(issue.IntentSHA256) {
		return errors.New("ledger issue nonce and intent digest must be lowercase SHA-256")
	}
	if issue.Kind != KindProduction && issue.Kind != KindPreflight {
		return errors.New("ledger issue kind is invalid")
	}
	if !issue.ExpiresAt.After(issue.IssuedAt) {
		return errors.New("ledger issue expiry must follow issuance")
	}
	return nil
}

func validateClaim(claim Claim) error {
	if !noncePattern.MatchString(claim.Nonce) || !noncePattern.MatchString(claim.IntentSHA256) || !noncePattern.MatchString(claim.PayloadSHA256) || !identifierPattern.MatchString(claim.AttemptID) {
		return errors.New("ledger claim fields are invalid")
	}
	if claim.Kind != KindProduction && claim.Kind != KindPreflight {
		return errors.New("ledger claim kind is invalid")
	}
	return nil
}

func validateCompletion(completion Completion) error {
	if !noncePattern.MatchString(completion.Nonce) || !noncePattern.MatchString(completion.PayloadSHA256) || !noncePattern.MatchString(completion.SignatureSHA256) || !identifierPattern.MatchString(completion.AttemptID) {
		return errors.New("ledger completion fields are invalid")
	}
	return nil
}

func validateAbandonment(abandonment Abandonment) error {
	if !noncePattern.MatchString(abandonment.Nonce) || !noncePattern.MatchString(abandonment.PayloadSHA256) || !identifierPattern.MatchString(abandonment.AttemptID) || !identifierPattern.MatchString(abandonment.FailureCode) {
		return errors.New("ledger abandonment fields are invalid")
	}
	return nil
}
