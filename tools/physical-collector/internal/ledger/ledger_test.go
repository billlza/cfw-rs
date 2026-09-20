package ledger

import (
	"strings"
	"testing"
	"time"
)

func TestLedgerInputValidationRejectsMalformedTransitions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name string
		err  error
	}{
		{name: "invalid-issue-kind", err: validateIssue(Issue{Nonce: digest, Kind: "attacker", IntentSHA256: digest, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})},
		{name: "expired-at-issue", err: validateIssue(Issue{Nonce: digest, Kind: KindProduction, IntentSHA256: digest, IssuedAt: now, ExpiresAt: now})},
		{name: "invalid-claim-attempt", err: validateClaim(Claim{Nonce: digest, Kind: KindProduction, IntentSHA256: digest, PayloadSHA256: digest, AttemptID: "bad/attempt", ClaimedAt: now})},
		{name: "invalid-completion-signature", err: validateCompletion(Completion{Nonce: digest, PayloadSHA256: digest, AttemptID: "attempt-1", SignatureSHA256: "short", CompletedAt: now})},
		{name: "invalid-abandonment-code", err: validateAbandonment(Abandonment{Nonce: digest, PayloadSHA256: digest, AttemptID: "attempt-1", FailureCode: "bad/code", AbandonedAt: now})},
	}
	for _, test := range tests {
		if test.err == nil {
			t.Errorf("%s was accepted", test.name)
		}
	}
}

func TestLedgerStateNamesAreClosed(t *testing.T) {
	t.Parallel()
	states := []string{StatusIssued, StatusSigning, StatusCommitted, StatusAbandoned}
	want := []string{"ISSUED", "SIGNING", "COMMITTED", "ABANDONED"}
	for index := range states {
		if states[index] != want[index] {
			t.Fatalf("ledger state %d is %q, expected %q", index, states[index], want[index])
		}
	}
}
