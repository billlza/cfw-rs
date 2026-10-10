package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/config"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/contract"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/ledger"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/signing"
)

const (
	productionNonceTTL = 6 * time.Hour
	preflightNonceTTL  = 10 * time.Minute
	preflightChallenge = "cfw-physical-collector-kms-preflight-v1"
)

type Service struct {
	config config.Config
	ledger ledger.Store
	signer signing.Signer
	random io.Reader
	now    func() time.Time
	mux    *http.ServeMux
}

type errorResponse struct {
	Error apiErrorBody `json:"error"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func New(configValue config.Config, store ledger.Store, signer signing.Signer) (*Service, error) {
	if store == nil {
		return nil, errors.New("nonce ledger is nil")
	}
	if configValue.Role == config.RoleReceiptSigner && signer == nil {
		return nil, errors.New("receipt-signer role requires a signer")
	}
	service := &Service{
		config: configValue,
		ledger: store,
		signer: signer,
		random: rand.Reader,
		now:    func() time.Time { return time.Now().UTC() },
		mux:    http.NewServeMux(),
	}
	service.routes()
	return service, nil
}

func (service *Service) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	service.mux.ServeHTTP(writer, request)
}

func (service *Service) routes() {
	// Cloud Run reserves request paths ending in "z", so the externally
	// verifiable health endpoint must not use the conventional /healthz name.
	service.mux.HandleFunc("/health", service.health)
	switch service.config.Role {
	case config.RoleNonceIssuer:
		service.mux.HandleFunc("/v1/nonces", service.issueNonce)
	case config.RoleReceiptSigner:
		service.mux.HandleFunc("/v1/receipts", service.signReceipt)
		service.mux.HandleFunc("/v1/preflight", service.preflight)
	}
}

func (service *Service) health(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer, http.MethodGet)
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest, "invalid_request", "query parameters are not accepted")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (service *Service) issueNonce(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !service.config.ProductionReceiptsEnabled {
		writeError(writer, http.StatusServiceUnavailable, "production_disabled", "production receipt issuance is disabled")
		return
	}
	var body contract.NonceRequest
	if err := decodeRequest(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request does not match the exact nonce schema")
		return
	}
	if err := contract.ValidateNonceRequest(body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request does not satisfy the source-pinned release contract")
		return
	}
	intent := contract.IntentFromNonceRequest(body, service.config.Binding())
	intentSHA256, err := contract.HashCanonical(intent)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "canonical intent construction failed")
		return
	}
	nonce, err := service.randomHex(32)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "entropy_unavailable", "secure nonce generation failed")
		return
	}
	issuedAt := service.now().UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(productionNonceTTL)
	if err := service.ledger.Issue(request.Context(), ledger.Issue{
		Nonce: nonce, Kind: ledger.KindProduction, IntentSHA256: intentSHA256,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ledger_unavailable", "nonce issuance failed closed")
		return
	}
	writeJSON(writer, http.StatusCreated, contract.NonceResponse{
		SchemaVersion: contract.RequestSchemaVersion,
		RunNonce:      nonce,
		ExpiresAt:     expiresAt.Format(time.RFC3339),
	})
}

func (service *Service) signReceipt(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if !service.config.ProductionReceiptsEnabled {
		writeError(writer, http.StatusServiceUnavailable, "production_disabled", "production receipt signing is disabled")
		return
	}
	var body contract.ReceiptRequest
	if err := decodeRequest(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request does not match the exact receipt schema")
		return
	}
	signedAt := service.now().UTC().Truncate(time.Second)
	payload, err := contract.BuildReceiptPayload(body, service.config.Binding(), signedAt)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "request does not satisfy the source-pinned receipt-v3 contract")
		return
	}
	payloadBytes, err := contract.CanonicalJSON(payload)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "canonical receipt construction failed")
		return
	}
	payloadDigest := sha256.Sum256(payloadBytes)
	payloadSHA256 := hex.EncodeToString(payloadDigest[:])
	intent := contract.IntentFromReceiptRequest(body, service.config.Binding())
	intentSHA256, err := contract.HashCanonical(intent)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "canonical intent construction failed")
		return
	}
	attemptID, err := service.randomHex(16)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "entropy_unavailable", "secure signing-attempt generation failed")
		return
	}
	claim := ledger.Claim{
		Nonce: body.Run.RunNonce, Kind: ledger.KindProduction,
		IntentSHA256: intentSHA256, PayloadSHA256: payloadSHA256,
		AttemptID: attemptID, ClaimedAt: signedAt,
	}
	if err := service.ledger.Claim(request.Context(), claim); err != nil {
		writeError(writer, http.StatusConflict, "nonce_unavailable", "nonce is absent, expired, mismatched, or already consumed")
		return
	}

	signature, err := service.signer.Sign(request.Context(), payloadBytes)
	if err != nil {
		if abandonErr := service.abandon(request, claim, "kms_ambiguous"); abandonErr != nil {
			writeError(writer, http.StatusServiceUnavailable, "ledger_ambiguous", "signing and ledger state are ambiguous; automatic re-sign is forbidden")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "signing_ambiguous", "signing failed closed; automatic re-sign is forbidden")
		return
	}
	signatureDigest := sha256.Sum256(signature)
	signatureSHA256 := hex.EncodeToString(signatureDigest[:])
	if err := service.ledger.Commit(request.Context(), ledger.Completion{
		Nonce: claim.Nonce, PayloadSHA256: claim.PayloadSHA256,
		AttemptID: claim.AttemptID, SignatureSHA256: signatureSHA256,
		CompletedAt: service.now().UTC().Truncate(time.Second),
	}); err != nil {
		if abandonErr := service.abandon(request, claim, "commit_ambiguous"); abandonErr != nil {
			writeError(writer, http.StatusServiceUnavailable, "ledger_ambiguous", "signature commit state is ambiguous; automatic re-sign is forbidden")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "commit_ambiguous", "signature was not durably committed; automatic re-sign is forbidden")
		return
	}
	writeJSON(writer, http.StatusOK, contract.ReceiptResponse{
		SchemaVersion: contract.RequestSchemaVersion,
		SignedAt:      payload.Run.SignedAt,
		ReceiptSHA256: payloadSHA256,
		Signature:     base64.RawURLEncoding.EncodeToString(signature),
	})
}

func (service *Service) preflight(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodPost)
		return
	}
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest, "invalid_request", "query parameters are not accepted")
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeError(writer, http.StatusUnsupportedMediaType, "invalid_request", "content encoding is not accepted")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, 1))
	if err != nil || len(body) != 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "preflight request body must be empty")
		return
	}
	now := service.now().UTC().Truncate(time.Second)
	nonce, err := service.randomHex(32)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "entropy_unavailable", "secure preflight nonce generation failed")
		return
	}
	challenge := []byte(preflightChallenge)
	challengeDigest := sha256.Sum256(challenge)
	challengeSHA256 := hex.EncodeToString(challengeDigest[:])
	intent := struct {
		Kind            string                 `json:"kind"`
		ChallengeSHA256 string                 `json:"challenge_sha256"`
		Binding         contract.ServerBinding `json:"binding"`
	}{Kind: ledger.KindPreflight, ChallengeSHA256: challengeSHA256, Binding: service.config.Binding()}
	intentSHA256, err := contract.HashCanonical(intent)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "canonical preflight intent failed")
		return
	}
	if err := service.ledger.Issue(request.Context(), ledger.Issue{
		Nonce: nonce, Kind: ledger.KindPreflight, IntentSHA256: intentSHA256,
		IssuedAt: now, ExpiresAt: now.Add(preflightNonceTTL),
	}); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ledger_unavailable", "preflight ledger issue failed closed")
		return
	}
	attemptID, err := service.randomHex(16)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "entropy_unavailable", "secure preflight attempt generation failed")
		return
	}
	claim := ledger.Claim{
		Nonce: nonce, Kind: ledger.KindPreflight, IntentSHA256: intentSHA256,
		PayloadSHA256: challengeSHA256, AttemptID: attemptID, ClaimedAt: now,
	}
	if err := service.ledger.Claim(request.Context(), claim); err != nil {
		writeError(writer, http.StatusServiceUnavailable, "ledger_unavailable", "preflight ledger claim failed closed")
		return
	}
	signature, err := service.signer.Sign(request.Context(), challenge)
	if err != nil {
		if abandonErr := service.abandon(request, claim, "kms_ambiguous"); abandonErr != nil {
			writeError(writer, http.StatusServiceUnavailable, "ledger_ambiguous", "preflight signing and ledger state are ambiguous; automatic re-sign is forbidden")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "signing_ambiguous", "preflight signing failed closed; automatic re-sign is forbidden")
		return
	}
	signatureDigest := sha256.Sum256(signature)
	signatureSHA256 := hex.EncodeToString(signatureDigest[:])
	if err := service.ledger.Commit(request.Context(), ledger.Completion{
		Nonce: nonce, PayloadSHA256: challengeSHA256, AttemptID: attemptID,
		SignatureSHA256: signatureSHA256, CompletedAt: service.now().UTC().Truncate(time.Second),
	}); err != nil {
		if abandonErr := service.abandon(request, claim, "commit_ambiguous"); abandonErr != nil {
			writeError(writer, http.StatusServiceUnavailable, "ledger_ambiguous", "preflight commit state is ambiguous; automatic re-sign is forbidden")
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "commit_ambiguous", "preflight signature was not committed; automatic re-sign is forbidden")
		return
	}
	writeJSON(writer, http.StatusOK, contract.PreflightResponse{
		SchemaVersion:   contract.RequestSchemaVersion,
		ChallengeSHA256: challengeSHA256,
		SignatureSHA256: signatureSHA256,
		Signature:       base64.RawURLEncoding.EncodeToString(signature),
		KeyVersion:      service.config.KMSKeyVersion,
		LedgerState:     ledger.StatusCommitted,
	})
}

func (service *Service) abandon(request *http.Request, claim ledger.Claim, failureCode string) error {
	// Any KMS or post-KMS uncertainty burns the nonce. A detached bounded context
	// lets the ledger record the terminal state even if the caller disconnects.
	// If the update is itself ambiguous, the record cannot return to ISSUED and
	// automatic re-sign remains forbidden.
	abandonContext, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
	defer cancel()
	if err := service.ledger.Abandon(abandonContext, ledger.Abandonment{
		Nonce: claim.Nonce, PayloadSHA256: claim.PayloadSHA256,
		AttemptID: claim.AttemptID, FailureCode: failureCode,
		AbandonedAt: service.now().UTC().Truncate(time.Second),
	}); err != nil {
		return fmt.Errorf("abandon ambiguous signing attempt: %w", err)
	}
	return nil
}

func (service *Service) randomHex(byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := io.ReadFull(service.random, buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func decodeRequest(writer http.ResponseWriter, request *http.Request, target any) error {
	if request.URL.RawQuery != "" {
		return errors.New("query parameters are not accepted")
	}
	if request.Header.Get("Content-Encoding") != "" {
		return errors.New("content encoding is not accepted")
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	for name, value := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(value, "utf-8") {
			return errors.New("Content-Type parameter is not accepted")
		}
	}
	if request.ContentLength > contract.MaxRequestBytes {
		return fmt.Errorf("request exceeds %d bytes", contract.MaxRequestBytes)
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, contract.MaxRequestBytes))
	if err != nil {
		return err
	}
	return contract.DecodeExact(body, target)
}

func methodNotAllowed(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed", "HTTP method is not allowed")
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, errorResponse{Error: apiErrorBody{Code: code, Message: message}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoded, err := json.Marshal(value)
	if err != nil {
		slog.Error("JSON response encoding failed", "error_type", fmt.Sprintf("%T", err))
		http.Error(writer, "internal response encoding error", http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(status)
	if _, err := writer.Write(append(encoded, '\n')); err != nil {
		slog.Warn("HTTP response write failed", "error_type", fmt.Sprintf("%T", err))
	}
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}
