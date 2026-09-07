package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/kms/apiv1"

	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/config"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/ledger"
	collectorserver "github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/server"
	"github.com/billziss-gh/cfw-rs/tools/physical-collector/internal/signing"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	shutdownTimeout   = 15 * time.Second
	maxHeaderBytes    = 16 * 1024
)

func main() {
	if err := run(); err != nil {
		slog.Error("physical collector terminated", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configValue, err := config.Load()
	if err != nil {
		return fmt.Errorf("load fail-closed configuration: %w", err)
	}
	rootContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	firestoreClient, err := firestore.NewClientWithDatabase(
		rootContext,
		configValue.ProjectID,
		configValue.FirestoreDatabase,
	)
	if err != nil {
		return fmt.Errorf("create Firestore client: %w", err)
	}
	defer func() {
		if err := firestoreClient.Close(); err != nil {
			slog.Error("Firestore client close failed", "error", err)
		}
	}()
	ledgerStore, err := ledger.NewFirestore(firestoreClient)
	if err != nil {
		return err
	}

	var receiptSigner signing.Signer
	var kmsClient *kms.KeyManagementClient
	if configValue.Role == config.RoleReceiptSigner {
		kmsClient, err = kms.NewKeyManagementClient(rootContext)
		if err != nil {
			return fmt.Errorf("create Cloud KMS client: %w", err)
		}
		defer func() {
			if err := kmsClient.Close(); err != nil {
				slog.Error("Cloud KMS client close failed", "error", err)
			}
		}()
		receiptSigner, err = signing.NewKMS(kmsClient, configValue.KMSKeyVersion, configValue.PublicKey)
		if err != nil {
			return err
		}
	}

	handler, err := collectorserver.New(configValue, ledgerStore, receiptSigner)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", configValue.Port),
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	serveError := make(chan error, 1)
	go func() {
		serveError <- server.ListenAndServe()
	}()
	slog.Info(
		"physical collector control plane started",
		"role", configValue.Role,
		"production_receipts_enabled", configValue.ProductionReceiptsEnabled,
	)

	select {
	case err := <-serveError:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	case <-rootContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("graceful HTTP shutdown: %w", err)
		}
		if err := <-serveError; !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("HTTP server stopped unexpectedly: %w", err)
		}
		return nil
	}
}
