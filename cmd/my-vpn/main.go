package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Almaz03/my-vpn/internal/config"
	"github.com/Almaz03/my-vpn/internal/httpapi"
	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/service"
	"github.com/Almaz03/my-vpn/internal/store"
	"github.com/Almaz03/my-vpn/internal/telegram"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configuration, err := config.Load()
	if err != nil {
		logger.Error("configuration rejected", "error", err)
		os.Exit(1)
	}
	database, err := store.Open(configuration.DatabasePath)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	// Constructing the allowlist here makes the authorization boundary explicit.
	// A Telegram polling transport is intentionally deferred until its commands
	// can use the same audited service methods without returning VPN credentials.
	_ = telegram.NewAllowlist(configuration.TelegramAdmins)
	application := service.New(database, provision.Noop{}, configuration.InviteHMACKey, configuration.PublicBaseURL)
	api := httpapi.New(application, database, configuration.AdminAPIToken, configuration.WebRoot, configuration.InviteTTL)
	server := &http.Server{
		Addr: configuration.ListenAddr, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	logger.Info("server starting", "address", configuration.ListenAddr, "provisioner", configuration.ProvisionerMode)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped unexpectedly", "error", err)
		os.Exit(1)
	}
}
