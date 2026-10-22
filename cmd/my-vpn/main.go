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

	var deviceProvisioner provision.Provisioner
	switch configuration.ProvisionerMode {
	case "noop":
		deviceProvisioner = provision.Noop{}
	case "vless-reality":
		deviceProvisioner = provision.NewReality()
	default:
		logger.Error("unsupported provisioner mode")
		os.Exit(1)
	}
	application := service.New(database, deviceProvisioner, configuration.InviteHMACKey, configuration.PublicBaseURL)
	api := httpapi.New(application, database, configuration.AdminAPIToken, configuration.WebRoot, configuration.InviteTTL)
	server := &http.Server{
		Addr: configuration.ListenAddr, Handler: api.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if configuration.TelegramBotToken != "" {
		bot, err := telegram.New(telegram.Config{
			Token: configuration.TelegramBotToken, Admins: configuration.TelegramAdmins,
			Application: telegramAdapter{service: application, store: database, provisionerMode: configuration.ProvisionerMode},
			OffsetStore: telegram.FileOffsetStore{Path: configuration.TelegramOffsetPath},
		})
		if err != nil {
			logger.Error("Telegram configuration rejected", "error", err)
			os.Exit(1)
		}
		go func() {
			if err := bot.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("Telegram transport stopped", "error", err)
				stop()
			}
		}()
	}
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
