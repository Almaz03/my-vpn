package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr         string
	DatabasePath       string
	InviteHMACKey      []byte
	AdminAPIToken      string
	PublicBaseURL      *url.URL
	WebRoot            string
	ProvisionerMode    string
	TelegramBotToken   string
	TelegramAdmins     []int64
	TelegramOffsetPath string
	InviteTTL          time.Duration
}

func Load() (Config, error) {
	key, err := decodeKey(os.Getenv("INVITE_HMAC_KEY"))
	if err != nil {
		return Config{}, fmt.Errorf("INVITE_HMAC_KEY: %w", err)
	}
	adminToken := os.Getenv("ADMIN_API_TOKEN")
	if len(adminToken) < 24 {
		return Config{}, errors.New("ADMIN_API_TOKEN must contain at least 24 characters")
	}
	base, err := url.Parse(envOr("PUBLIC_BASE_URL", "https://vpn.akalmaz.tech"))
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		return Config{}, errors.New("PUBLIC_BASE_URL must be an absolute https URL without user info")
	}
	mode := envOr("PROVISIONER_MODE", "noop")
	if mode != "noop" && mode != "vless-reality" {
		return Config{}, fmt.Errorf("unsupported PROVISIONER_MODE %q", mode)
	}
	admins, err := parseAdmins(os.Getenv("TELEGRAM_ADMIN_IDS"))
	if err != nil {
		return Config{}, err
	}
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken != "" && len(admins) == 0 {
		return Config{}, errors.New("TELEGRAM_ADMIN_IDS is required when TELEGRAM_BOT_TOKEN is set")
	}
	return Config{
		ListenAddr:         envOr("APP_LISTEN", "127.0.0.1:8080"),
		DatabasePath:       envOr("APP_DB_PATH", "./data/my-vpn.db"),
		InviteHMACKey:      key,
		AdminAPIToken:      adminToken,
		PublicBaseURL:      base,
		WebRoot:            envOr("WEB_ROOT", "./web"),
		ProvisionerMode:    mode,
		TelegramBotToken:   botToken,
		TelegramAdmins:     admins,
		TelegramOffsetPath: envOr("TELEGRAM_OFFSET_PATH", "/var/lib/my-vpn/telegram-offset"),
		InviteTTL:          5 * time.Minute,
	}, nil
}

func decodeKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("is required (base64-encoded random value)")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, errors.New("must be valid standard base64")
	}
	if len(key) < sha256.Size {
		return nil, errors.New("must decode to at least 32 bytes")
	}
	return key, nil
}

func parseAdmins(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	ids := make([]int64, 0, len(parts))
	seen := make(map[int64]struct{}, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("TELEGRAM_ADMIN_IDS contains invalid id %q", part)
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
