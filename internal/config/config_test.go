package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadRejectsTelegramTokenWithoutAdmins(t *testing.T) {
	t.Setenv("INVITE_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("ADMIN_API_TOKEN", strings.Repeat("a", 24))
	t.Setenv("TELEGRAM_BOT_TOKEN", "not-a-real-token")
	t.Setenv("TELEGRAM_ADMIN_IDS", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted Telegram token without administrator allowlist")
	}
}

func TestLoadAcceptsSafeMinimum(t *testing.T) {
	t.Setenv("INVITE_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("ADMIN_API_TOKEN", strings.Repeat("a", 24))
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_ADMIN_IDS", "")
	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ListenAddr != "127.0.0.1:8080" || configuration.ProvisionerMode != "noop" ||
		configuration.TelegramOffsetPath != "/var/lib/my-vpn/telegram-offset" {
		t.Fatalf("unexpected defaults: %#v", configuration)
	}
}

func TestLoadAcceptsAmneziaWGMode(t *testing.T) {
	t.Setenv("INVITE_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("ADMIN_API_TOKEN", strings.Repeat("a", 24))
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_ADMIN_IDS", "")
	t.Setenv("PROVISIONER_MODE", "amneziawg")
	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ProvisionerMode != "amneziawg" {
		t.Fatalf("mode=%q", configuration.ProvisionerMode)
	}
}

func TestLoadRejectsUnknownProvisionerMode(t *testing.T) {
	t.Setenv("INVITE_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("ADMIN_API_TOKEN", strings.Repeat("a", 24))
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_ADMIN_IDS", "")
	t.Setenv("PROVISIONER_MODE", "shell")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted unknown provisioner")
	}
}
