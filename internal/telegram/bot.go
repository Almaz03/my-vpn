package telegram

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	defaultInviteTTL = 10 * time.Minute
	maxTelegramText  = 4000
)

// Application deliberately exposes no VPN credentials, configuration bodies,
// or import URLs to the Telegram transport.
type Application interface {
	CreateInvitation(ctx context.Context, relativeName, deviceName string, ttl time.Duration) (Invitation, error)
	ListDevices(ctx context.Context) ([]Device, error)
	RevokeDevice(ctx context.Context, id string) error
	SystemStatus(ctx context.Context) (SystemStatus, error)
}

type Invitation struct {
	Code      string
	ExpiresAt time.Time
}

type Device struct {
	ID           string
	RelativeName string
	DeviceName   string
	Platform     string
	State        string
	Revoked      bool
}

type SystemStatus struct {
	Portal      string
	VPN         string
	Certificate string
	CPU         string
	Memory      string
	Disk        string
	Network     string
}

type Bot struct {
	api       *apiClient
	app       Application
	allowlist Allowlist
	offsets   OffsetStore
	sleep     func(context.Context, time.Duration) error
}

type Config struct {
	Token       string
	APIBaseURL  string
	HTTPClient  HTTPDoer
	Admins      []int64
	Application Application
	OffsetStore OffsetStore
	PollTimeout time.Duration
}

func New(config Config) (*Bot, error) {
	if strings.TrimSpace(config.Token) == "" {
		return nil, errors.New("telegram token is required")
	}
	if config.Application == nil {
		return nil, errors.New("telegram application is required")
	}
	allowlist := NewAllowlist(config.Admins)
	if len(allowlist) == 0 {
		return nil, errors.New("at least one Telegram administrator is required")
	}
	store := config.OffsetStore
	if store == nil {
		store = NewMemoryOffsetStore()
	}
	client, err := newAPIClient(config.Token, config.APIBaseURL, config.HTTPClient, config.PollTimeout)
	if err != nil {
		return nil, err
	}
	return &Bot{api: client, app: config.Application, allowlist: allowlist, offsets: store, sleep: sleepContext}, nil
}

// Run performs Telegram long polling until ctx is cancelled. Transient errors
// are retried with bounded exponential backoff.
func (b *Bot) Run(ctx context.Context) error {
	offset, err := b.offsets.Load(ctx)
	if err != nil {
		return fmt.Errorf("load Telegram offset: %w", err)
	}
	backoff := time.Second
	for {
		updates, err := b.api.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if err := b.sleep(ctx, backoff); err != nil {
				return nil
			}
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		for _, update := range updates {
			if update.ID < offset {
				continue
			}
			next := update.ID + 1
			// Advance before dispatch. Repeating a side-effecting /invite after a
			// crash is less safe than asking the administrator to retry once.
			if err := b.offsets.Save(ctx, next); err != nil {
				return fmt.Errorf("save Telegram offset: %w", err)
			}
			offset = next
			_ = b.handleUpdate(ctx, update)
		}
	}
}

func (b *Bot) handleUpdate(ctx context.Context, update apiUpdate) error {
	if update.Callback != nil {
		return b.handleCallback(ctx, *update.Callback)
	}
	if update.Message == nil || update.Message.From == nil {
		return nil
	}
	message := update.Message
	if !b.allowlist.Authorized(message.From.ID) {
		return b.api.sendMessage(ctx, message.Chat.ID, "Команда недоступна.", nil)
	}
	command, argument := splitCommand(message.Text)
	switch command {
	case "/start", "/help":
		return b.api.sendMessage(ctx, message.Chat.ID, helpText(), nil)
	case "/invite", "/new":
		return b.createInvitation(ctx, message.Chat.ID, argument)
	case "/devices":
		return b.listDevices(ctx, message.Chat.ID)
	case "/revoke":
		return b.revokeDevice(ctx, message.Chat.ID, strings.TrimSpace(argument), "")
	case "/status":
		return b.status(ctx, message.Chat.ID)
	default:
		return b.api.sendMessage(ctx, message.Chat.ID, helpText(), nil)
	}
}

func (b *Bot) handleCallback(ctx context.Context, callback apiCallbackQuery) error {
	if callback.From == nil || !b.allowlist.Authorized(callback.From.ID) {
		return b.api.answerCallback(ctx, callback.ID, "Команда недоступна.")
	}
	if callback.Message == nil || !strings.HasPrefix(callback.Data, "revoke:") {
		return b.api.answerCallback(ctx, callback.ID, "Некорректное действие.")
	}
	id := strings.TrimPrefix(callback.Data, "revoke:")
	if err := validateDeviceID(id); err != nil {
		return b.api.answerCallback(ctx, callback.ID, "Некорректное устройство.")
	}
	return b.revokeDevice(ctx, callback.Message.Chat.ID, id, callback.ID)
}

func (b *Bot) createInvitation(ctx context.Context, chatID int64, argument string) error {
	parts := strings.Split(argument, "|")
	if len(parts) < 2 || len(parts) > 3 {
		return b.api.sendMessage(ctx, chatID, "Формат: /invite Имя родственника | Устройство | 10", nil)
	}
	relativeName := strings.TrimSpace(parts[0])
	deviceName := strings.TrimSpace(parts[1])
	ttl := defaultInviteTTL
	if len(parts) == 3 {
		minutes, err := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err != nil || minutes < 1 || minutes > 60 {
			return b.api.sendMessage(ctx, chatID, "Срок должен быть от 1 до 60 минут.", nil)
		}
		ttl = time.Duration(minutes) * time.Minute
	}
	if relativeName == "" || deviceName == "" || len([]rune(relativeName)) > 100 || len([]rune(deviceName)) > 100 {
		return b.api.sendMessage(ctx, chatID, "Имя родственника и устройства должны содержать от 1 до 100 символов.", nil)
	}
	invitation, err := b.app.CreateInvitation(ctx, relativeName, deviceName, ttl)
	if err != nil {
		return b.api.sendMessage(ctx, chatID, "Не удалось создать приглашение. Повторите позже.", nil)
	}
	expires := invitation.ExpiresAt.In(time.Local).Format("15:04:05")
	message := fmt.Sprintf("Одноразовый код: %s\nДействует до: %s\nПередайте родственнику только этот код.", invitation.Code, expires)
	return b.api.sendMessage(ctx, chatID, message, nil)
}

func (b *Bot) listDevices(ctx context.Context, chatID int64) error {
	devices, err := b.app.ListDevices(ctx)
	if err != nil {
		return b.api.sendMessage(ctx, chatID, "Не удалось получить список устройств.", nil)
	}
	if len(devices) == 0 {
		return b.api.sendMessage(ctx, chatID, "Устройств пока нет.", nil)
	}
	for _, device := range devices {
		state := safeField(device.State)
		if device.Revoked {
			state = "revoked"
		}
		text := fmt.Sprintf("%s — %s\nПлатформа: %s\nСостояние: %s\nID: %s",
			safeField(device.RelativeName), safeField(device.DeviceName), safeField(device.Platform), state, safeField(device.ID))
		var keyboard *inlineKeyboard
		if !device.Revoked && validateDeviceID(device.ID) == nil {
			keyboard = &inlineKeyboard{InlineKeyboard: [][]inlineButton{{{
				Text: "Отозвать устройство", CallbackData: "revoke:" + device.ID,
			}}}}
		}
		if err := b.api.sendMessage(ctx, chatID, truncate(text), keyboard); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bot) revokeDevice(ctx context.Context, chatID int64, id, callbackID string) error {
	if err := validateDeviceID(id); err != nil {
		if callbackID != "" {
			return b.api.answerCallback(ctx, callbackID, "Некорректное устройство.")
		}
		return b.api.sendMessage(ctx, chatID, "Формат: /revoke ID", nil)
	}
	if err := b.app.RevokeDevice(ctx, id); err != nil {
		if callbackID != "" {
			return b.api.answerCallback(ctx, callbackID, "Не удалось отозвать устройство.")
		}
		return b.api.sendMessage(ctx, chatID, "Не удалось отозвать устройство.", nil)
	}
	if callbackID != "" {
		if err := b.api.answerCallback(ctx, callbackID, "Устройство отозвано."); err != nil {
			return err
		}
	}
	return b.api.sendMessage(ctx, chatID, "Устройство отозвано: "+id, nil)
}

func (b *Bot) status(ctx context.Context, chatID int64) error {
	status, err := b.app.SystemStatus(ctx)
	if err != nil {
		return b.api.sendMessage(ctx, chatID, "Не удалось получить состояние системы.", nil)
	}
	message := fmt.Sprintf("Портал: %s\nVPN: %s\nСертификат: %s\nCPU: %s\nRAM: %s\nДиск: %s\nСеть: %s",
		safeField(status.Portal), safeField(status.VPN), safeField(status.Certificate), safeField(status.CPU),
		safeField(status.Memory), safeField(status.Disk), safeField(status.Network))
	return b.api.sendMessage(ctx, chatID, truncate(message), nil)
}

func splitCommand(text string) (string, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", ""
	}
	fields := strings.Fields(text)
	command := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0])
	argument := strings.TrimSpace(strings.TrimPrefix(text, fields[0]))
	return command, argument
}

func helpText() string {
	return "Команды:\n/invite Имя | Устройство | 10 — создать код\n/devices — список устройств\n/revoke ID — отозвать устройство\n/status — состояние сервиса"
}

func validateDeviceID(id string) error {
	if len(id) < 8 || len(id) > 128 {
		return errors.New("invalid device id")
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return errors.New("invalid device id")
		}
	}
	return nil
}

func safeField(value string) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\x00' {
			return ' '
		}
		return r
	}, value))
	if value == "" {
		return "—"
	}
	return value
}

func truncate(value string) string {
	runes := []rune(value)
	if len(runes) <= maxTelegramText {
		return value
	}
	return string(runes[:maxTelegramText-1]) + "…"
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
