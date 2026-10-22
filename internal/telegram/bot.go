package telegram

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
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
	ApproveAccessRequest(ctx context.Context, id string) (Invitation, error)
	DenyAccessRequest(ctx context.Context, id string) error
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
	api         *apiClient
	app         Application
	allowlist   Allowlist
	offsets     OffsetStore
	admins      []int64
	sleep       func(context.Context, time.Duration) error
	inviteMu    sync.Mutex
	awaitInvite map[int64]bool
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
	admins := append([]int64(nil), config.Admins...)
	return &Bot{
		api: client, app: config.Application, allowlist: allowlist, admins: admins,
		offsets: store, sleep: sleepContext, awaitInvite: make(map[int64]bool),
	}, nil
}

func (b *Bot) NotifyAccessRequest(ctx context.Context, id, relativeName, deviceName, platform string, expiresAt time.Time) error {
	if validateDeviceID(id) != nil {
		return errors.New("invalid access request id")
	}
	text := fmt.Sprintf("Запрос доступа\nИмя: %s\nУстройство: %s\nПлатформа: %s\nОдобрить до: %s",
		safeField(relativeName), safeField(deviceName), safeField(platform), expiresAt.In(time.Local).Format("15:04:05"))
	keyboard := &inlineKeyboard{InlineKeyboard: [][]inlineButton{{
		{Text: "✅ Одобрить", CallbackData: "access-approve:" + id},
		{Text: "❌ Отклонить", CallbackData: "access-deny:" + id},
	}}}
	for _, chatID := range b.admins {
		if err := b.api.sendMessage(ctx, chatID, text, keyboard); err != nil {
			return err
		}
	}
	return nil
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
	if b.takeInvitePrompt(message.Chat.ID, message.Text) {
		return b.createInvitation(ctx, message.Chat.ID, message.Text)
	}
	command, argument := splitCommand(message.Text)
	switch command {
	case "/start", "/help":
		return b.api.sendMessage(ctx, message.Chat.ID, helpText(), mainMenu())
	case "/invite", "/new":
		if strings.TrimSpace(argument) == "" {
			b.setInvitePrompt(message.Chat.ID)
			return b.api.sendMessage(ctx, message.Chat.ID, "Отправь одним сообщением:\nИмя | Устройство | 10\n\n10 — срок действия кода в минутах.", mainMenu())
		}
		return b.createInvitation(ctx, message.Chat.ID, argument)
	case "/devices":
		return b.listDevices(ctx, message.Chat.ID, false)
	case "/revoked":
		return b.listDevices(ctx, message.Chat.ID, true)
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
	if callback.Message == nil {
		return b.api.answerCallback(ctx, callback.ID, "Некорректное действие.")
	}
	if strings.HasPrefix(callback.Data, "access-approve:") {
		return b.decideAccessRequest(ctx, callback, true)
	}
	if strings.HasPrefix(callback.Data, "access-deny:") {
		return b.decideAccessRequest(ctx, callback, false)
	}
	if !strings.HasPrefix(callback.Data, "revoke:") {
		return b.api.answerCallback(ctx, callback.ID, "Некорректное действие.")
	}
	id := strings.TrimPrefix(callback.Data, "revoke:")
	if err := validateDeviceID(id); err != nil {
		return b.api.answerCallback(ctx, callback.ID, "Некорректное устройство.")
	}
	return b.revokeDevice(ctx, callback.Message.Chat.ID, id, callback.ID)
}

func (b *Bot) decideAccessRequest(ctx context.Context, callback apiCallbackQuery, approve bool) error {
	prefix := "access-deny:"
	if approve {
		prefix = "access-approve:"
	}
	id := strings.TrimPrefix(callback.Data, prefix)
	if validateDeviceID(id) != nil {
		return b.api.answerCallback(ctx, callback.ID, "Некорректный запрос.")
	}
	if !approve {
		if err := b.app.DenyAccessRequest(ctx, id); err != nil {
			return b.api.answerCallback(ctx, callback.ID, "Запрос уже обработан или истёк.")
		}
		if err := b.api.answerCallback(ctx, callback.ID, "Доступ отклонён."); err != nil {
			return err
		}
		return b.api.sendMessage(ctx, callback.Message.Chat.ID, "Запрос доступа отклонён.", nil)
	}
	invitation, err := b.app.ApproveAccessRequest(ctx, id)
	if err != nil {
		return b.api.answerCallback(ctx, callback.ID, "Не удалось одобрить: запрос истёк, уже обработан или устройство уже существует.")
	}
	if err := b.api.answerCallback(ctx, callback.ID, "Доступ одобрен."); err != nil {
		return err
	}
	expires := invitation.ExpiresAt.In(time.Local).Format("15:04:05")
	text := fmt.Sprintf("Доступ одобрен.\nКод подтверждения:\n%s\nДействует до: %s", invitation.Code, expires)
	keyboard := &inlineKeyboard{InlineKeyboard: [][]inlineButton{{{
		Text: "📋 Скопировать код", CopyText: &copyTextButton{Text: invitation.Code},
	}}}}
	return b.api.sendMessage(ctx, callback.Message.Chat.ID, text, keyboard)
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

func (b *Bot) listDevices(ctx context.Context, chatID int64, revokedOnly bool) error {
	devices, err := b.app.ListDevices(ctx)
	if err != nil {
		return b.api.sendMessage(ctx, chatID, "Не удалось получить список устройств.", nil)
	}
	filtered := make([]Device, 0, len(devices))
	for _, device := range devices {
		revoked := device.Revoked || device.State == "revoked"
		if revokedOnly == revoked && (revokedOnly || device.State == "active") {
			filtered = append(filtered, device)
		}
	}
	if len(filtered) == 0 {
		if revokedOnly {
			return b.api.sendMessage(ctx, chatID, "Отозванных устройств нет.", nil)
		}
		return b.api.sendMessage(ctx, chatID, "Активных устройств пока нет.", nil)
	}
	for _, device := range filtered {
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
	switch text {
	case "📱 Активные":
		return "/devices", ""
	case "🗑 Отозванные":
		return "/revoked", ""
	case "➕ Приглашение":
		return "/invite", ""
	case "📊 Статус":
		return "/status", ""
	}
	if text == "" {
		return "", ""
	}
	fields := strings.Fields(text)
	command := strings.ToLower(strings.SplitN(fields[0], "@", 2)[0])
	argument := strings.TrimSpace(strings.TrimPrefix(text, fields[0]))
	return command, argument
}

func helpText() string {
	return "Выбери действие кнопкой ниже.\n\nКоманды также доступны:\n/invite Имя | Устройство | 10\n/devices\n/revoked\n/revoke ID\n/status"
}

func mainMenu() *replyKeyboard {
	return &replyKeyboard{
		Keyboard: [][]replyButton{
			{{Text: "📱 Активные"}, {Text: "🗑 Отозванные"}},
			{{Text: "➕ Приглашение"}, {Text: "📊 Статус"}},
		},
		ResizeKeyboard: true, IsPersistent: true,
		InputPlaceholder: "Выберите действие",
	}
}

func (b *Bot) setInvitePrompt(chatID int64) {
	b.inviteMu.Lock()
	b.awaitInvite[chatID] = true
	b.inviteMu.Unlock()
}

func (b *Bot) takeInvitePrompt(chatID int64, text string) bool {
	trimmed := strings.TrimSpace(text)
	if strings.HasPrefix(trimmed, "/") {
		return false
	}
	if isMenuButton(trimmed) {
		if trimmed != "➕ Приглашение" {
			b.inviteMu.Lock()
			delete(b.awaitInvite, chatID)
			b.inviteMu.Unlock()
		}
		return false
	}
	b.inviteMu.Lock()
	defer b.inviteMu.Unlock()
	if !b.awaitInvite[chatID] {
		return false
	}
	delete(b.awaitInvite, chatID)
	return true
}

func isMenuButton(text string) bool {
	switch strings.TrimSpace(text) {
	case "📱 Активные", "🗑 Отозванные", "➕ Приглашение", "📊 Статус":
		return true
	default:
		return false
	}
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
