package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeApplication struct {
	mu             sync.Mutex
	createCalls    int
	relativeName   string
	deviceName     string
	ttl            time.Duration
	devices        []Device
	revokedID      string
	status         SystemStatus
	traffic        []EdgeTraffic
	invitationCode string
	err            error
	approvedID     string
	deniedID       string
}

func (a *fakeApplication) CreateInvitation(_ context.Context, relativeName, deviceName string, ttl time.Duration) (Invitation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.createCalls++
	a.relativeName, a.deviceName, a.ttl = relativeName, deviceName, ttl
	if a.err != nil {
		return Invitation{}, a.err
	}
	return Invitation{Code: a.invitationCode, ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.Local)}, nil
}

func (a *fakeApplication) ListDevices(context.Context) ([]Device, error) {
	return a.devices, a.err
}

func (a *fakeApplication) RevokeDevice(_ context.Context, id string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revokedID = id
	return a.err
}

func (a *fakeApplication) SystemStatus(context.Context) (SystemStatus, error) {
	return a.status, a.err
}

func (a *fakeApplication) TrafficSummary(context.Context) ([]EdgeTraffic, error) {
	return a.traffic, a.err
}

func (a *fakeApplication) ApproveAccessRequest(_ context.Context, id string) (Invitation, error) {
	a.approvedID = id
	if a.err != nil {
		return Invitation{}, a.err
	}
	return Invitation{Code: a.invitationCode, ExpiresAt: time.Date(2030, 1, 2, 4, 5, 6, 0, time.Local)}, nil
}

func (a *fakeApplication) DenyAccessRequest(_ context.Context, id string) error {
	a.deniedID = id
	return a.err
}

type recordedRequest struct {
	method string
	body   map[string]any
}

func telegramServer(t *testing.T) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	requests := make([]recordedRequest, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requests = append(requests, recordedRequest{method: filepath.Base(r.URL.Path), body: body})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	return server, &requests
}

func newTestBot(t *testing.T, server *httptest.Server, app Application) *Bot {
	t.Helper()
	bot, err := New(Config{
		Token: "123456:test_token", APIBaseURL: server.URL, HTTPClient: server.Client(),
		Admins: []int64{42}, Application: app, PollTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return bot
}

func TestUnauthorizedUserGetsNeutralResponse(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{invitationCode: "SECRET-CODE"}
	bot := newTestBot(t, server, app)

	err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 7}, Chat: apiChat{ID: 9}, Text: "/invite Alice | Phone",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if app.createCalls != 0 {
		t.Fatal("unauthorized user reached application")
	}
	if len(*requests) != 1 || (*requests)[0].body["text"] != "Команда недоступна." {
		t.Fatalf("unexpected response: %#v", *requests)
	}
}

func TestInviteCommandCreatesShortLivedCode(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{invitationCode: "ABCD-EFGH"}
	bot := newTestBot(t, server, app)

	err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: "/invite Мама | iPhone | 12",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if app.createCalls != 1 || app.relativeName != "Мама" || app.deviceName != "iPhone" || app.ttl != 12*time.Minute {
		t.Fatalf("unexpected application call: %#v", app)
	}
	text, _ := (*requests)[0].body["text"].(string)
	if !strings.Contains(text, "ABCD-EFGH") || strings.Contains(strings.ToLower(text), "private") || strings.Contains(text, "vless://") {
		t.Fatalf("unexpected Telegram text: %q", text)
	}
	markup, _ := json.Marshal((*requests)[0].body["reply_markup"])
	if !strings.Contains(string(markup), `"copy_text":{"text":"ABCD-EFGH"}`) {
		t.Fatalf("copy button missing: %s", markup)
	}
}

func TestDevicesAndRevokeCallback(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{devices: []Device{{
		ID: "device_123456", RelativeName: "Папа", DeviceName: "Mac", Platform: "macos", State: "active",
	}}}
	bot := newTestBot(t, server, app)

	if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: "/devices",
	}}); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 || (*requests)[0].body["reply_markup"] == nil {
		t.Fatalf("device response has no revoke keyboard: %#v", *requests)
	}
	if err := bot.handleUpdate(context.Background(), apiUpdate{Callback: &apiCallbackQuery{
		ID: "callback-1", From: &apiUser{ID: 42}, Data: "revoke:device_123456",
		Message: &apiMessage{Chat: apiChat{ID: 42}},
	}}); err != nil {
		t.Fatal(err)
	}
	if app.revokedID != "device_123456" {
		t.Fatalf("revoked %q", app.revokedID)
	}
	if len(*requests) != 3 || (*requests)[1].method != "answerCallbackQuery" || (*requests)[2].method != "sendMessage" {
		t.Fatalf("unexpected callback calls: %#v", *requests)
	}
}

func TestDeviceCommandsSeparateActiveAndRevoked(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{devices: []Device{
		{ID: "device_active_1", RelativeName: "Мама", DeviceName: "iPhone", Platform: "ios", State: "active"},
		{ID: "device_revoked_1", RelativeName: "Папа", DeviceName: "Mac", Platform: "macos", State: "revoked", Revoked: true},
	}}
	bot := newTestBot(t, server, app)

	for _, command := range []string{"/devices", "/revoked"} {
		if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
			From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: command,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(*requests) != 2 {
		t.Fatalf("unexpected requests: %#v", *requests)
	}
	activeText, _ := (*requests)[0].body["text"].(string)
	revokedText, _ := (*requests)[1].body["text"].(string)
	if !strings.Contains(activeText, "Мама") || strings.Contains(activeText, "Папа") {
		t.Fatalf("active list contains wrong devices: %q", activeText)
	}
	if !strings.Contains(revokedText, "Папа") || strings.Contains(revokedText, "Мама") {
		t.Fatalf("revoked list contains wrong devices: %q", revokedText)
	}
	if (*requests)[1].body["reply_markup"] != nil {
		t.Fatalf("revoked device must not have actions: %#v", (*requests)[1].body)
	}
}

func TestMenuButtonsAndInvitationPrompt(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{invitationCode: "ABCD-EFGH"}
	bot := newTestBot(t, server, app)

	messages := []string{"/start", "➕ Приглашение", "Мама", "iPhone"}
	for _, text := range messages {
		if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
			From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: text,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(*requests) != 4 {
		t.Fatalf("unexpected requests: %#v", *requests)
	}
	menu, ok := (*requests)[0].body["reply_markup"].(map[string]any)
	if !ok || menu["keyboard"] == nil {
		t.Fatalf("persistent menu missing: %#v", (*requests)[0].body)
	}
	if app.createCalls != 1 || app.relativeName != "Мама" || app.deviceName != "iPhone" || app.ttl != 5*time.Minute {
		t.Fatalf("unexpected invitation from button flow: %#v", app)
	}
	if (*requests)[1].body["text"] != "Как зовут человека?" || !strings.Contains((*requests)[2].body["text"].(string), "устройство") {
		t.Fatalf("unexpected invitation prompts: %#v", *requests)
	}
	markup, _ := json.Marshal((*requests)[3].body["reply_markup"])
	if !strings.Contains(string(markup), `"copy_text":{"text":"ABCD-EFGH"}`) {
		t.Fatalf("copy button missing: %s", markup)
	}
}

func TestInviteCommandCanOverrideDefaultTTL(t *testing.T) {
	server, _ := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{invitationCode: "ABCD-EFGH"}
	bot := newTestBot(t, server, app)

	for _, text := range []string{"/invite 15", "Папа", "MacBook"} {
		if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
			From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: text,
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if app.createCalls != 1 || app.relativeName != "Папа" || app.deviceName != "MacBook" || app.ttl != 15*time.Minute {
		t.Fatalf("unexpected invitation: %#v", app)
	}
}

func TestAccessRequestNotificationApprovalHasCopyButton(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{invitationCode: "ABCD-EFGH"}
	bot := newTestBot(t, server, app)
	const requestID = "0123456789abcdef0123456789abcdef"

	if err := bot.NotifyAccessRequest(context.Background(), requestID, "Мама", "iPhone", "ios", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 || (*requests)[0].body["reply_markup"] == nil || !strings.Contains((*requests)[0].body["text"].(string), "Мама") {
		t.Fatalf("notification=%#v", *requests)
	}
	if err := bot.handleUpdate(context.Background(), apiUpdate{Callback: &apiCallbackQuery{
		ID: "callback-access", From: &apiUser{ID: 42}, Data: "access-approve:" + requestID,
		Message: &apiMessage{Chat: apiChat{ID: 42}},
	}}); err != nil {
		t.Fatal(err)
	}
	if app.approvedID != requestID || len(*requests) != 3 {
		t.Fatalf("approved=%q requests=%#v", app.approvedID, *requests)
	}
	message := (*requests)[2]
	if !strings.Contains(message.body["text"].(string), "ABCD-EFGH") {
		t.Fatalf("approval message=%#v", message)
	}
	keyboard, ok := message.body["reply_markup"].(map[string]any)
	if !ok || keyboard["inline_keyboard"] == nil {
		t.Fatalf("copy keyboard=%#v", message.body["reply_markup"])
	}
}

func TestApplicationErrorsDoNotLeak(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{err: errors.New("vless://private-credential")}
	bot := newTestBot(t, server, app)

	if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: "/invite A | B",
	}}); err != nil {
		t.Fatal(err)
	}
	text, _ := (*requests)[0].body["text"].(string)
	if strings.Contains(text, "vless") || strings.Contains(text, "private") {
		t.Fatalf("application error leaked: %q", text)
	}
}

func TestStatusListsAllVPNProfileEdges(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{status: SystemStatus{
		Portal: "ok", VPN: "vless-reality", Edges: "🇱🇹 Литва 🚀 · 🇫🇮 Финляндия 🚀",
		Certificate: "ok", CPU: "2 vCPU", Memory: "10 MiB", Disk: "20 GiB", Network: "443/tcp",
	}}
	bot := newTestBot(t, server, app)

	if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: "/status",
	}}); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("requests=%#v", *requests)
	}
	text, _ := (*requests)[0].body["text"].(string)
	if !strings.Contains(text, "Узлы профиля: 🇱🇹 Литва 🚀 · 🇫🇮 Финляндия 🚀") {
		t.Fatalf("status=%q", text)
	}
}

func TestTrafficButtonShowsBothEdges(t *testing.T) {
	server, requests := telegramServer(t)
	defer server.Close()
	app := &fakeApplication{traffic: []EdgeTraffic{
		{Edge: "lt", Bytes24Hours: 2 << 30, BytesMonth: 3 << 30},
		{Edge: "fi", Bytes24Hours: 5 << 20, BytesMonth: 7 << 20},
	}}
	bot := newTestBot(t, server, app)
	if err := bot.handleUpdate(context.Background(), apiUpdate{Message: &apiMessage{
		From: &apiUser{ID: 42}, Chat: apiChat{ID: 42}, Text: "📈 Трафик",
	}}); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 1 {
		t.Fatalf("requests=%#v", *requests)
	}
	text, _ := (*requests)[0].body["text"].(string)
	if !strings.Contains(text, "🇱🇹 Литва") || !strings.Contains(text, "2.00 ГБ") || !strings.Contains(text, "🇫🇮 Финляндия") || !strings.Contains(text, "5.0 МБ") {
		t.Fatalf("traffic=%q", text)
	}
}

func TestFileOffsetStoreRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "telegram.offset")
	store := FileOffsetStore{Path: path}
	if err := store.Save(context.Background(), 123); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(context.Background())
	if err != nil || got != 123 {
		t.Fatalf("Load = %d, %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestNewRejectsMissingSecurityInputs(t *testing.T) {
	app := &fakeApplication{}
	if _, err := New(Config{Token: "token", Application: app}); err == nil {
		t.Fatal("New accepted an empty allowlist")
	}
	if _, err := New(Config{Admins: []int64{42}, Application: app}); err == nil {
		t.Fatal("New accepted an empty token")
	}
}
