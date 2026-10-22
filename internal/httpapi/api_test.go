package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/service"
	"github.com/Almaz03/my-vpn/internal/store"
)

type apiAmneziaWGProvider struct{ credential string }

type recordingNotifier struct {
	id       string
	name     string
	device   string
	platform string
	err      error
}

func (n *recordingNotifier) NotifyAccessRequest(_ context.Context, id, name, device, platform string, _ time.Time) error {
	n.id, n.name, n.device, n.platform = id, name, device, platform
	return n.err
}

func (p *apiAmneziaWGProvider) Provision(_ context.Context, request provision.DeviceRequest) (provision.Result, error) {
	p.credential = "amneziawg:" + request.DeviceID
	return provision.Result{CredentialRef: p.credential, State: "active", ConfigPath: "/api/v1/devices/" + request.DeviceID + "/config"}, nil
}
func (p *apiAmneziaWGProvider) Revoke(context.Context, string) error { return nil }
func (p *apiAmneziaWGProvider) ClientConfig(context.Context, string) (provision.ClientConfig, error) {
	return provision.ClientConfig{
		Body: testAPIConfig, ContentType: "text/plain; charset=utf-8",
		Filename: "family-vpn.conf", QRContent: testAPIConfig,
	}, nil
}

const testAPIConfig = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 20
S2 = 40
H1 = 111
H2 = 222
H3 = 333
H4 = 444

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
PresharedKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.test:35473
PersistentKeepalive = 25
`

func TestAdminInvitationAndOneTimeActivationFlow(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := service.New(database, provision.Noop{}, bytes.Repeat([]byte{3}, 32), base)
	handler := New(application, database, "this-is-a-long-admin-token", t.TempDir(), 10*time.Minute).Handler()

	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/invitations", bytes.NewBufferString(`{"relative_name":"Мама","device_name":"Телефон"}`))
	request.Header.Set("Authorization", "Bearer this-is-a-long-admin-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", response.Code, response.Body.String())
	}
	var created struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Code == "" {
		t.Fatalf("decode invitation: %v body=%s", err, response.Body.String())
	}

	payload, _ := json.Marshal(map[string]string{"code": created.Code, "platform": "android"})
	activate := httptest.NewRequest(http.MethodPost, "/api/v1/activate", bytes.NewReader(payload))
	activate.RemoteAddr = "192.0.2.10:1234"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, activate)
	if response.Code != http.StatusCreated {
		t.Fatalf("activation status = %d body=%s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["state"] != "pending" || result["config_download_url"] != "" {
		t.Fatalf("unsafe noop response: %#v", result)
	}

	devices, err := application.ListDevices(context.Background())
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices=%d err=%v", len(devices), err)
	}
}

func TestAdminRequiresBearerTokenAndHealthChecksDB(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := service.New(database, provision.Noop{}, bytes.Repeat([]byte{4}, 32), base)
	handler := New(application, database, "this-is-a-long-admin-token", t.TempDir(), 10*time.Minute).Handler()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/admin/devices", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("admin status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d body=%s", response.Code, response.Body.String())
	}
}

func TestAmneziaWGActivationUsesOpaqueSubscriptionWithSecureHeaders(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &apiAmneziaWGProvider{}
	application := service.New(database, provider, bytes.Repeat([]byte{5}, 32), base)
	handler := New(application, database, "this-is-a-long-admin-token", t.TempDir(), 10*time.Minute).Handler()

	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/invitations", bytes.NewBufferString(`{"relative_name":"Мама","device_name":"Телефон"}`))
	request.Header.Set("Authorization", "Bearer this-is-a-long-admin-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var created struct {
		Code string `json:"code"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	payload, _ := json.Marshal(map[string]string{"code": created.Code, "platform": "android"})
	activate := httptest.NewRequest(http.MethodPost, "/api/v1/activate", bytes.NewReader(payload))
	activate.RemoteAddr = "192.0.2.50:1234"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, activate)
	var activation struct {
		Download string `json:"config_download_url"`
		QRCode   string `json:"qr_code_url"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &activation) != nil {
		t.Fatalf("activate status=%d body=%s", response.Code, response.Body.String())
	}
	const prefix = "https://vpn.example.test"
	if !strings.HasPrefix(activation.Download, prefix+"/s/") || !strings.HasSuffix(activation.Download, "?download=1") {
		t.Fatalf("unsafe download URL=%q", activation.Download)
	}
	if !strings.HasPrefix(activation.QRCode, "https://vpn.example.test/s/") || !strings.HasSuffix(activation.QRCode, "/qr") {
		t.Fatalf("unsafe QR URL=%q", activation.QRCode)
	}
	downloadURL, err := url.Parse(activation.Download)
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, downloadURL.RequestURI(), nil))
	if response.Code != http.StatusOK || response.Body.String() != testAPIConfig {
		t.Fatalf("subscription status=%d is not an AmneziaWG configuration", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store, private, max-age=0" ||
		response.Header().Get("Content-Type") != "text/plain; charset=utf-8" ||
		response.Header().Get("Content-Disposition") != `attachment; filename="family-vpn.conf"` {
		t.Fatalf("unsafe subscription headers: %#v", response.Header())
	}
	qrURL, err := url.Parse(activation.QRCode)
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, qrURL.Path, nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/png" ||
		!bytes.HasPrefix(response.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("QR status=%d type=%q", response.Code, response.Header().Get("Content-Type"))
	}

}

func TestAdminStatusAndInvitationLifecycle(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := service.New(database, provision.Noop{}, bytes.Repeat([]byte{6}, 32), base)
	handler := New(application, database, "this-is-a-long-admin-token", t.TempDir(), 10*time.Minute).Handler()
	admin := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer this-is-a-long-admin-token")
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	created := admin(http.MethodPost, "/api/v1/admin/invitations", `{"relative_name":"Папа","device_name":"Ноутбук"}`)
	var value struct {
		Invitation store.Invitation `json:"invitation"`
	}
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &value) != nil {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	listed := admin(http.MethodGet, "/api/v1/admin/invitations", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), value.Invitation.ID) {
		t.Fatalf("list status=%d body=%s", listed.Code, listed.Body.String())
	}
	extended := admin(http.MethodPost, "/api/v1/admin/invitations/"+value.Invitation.ID+"/extend", `{"ttl_seconds":1200}`)
	if extended.Code != http.StatusOK {
		t.Fatalf("extend status=%d body=%s", extended.Code, extended.Body.String())
	}
	status := admin(http.MethodGet, "/api/v1/admin/status", "")
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"database":"ok"`) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
}

func TestPublicAccessRequestApprovalAndCopyableCode(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := service.New(database, provision.Noop{}, bytes.Repeat([]byte{9}, 32), base)
	api := New(application, database, "this-is-a-long-admin-token", t.TempDir(), 10*time.Minute)
	notifier := &recordingNotifier{}
	api.SetAccessRequestNotifier(notifier)
	handler := api.Handler()

	create := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests",
		strings.NewReader(`{"relative_name":"Мама","device_name":"iPhone","platform":"ios"}`))
	create.Header.Set("Content-Type", "application/json")
	create.RemoteAddr = "192.0.2.90:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, create)
	var created struct {
		Token string `json:"request_token"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.Token == "" {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if notifier.id == "" || notifier.name != "Мама" || notifier.device != "iPhone" || notifier.platform != "ios" {
		t.Fatalf("notification=%#v", notifier)
	}
	repeat := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests",
		strings.NewReader(`{"relative_name":"мама","device_name":"iPhone","platform":"ios"}`))
	repeat.Header.Set("Content-Type", "application/json")
	repeat.RemoteAddr = "192.0.2.90:4321"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, repeat)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "уже отправили") {
		t.Fatalf("repeat=%d body=%s", response.Code, response.Body.String())
	}
	approved, err := application.ApproveAccessRequest(context.Background(), notifier.id)
	if err != nil || approved.Code == "" {
		t.Fatalf("approve=%#v err=%v", approved, err)
	}

	payload, _ := json.Marshal(map[string]string{"request_token": created.Token})
	status := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests/status", bytes.NewReader(payload))
	status.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, status)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), approved.Code) || !strings.Contains(response.Body.String(), `"state":"approved"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}

	activatePayload, _ := json.Marshal(map[string]string{"code": approved.Code, "platform": "ios"})
	activate := httptest.NewRequest(http.MethodPost, "/api/v1/activate", bytes.NewReader(activatePayload))
	activate.RemoteAddr = "192.0.2.90:1234"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, activate)
	if response.Code != http.StatusCreated {
		t.Fatalf("activate=%d body=%s", response.Code, response.Body.String())
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/api/v1/access-requests",
		strings.NewReader(`{"relative_name":"мама","device_name":"iPad","platform":"ios"}`))
	duplicate.Header.Set("Content-Type", "application/json")
	duplicate.RemoteAddr = "192.0.2.91:1234"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, duplicate)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAccessStatusRateLimiter(t *testing.T) {
	limiter := newIPWindowLimiter(time.Minute, 2, 3)
	now := time.Now()
	if !limiter.Allow("192.0.2.1", now) || !limiter.Allow("192.0.2.1", now) || limiter.Allow("192.0.2.1", now) {
		t.Fatal("per-IP limit was not enforced")
	}
	if !limiter.Allow("192.0.2.2", now) || limiter.Allow("192.0.2.3", now) {
		t.Fatal("global limit was not enforced")
	}
	if !limiter.Allow("192.0.2.1", now.Add(time.Minute+time.Second)) {
		t.Fatal("expired window did not reopen")
	}
}
