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

type apiRealityProvider struct{ credential string }

func (p *apiRealityProvider) Provision(_ context.Context, request provision.DeviceRequest) (provision.Result, error) {
	p.credential = "vless-reality:" + request.DeviceID
	return provision.Result{CredentialRef: p.credential, State: "active", INCYDeepLink: "incy://import/provider-secret"}, nil
}
func (p *apiRealityProvider) Revoke(context.Context, string) error { return nil }
func (p *apiRealityProvider) ClientConfig(context.Context, string) (provision.ClientConfig, error) {
	return provision.ClientConfig{
		VLESSURI:     "vless://00000000-0000-4000-8000-000000000001@vpn.example.test:8443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=vpn.example.test&pbk=public&sid=abcd#Family",
		INCYDeepLink: "incy://import/provider-secret",
	}, nil
}

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
	if result["state"] != "pending" || result["incy_deep_link"] != "" || result["config_download_url"] != "" {
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

func TestRealityActivationUsesOpaqueSubscriptionWithSecureHeaders(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &apiRealityProvider{}
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
		DeepLink string `json:"incy_deep_link"`
		QRCode   string `json:"qr_code_url"`
	}
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &activation) != nil {
		t.Fatalf("activate status=%d body=%s", response.Code, response.Body.String())
	}
	const prefix = "incy://add/https://vpn.example.test"
	if !strings.HasPrefix(activation.DeepLink, prefix+"/s/") || strings.Contains(activation.DeepLink, "provider-secret") {
		t.Fatalf("unsafe deep link=%q", activation.DeepLink)
	}
	if !strings.HasPrefix(activation.QRCode, "https://vpn.example.test/s/") || !strings.HasSuffix(activation.QRCode, "/qr") {
		t.Fatalf("unsafe QR URL=%q", activation.QRCode)
	}
	subscriptionPath := strings.TrimPrefix(activation.DeepLink, prefix)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, subscriptionPath, nil))
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Body.String(), "vless://") {
		t.Fatalf("subscription status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store, private, max-age=0" ||
		!strings.HasPrefix(response.Header().Get("Autorouting"), "incy://autorouting/onadd/https://vpn.example.test/") ||
		response.Header().Get("Hide-Url") != "1" {
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

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/routing/family-ru-direct.json", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"GlobalProxy":"true"`) || !strings.Contains(response.Body.String(), "geosite:ru") {
		t.Fatalf("routing status=%d body=%s", response.Code, response.Body.String())
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
