package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/service"
	"github.com/Almaz03/my-vpn/internal/store"
)

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
