package service

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/store"
)

type failingProvisioner struct{}

func (failingProvisioner) Provision(context.Context, provision.DeviceRequest) (provision.Result, error) {
	return provision.Result{}, errors.New("offline")
}

type subscriptionProvisioner struct {
	mu      sync.Mutex
	configs map[string]provision.ClientConfig
}

func (p *subscriptionProvisioner) Provision(_ context.Context, request provision.DeviceRequest) (provision.Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.configs == nil {
		p.configs = make(map[string]provision.ClientConfig)
	}
	credential := "amneziawg:" + request.DeviceID
	p.configs[credential] = provision.ClientConfig{
		Body: testAWGConfig, ContentType: "text/plain; charset=utf-8",
		Filename: "family-vpn.conf", QRContent: testAWGConfig,
	}
	return provision.Result{CredentialRef: credential, State: "active", ConfigPath: "/api/v1/devices/" + request.DeviceID + "/config"}, nil
}

const testAWGConfig = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.2/32
DNS = 1.1.1.1, 8.8.8.8
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

func (p *subscriptionProvisioner) Revoke(_ context.Context, credential string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.configs, credential)
	return nil
}

func (p *subscriptionProvisioner) ClientConfig(_ context.Context, credential string) (provision.ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	config, ok := p.configs[credential]
	if !ok {
		return provision.ClientConfig{}, errors.New("not found")
	}
	return config, nil
}
func (failingProvisioner) Revoke(context.Context, string) error { return nil }

type controlledProvisioner struct {
	result         provision.Result
	provisionErr   error
	revokeFailures int
	revokeCalls    int
}

func (p *controlledProvisioner) Provision(context.Context, provision.DeviceRequest) (provision.Result, error) {
	return p.result, p.provisionErr
}

func (p *controlledProvisioner) Revoke(context.Context, string) error {
	p.revokeCalls++
	if p.revokeFailures > 0 {
		p.revokeFailures--
		return errors.New("temporary revoke failure")
	}
	return nil
}

func TestProvisionFailureCompensatesInvitation(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := New(database, failingProvisioner{}, make([]byte, 32), base)
	_, code, err := application.CreateInvitation(context.Background(), "Друг", "Телефон", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Activate(context.Background(), code, "android", "", "192.0.2.1"); !errors.Is(err, ErrProvisioning) {
		t.Fatalf("first activation error = %v", err)
	}
	if _, err := application.Activate(context.Background(), code, "android", "", "192.0.2.1"); !errors.Is(err, ErrProvisioning) {
		t.Fatalf("invitation was not reusable after compensation: %v", err)
	}
}

func TestInvalidProvisionResultIsRevokedAndCompensated(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &controlledProvisioner{result: provision.Result{CredentialRef: "provider:123", State: "active"}}
	application := New(database, provider, make([]byte, 32), base)
	_, code, err := application.CreateInvitation(context.Background(), "Друг", "Телефон", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Activate(context.Background(), code, "android", "", "192.0.2.1"); !errors.Is(err, ErrProvisioning) {
		t.Fatalf("activation error = %v", err)
	}
	if provider.revokeCalls != 1 {
		t.Fatalf("provider revoke calls = %d", provider.revokeCalls)
	}
	devices, err := application.ListDevices(context.Background())
	if err != nil || len(devices) != 0 {
		t.Fatalf("compensated devices=%d err=%v", len(devices), err)
	}
}

func TestUpdateProvisionedFailureRevokesAndCompensates(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &controlledProvisioner{result: provision.Result{CredentialRef: "provider:duplicate", State: "pending"}}
	application := New(database, provider, make([]byte, 32), base)
	_, firstCode, err := application.CreateInvitation(context.Background(), "Первый", "Телефон", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Activate(context.Background(), firstCode, "android", "", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	_, secondCode, err := application.CreateInvitation(context.Background(), "Второй", "Ноутбук", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.Activate(context.Background(), secondCode, "linux", "", "192.0.2.2"); !errors.Is(err, ErrProvisioning) {
		t.Fatalf("second activation error = %v", err)
	}
	if provider.revokeCalls != 1 {
		t.Fatalf("provider revoke calls = %d", provider.revokeCalls)
	}
	devices, err := application.ListDevices(context.Background())
	if err != nil || len(devices) != 1 {
		t.Fatalf("devices=%d err=%v", len(devices), err)
	}
}

func TestRevokeFailureRemainsPendingAndRetryCompletes(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &controlledProvisioner{result: provision.Result{CredentialRef: "provider:revoke", State: "pending"}, revokeFailures: 1}
	application := New(database, provider, make([]byte, 32), base)
	_, code, err := application.CreateInvitation(context.Background(), "Друг", "Телефон", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := application.Activate(context.Background(), code, "android", "", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := application.Revoke(context.Background(), activation.Device.ID)
	if !errors.Is(err, ErrRevokePending) || pending.State != "revoke_pending" || pending.RevokedAt != nil {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	revoked, err := application.Revoke(context.Background(), activation.Device.ID)
	if err != nil || revoked.State != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked=%#v err=%v", revoked, err)
	}
	if _, err := application.Revoke(context.Background(), activation.Device.ID); !errors.Is(err, store.ErrDeviceNotFound) {
		t.Fatalf("deleted device revoke error=%v", err)
	}
	devices, err := application.ListDevices(context.Background())
	if err != nil || len(devices) != 0 {
		t.Fatalf("devices after revoke=%d err=%v", len(devices), err)
	}
}

func TestOpaqueSubscriptionIsHMACOnlyAndRevokedWithDevice(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "test.db")
	database, err := store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &subscriptionProvisioner{}
	application := New(database, provider, []byte(strings.Repeat("h", 32)), base)
	_, code, err := application.CreateInvitation(context.Background(), "Друг", "Телефон", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := application.Activate(context.Background(), code, "android", "", "192.0.2.5")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "https://vpn.example.test/s/"
	if !strings.HasPrefix(activation.ConfigDownloadURL, prefix) || !strings.HasSuffix(activation.ConfigDownloadURL, "?download=1") {
		t.Fatalf("unsafe activation download URL: %q", activation.ConfigDownloadURL)
	}
	token := strings.TrimSuffix(strings.TrimPrefix(activation.ConfigDownloadURL, prefix), "?download=1")
	payload, err := application.Subscription(context.Background(), token)
	if err != nil || payload.ContentType != "text/plain; charset=utf-8" {
		t.Fatalf("subscription err=%v content-type=%q", err, payload.ContentType)
	}
	if payload.Body != testAWGConfig || payload.QRContent != testAWGConfig || payload.Filename != "family-vpn.conf" {
		t.Fatal("subscription is not a complete AmneziaWG configuration")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(databasePath + "*")
	for _, name := range files {
		contents, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(contents), token) {
			t.Fatalf("raw subscription token persisted in %s", name)
		}
	}
	// Reopen to prove the HMAC token survives restart while the raw token does
	// not, then prove revocation invalidates it immediately.
	database, err = store.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	application = New(database, provider, []byte(strings.Repeat("h", 32)), base)
	if _, err := application.Revoke(context.Background(), activation.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := application.Subscription(context.Background(), token); !errors.Is(err, store.ErrSubscriptionNotFound) {
		t.Fatalf("subscription after revoke error=%v", err)
	}
}

func TestSeparateClientsHaveUniqueSubscriptionsAndIndependentRevoke(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	provider := &subscriptionProvisioner{}
	application := New(database, provider, []byte(strings.Repeat("u", 32)), base)
	var activations []Activation
	for index, platform := range []string{"android", "linux"} {
		clientName := []string{"Мама", "Папа"}[index]
		_, code, err := application.CreateInvitation(context.Background(), clientName, "Device", 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		activation, err := application.Activate(context.Background(), code, platform, "", "192.0.2."+string(rune('1'+index)))
		if err != nil {
			t.Fatal(err)
		}
		activations = append(activations, activation)
	}
	if activations[0].ConfigDownloadURL == activations[1].ConfigDownloadURL || activations[0].Device.ID == activations[1].Device.ID {
		t.Fatal("devices did not receive unique identities and subscriptions")
	}
	firstToken := strings.TrimSuffix(strings.TrimPrefix(activations[0].ConfigDownloadURL, "https://vpn.example.test/s/"), "?download=1")
	secondToken := strings.TrimSuffix(strings.TrimPrefix(activations[1].ConfigDownloadURL, "https://vpn.example.test/s/"), "?download=1")
	if _, err := application.Revoke(context.Background(), activations[0].Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := application.Subscription(context.Background(), firstToken); !errors.Is(err, store.ErrSubscriptionNotFound) {
		t.Fatalf("revoked device subscription error=%v", err)
	}
	if _, err := application.Subscription(context.Background(), secondToken); err != nil {
		t.Fatalf("unrelated device subscription failed: %v", err)
	}
}

func TestOneActiveDevicePerClient(t *testing.T) {
	database, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	base, _ := url.Parse("https://vpn.example.test")
	application := New(database, &subscriptionProvisioner{}, []byte(strings.Repeat("l", 32)), base)
	_, code, err := application.CreateInvitation(context.Background(), "Мама", "iPhone", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	first, err := application.Activate(context.Background(), code, "ios", "", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.CreateInvitation(context.Background(), "мама", "iPad", 10*time.Minute); !errors.Is(err, store.ErrClientDeviceLimit) {
		t.Fatalf("second device invitation error=%v", err)
	}
	if _, err := application.Revoke(context.Background(), first.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := application.CreateInvitation(context.Background(), "МАМА", "iPad", 10*time.Minute); err != nil {
		t.Fatalf("invitation after revoke: %v", err)
	}
}
