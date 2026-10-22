package provision

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type helperCall struct {
	action string
	input  []byte
}

type fakeHelper struct {
	calls        []helperCall
	provision    []byte
	provisionErr error
	revoke       []byte
	revokeErr    error
	config       []byte
	configErr    error
}

func (f *fakeHelper) Run(_ context.Context, action string, input []byte) ([]byte, error) {
	f.calls = append(f.calls, helperCall{action: action, input: append([]byte(nil), input...)})
	switch action {
	case "provision":
		return f.provision, f.provisionErr
	case "config":
		return f.config, f.configErr
	default:
		return f.revoke, f.revokeErr
	}
}

func validDeviceRequest() DeviceRequest {
	return DeviceRequest{
		DeviceID: "0123456789abcdef0123456789abcdef", RelativeName: "Мама",
		DeviceName: "Телефон", Platform: "android",
	}
}

const validAWGConfig = `[Interface]
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

func TestAmneziaWGProvisionAndConfig(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/api/v1/devices/0123456789abcdef0123456789abcdef/config"}`),
		config:    []byte(`{"version":1,"config":` + mustJSON(t, validAWGConfig) + `}`),
		revoke:    []byte(`{"version":1,"state":"revoked"}`),
	}
	provider := &AmneziaWG{runner: helper, timeout: time.Second}
	result, err := provider.Provision(context.Background(), validDeviceRequest())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.CredentialRef != "amneziawg:0123456789abcdef0123456789abcdef" || result.State != "active" {
		t.Fatalf("unexpected result: %#v", result)
	}
	config, err := provider.ClientConfig(context.Background(), result.CredentialRef)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if config.Body != validAWGConfig || config.Filename != "family-vpn.conf" || config.QRContent != validAWGConfig {
		t.Fatalf("unexpected config metadata: %#v", config)
	}
	if err := provider.Revoke(context.Background(), result.CredentialRef); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestAmneziaWGLazilyMigratesLegacyCredential(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/api/v1/devices/0123456789abcdef0123456789abcdef/config"}`),
		config:    []byte(`{"version":1,"config":` + mustJSON(t, validAWGConfig) + `}`),
	}
	provider := &AmneziaWG{runner: helper, timeout: time.Second}
	if _, err := provider.ClientConfig(context.Background(), "vless-reality:0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("legacy ClientConfig: %v", err)
	}
	if len(helper.calls) != 2 || helper.calls[0].action != "provision" || helper.calls[1].action != "config" {
		t.Fatalf("unexpected migration calls: %#v", helper.calls)
	}
}

func TestAmneziaWGRejectsMalformedConfig(t *testing.T) {
	helper := &fakeHelper{config: []byte(`{"version":1,"config":"[Interface]\\nPrivateKey = leaked"}`)}
	provider := &AmneziaWG{runner: helper, timeout: time.Second}
	if _, err := provider.ClientConfig(context.Background(), "amneziawg:0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("ClientConfig accepted incomplete configuration")
	}
	if err := provider.Revoke(context.Background(), "pending:bad"); err == nil {
		t.Fatal("Revoke accepted a foreign credential reference")
	}
}

func TestAmneziaWGDoesNotExposeHelperErrors(t *testing.T) {
	const secret = "private-key-must-not-leak"
	helper := &fakeHelper{
		provisionErr: errors.New(secret),
		revoke:       []byte(`{"version":1,"state":"absent"}`),
	}
	provider := &AmneziaWG{runner: helper, timeout: time.Second}
	_, err := provider.Provision(context.Background(), validDeviceRequest())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked through error: %v", err)
	}
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestSafeAmneziaWGConfigRejectsControlCharacters(t *testing.T) {
	if !safeAmneziaWGConfig(validAWGConfig) {
		t.Fatal("valid config rejected")
	}
	if safeAmneziaWGConfig(strings.Replace(validAWGConfig, "[Peer]", "[Peer]\r", 1)) {
		t.Fatal("CR-containing config accepted")
	}
}

func TestLimitedBufferCapsHelperOutput(t *testing.T) {
	var buffer limitedBuffer
	payload := make([]byte, maxHelperOutput+10)
	if written, err := buffer.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("Write = %d, %v", written, err)
	}
	if !buffer.overflow || len(buffer.Bytes()) != maxHelperOutput {
		t.Fatalf("limit not applied: overflow=%v length=%d", buffer.overflow, len(buffer.Bytes()))
	}
}
