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
	stats        []byte
	statsErr     error
}

func (f *fakeHelper) Run(_ context.Context, action string, input []byte) ([]byte, error) {
	f.calls = append(f.calls, helperCall{action: action, input: append([]byte(nil), input...)})
	if action == "provision" {
		return f.provision, f.provisionErr
	}
	if action == "config" {
		return f.config, f.configErr
	}
	if action == "stats" {
		return f.stats, f.statsErr
	}
	return f.revoke, f.revokeErr
}

func TestRealityTrafficSnapshot(t *testing.T) {
	helper := &fakeHelper{stats: []byte(`{"version":1,"edges":[{"id":"lt","stats":[{"name":"user>>>device-0123456789abcdef0123456789abcdef>>>traffic>>>uplink","value":123},{"name":"user>>>device-0123456789abcdef0123456789abcdef>>>traffic>>>downlink","value":456}]},{"id":"fi","stats":[]}]}`)}
	provider := &Reality{runner: helper, timeout: time.Second}
	counters, err := provider.TrafficSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(counters) != 1 || counters[0].DeviceID != "0123456789abcdef0123456789abcdef" || counters[0].Edge != "lt" || counters[0].Uplink != 123 || counters[0].Downlink != 456 {
		t.Fatalf("counters=%#v", counters)
	}
}

func TestRealityTrafficSnapshotRejectsDestinationData(t *testing.T) {
	helper := &fakeHelper{stats: []byte(`{"version":1,"edges":[{"id":"lt","stats":[{"name":"domain>>>example.com","value":1}]},{"id":"fi","stats":[]}]}`)}
	provider := &Reality{runner: helper, timeout: time.Second}
	if _, err := provider.TrafficSnapshot(context.Background()); err == nil {
		t.Fatal("destination-bearing statistic was accepted")
	}
}

func validDeviceRequest() DeviceRequest {
	return DeviceRequest{
		DeviceID:     "0123456789abcdef0123456789abcdef",
		RelativeName: "Мама",
		DeviceName:   "Телефон",
		Platform:     "android",
	}
}

func TestRealityProvision(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/api/v1/devices/0123456789abcdef0123456789abcdef/config"}`),
		revoke:    []byte(`{"version":1,"state":"revoked"}`),
	}
	provider := &Reality{runner: helper, timeout: time.Second}
	result, err := provider.Provision(context.Background(), validDeviceRequest())
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.CredentialRef != "vless-reality:0123456789abcdef0123456789abcdef" || result.State != "active" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.ConfigPath == "" || len(helper.calls) != 1 || helper.calls[0].action != "provision" {
		t.Fatalf("unexpected helper calls/result: %#v %#v", helper.calls, result)
	}
	var request helperRequest
	if err := json.Unmarshal(helper.calls[0].input, &request); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if request.Version != helperProtocol || request.DeviceID != validDeviceRequest().DeviceID || request.RelativeName != "Мама" {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestRealityRejectsRequestBeforeHelper(t *testing.T) {
	helper := &fakeHelper{}
	provider := &Reality{runner: helper, timeout: time.Second}
	request := validDeviceRequest()
	request.DeviceID = "../../etc/passwd"
	if _, err := provider.Provision(context.Background(), request); err == nil {
		t.Fatal("Provision accepted unsafe device id")
	}
	if len(helper.calls) != 0 {
		t.Fatalf("helper called for invalid request: %#v", helper.calls)
	}
}

func TestRealityInvalidResponseTriggersIdempotentCleanup(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/unsafe"}`),
		revoke:    []byte(`{"version":1,"state":"absent"}`),
	}
	provider := &Reality{runner: helper, timeout: time.Second}
	result, err := provider.Provision(context.Background(), validDeviceRequest())
	if err == nil || result.CredentialRef == "" {
		t.Fatalf("expected cleanup-capable failure, result=%#v err=%v", result, err)
	}
	if len(helper.calls) != 2 || helper.calls[1].action != "revoke" {
		t.Fatalf("cleanup was not attempted: %#v", helper.calls)
	}
}

func TestRealityExecutionErrorDoesNotExposeHelperError(t *testing.T) {
	secret := "vless://do-not-log-this"
	helper := &fakeHelper{
		provisionErr: errors.New(secret),
		revoke:       []byte(`{"version":1,"state":"revoked"}`),
	}
	provider := &Reality{runner: helper, timeout: time.Second}
	_, err := provider.Provision(context.Background(), validDeviceRequest())
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("credential leaked through error: %v", err)
	}
	if len(helper.calls) != 2 || helper.calls[1].action != "revoke" {
		t.Fatalf("cleanup was not attempted: %#v", helper.calls)
	}
}

func TestRealityRevokeIsStrictAndAcceptsAbsent(t *testing.T) {
	helper := &fakeHelper{revoke: []byte(`{"version":1,"state":"absent"}`)}
	provider := &Reality{runner: helper, timeout: time.Second}
	if err := provider.Revoke(context.Background(), "pending:bad"); err == nil {
		t.Fatal("Revoke accepted a foreign credential reference")
	}
	if len(helper.calls) != 0 {
		t.Fatal("helper called for invalid credential reference")
	}
	if err := provider.Revoke(context.Background(), "vless-reality:0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatalf("idempotent Revoke: %v", err)
	}
	if len(helper.calls) != 1 || helper.calls[0].action != "revoke" {
		t.Fatalf("unexpected calls: %#v", helper.calls)
	}
}

func TestRealityClientConfig(t *testing.T) {
	helper := &fakeHelper{config: []byte(`{"version":1,"vless_uris":["vless://01234567-89ab-4def-8123-456789abcdef@lt.example.test:443?security=reality&sni=lt.example.com&pbk=public-key","vless://01234567-89ab-4def-8123-456789abcdef@fi.example.test:443?security=reality&sni=fi.example.com&pbk=public-key"]}`)}
	provider := &Reality{runner: helper, timeout: time.Second}
	config, err := provider.ClientConfig(context.Background(), "vless-reality:0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if len(config.VLESSURIs) != 2 || !strings.HasPrefix(config.VLESSURIs[0], "vless://") {
		t.Fatalf("unexpected config: %#v", config)
	}
	if len(helper.calls) != 1 || helper.calls[0].action != "config" {
		t.Fatalf("unexpected calls: %#v", helper.calls)
	}
}

func TestRealityClientConfigRejectsCredentialLeakInMalformedResponse(t *testing.T) {
	helper := &fakeHelper{config: []byte(`{"version":1,"vless_uris":["https://example.test/not-vless","vless://01234567-89ab-4def-8123-456789abcdef@fi.example.test:443?security=reality&sni=fi.example.com&pbk=key"]}`)}
	provider := &Reality{runner: helper, timeout: time.Second}
	if _, err := provider.ClientConfig(context.Background(), "vless-reality:0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("ClientConfig accepted an invalid VLESS URI")
	}
}

func TestRealityRejectsUnknownResponseFields(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/api/v1/devices/0123456789abcdef0123456789abcdef/config","credential":"must-not-be-trusted"}`),
		revoke:    []byte(`{"version":1,"state":"revoked"}`),
	}
	provider := &Reality{runner: helper, timeout: time.Second}
	if _, err := provider.Provision(context.Background(), validDeviceRequest()); err == nil {
		t.Fatal("Provision accepted an extended helper response")
	}
	if len(helper.calls) != 2 || helper.calls[1].action != "revoke" {
		t.Fatalf("cleanup was not attempted: %#v", helper.calls)
	}
}

func TestRealityRejectsTrailingResponseData(t *testing.T) {
	helper := &fakeHelper{
		provision: []byte(`{"version":1,"state":"active","config_path":"/api/v1/devices/0123456789abcdef0123456789abcdef/config"} credential`),
		revoke:    []byte(`{"version":1,"state":"revoked"}`),
	}
	provider := &Reality{runner: helper, timeout: time.Second}
	if _, err := provider.Provision(context.Background(), validDeviceRequest()); err == nil {
		t.Fatal("Provision accepted trailing helper output")
	}
	if len(helper.calls) != 2 || helper.calls[1].action != "revoke" {
		t.Fatalf("cleanup was not attempted: %#v", helper.calls)
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
