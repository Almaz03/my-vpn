package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const AmneziaWGHelperPath = "/usr/local/libexec/my-vpn/amneziawg-helper"

// AmneziaWG provisions one isolated peer per approved device in the existing
// amnezia-awg2 data plane. Secret client material is kept only by the root-owned
// helper and is returned on demand through the authenticated subscription URL.
type AmneziaWG struct {
	runner  helperRunner
	timeout time.Duration
}

var _ Provisioner = (*AmneziaWG)(nil)
var _ ConfigProvider = (*AmneziaWG)(nil)

type amneziaConfigResponse struct {
	Version int    `json:"version"`
	Config  string `json:"config"`
}

func NewAmneziaWG() *AmneziaWG {
	return &AmneziaWG{runner: amneziaWGHelperRunner{}, timeout: 20 * time.Second}
}

func (a *AmneziaWG) Provision(ctx context.Context, request DeviceRequest) (Result, error) {
	credentialRef := "amneziawg:" + request.DeviceID
	result := Result{CredentialRef: credentialRef}
	if err := validateDeviceRequest(request); err != nil {
		return Result{}, err
	}
	payload, err := json.Marshal(helperRequest{
		Version: helperProtocol, DeviceID: request.DeviceID, RelativeName: request.RelativeName,
		DeviceName: request.DeviceName, Platform: request.Platform,
	})
	if err != nil {
		return result, errors.New("encode AmneziaWG helper request")
	}
	output, err := a.run(ctx, "provision", payload)
	if err != nil {
		a.bestEffortRevoke(ctx, credentialRef)
		return result, errors.New("AmneziaWG helper could not provision device")
	}
	var response provisionResponse
	if err := decodeHelperResponse(output, &response); err != nil || response.Version != helperProtocol ||
		response.State != "active" || !safeDeviceConfigPath(response.ConfigPath, request.DeviceID) {
		a.bestEffortRevoke(ctx, credentialRef)
		return result, errors.New("AmneziaWG helper returned an invalid provision response")
	}
	return Result{CredentialRef: credentialRef, State: "active", ConfigPath: response.ConfigPath}, nil
}

func (a *AmneziaWG) Revoke(ctx context.Context, credentialRef string) error {
	deviceID, ok := amneziaDeviceID(credentialRef)
	if !ok {
		return errors.New("invalid AmneziaWG credential reference")
	}
	payload, err := json.Marshal(helperRequest{Version: helperProtocol, Credential: "amneziawg:" + deviceID})
	if err != nil {
		return errors.New("encode AmneziaWG helper request")
	}
	output, err := a.run(ctx, "revoke", payload)
	if err != nil {
		return errors.New("AmneziaWG helper could not revoke device")
	}
	var response revokeResponse
	if err := decodeHelperResponse(output, &response); err != nil || response.Version != helperProtocol ||
		(response.State != "revoked" && response.State != "absent") {
		return errors.New("AmneziaWG helper returned an invalid revoke response")
	}
	return nil
}

func (a *AmneziaWG) ClientConfig(ctx context.Context, credentialRef string) (ClientConfig, error) {
	deviceID, ok := amneziaDeviceID(credentialRef)
	if !ok {
		return ClientConfig{}, errors.New("invalid AmneziaWG credential reference")
	}
	// A legacy Reality credential contains the same opaque device ID. The helper
	// lazily creates its AmneziaWG peer so existing active users can migrate
	// without another invitation or database rewrite.
	if strings.HasPrefix(credentialRef, "vless-reality:") {
		payload, err := json.Marshal(helperRequest{
			Version: helperProtocol, DeviceID: deviceID, RelativeName: "legacy",
			DeviceName: "migrated-device", Platform: "ios",
		})
		if err != nil {
			return ClientConfig{}, errors.New("encode AmneziaWG migration request")
		}
		if _, err := a.run(ctx, "provision", payload); err != nil {
			return ClientConfig{}, errors.New("AmneziaWG helper could not migrate device")
		}
	}
	payload, err := json.Marshal(helperRequest{Version: helperProtocol, Credential: "amneziawg:" + deviceID})
	if err != nil {
		return ClientConfig{}, errors.New("encode AmneziaWG helper request")
	}
	output, err := a.run(ctx, "config", payload)
	if err != nil {
		return ClientConfig{}, errors.New("AmneziaWG helper could not read device config")
	}
	var response amneziaConfigResponse
	if err := decodeHelperResponse(output, &response); err != nil || response.Version != helperProtocol ||
		!safeAmneziaWGConfig(response.Config) {
		return ClientConfig{}, errors.New("AmneziaWG helper returned an invalid config response")
	}
	return ClientConfig{
		Body: response.Config, ContentType: "text/plain; charset=utf-8",
		Filename: "family-vpn.conf", QRContent: response.Config,
	}, nil
}

func (a *AmneziaWG) run(parent context.Context, action string, payload []byte) ([]byte, error) {
	timeout := a.timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return a.runner.Run(ctx, action, payload)
}

func (a *AmneziaWG) bestEffortRevoke(parent context.Context, credentialRef string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), 20*time.Second)
	defer cancel()
	_ = a.Revoke(cleanupCtx, credentialRef)
}

func amneziaDeviceID(credentialRef string) (string, bool) {
	for _, prefix := range []string{"amneziawg:", "vless-reality:"} {
		if strings.HasPrefix(credentialRef, prefix) {
			deviceID := strings.TrimPrefix(credentialRef, prefix)
			return deviceID, deviceIDPattern.MatchString(deviceID)
		}
	}
	return "", false
}

func safeAmneziaWGConfig(value string) bool {
	if len(value) == 0 || len(value) > 32<<10 || strings.ContainsAny(value, "\r\x00") {
		return false
	}
	required := []string{
		"[Interface]\n", "PrivateKey = ", "Address = ", "Jc = ", "Jmin = ", "Jmax = ",
		"S1 = ", "S2 = ", "H1 = ", "H2 = ", "H3 = ", "H4 = ",
		"[Peer]\n", "PublicKey = ", "PresharedKey = ", "AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = ", "PersistentKeepalive = 25",
	}
	for _, marker := range required {
		if !strings.Contains(value, marker) {
			return false
		}
	}
	return true
}

type amneziaWGHelperRunner struct{}

func (amneziaWGHelperRunner) Run(ctx context.Context, action string, input []byte) ([]byte, error) {
	if action != "provision" && action != "revoke" && action != "config" {
		return nil, errors.New("unsupported AmneziaWG helper action")
	}
	if filepath.Clean(AmneziaWGHelperPath) != AmneziaWGHelperPath {
		return nil, errors.New("invalid AmneziaWG helper path")
	}
	command := exec.CommandContext(ctx, "sudo", "--non-interactive", "--", AmneziaWGHelperPath, action)
	command.Stdin = bytes.NewReader(input)
	var stdout limitedBuffer
	var stderr limitedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("AmneziaWG helper execution failed")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("AmneziaWG helper output exceeded limit")
	}
	return stdout.Bytes(), nil
}
