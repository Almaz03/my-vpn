package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	RealityHelperPath = "/usr/local/libexec/my-vpn/reality-helper"
	helperProtocol    = 1
	maxHelperOutput   = 64 << 10
)

var deviceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Reality provisions one VLESS Reality UUID per device through a fixed,
// root-owned helper. The my-vpn service must only receive sudo permission for
// RealityHelperPath; it never writes the Xray configuration itself.
//
// The helper protocol is deliberately narrow and JSON-only. A provision call
// must be idempotent for device_id and a revoke call must succeed when the
// credential is already absent. Private credentials may be returned only in
// the one-time INCY deep link and must never be written to stderr or logs.
type Reality struct {
	runner  helperRunner
	timeout time.Duration
}

// ClientConfig is sensitive, short-lived response data. Callers must not log,
// persist, cache, or send it through Telegram.
type ClientConfig struct {
	VLESSURI     string
	INCYDeepLink string
}

// ConfigProvider is optional functionality implemented by production
// provisioners. HTTP delivery code can type-assert this interface without
// expanding the mutation-only Provisioner contract.
type ConfigProvider interface {
	ClientConfig(context.Context, string) (ClientConfig, error)
}

var _ Provisioner = (*Reality)(nil)
var _ ConfigProvider = (*Reality)(nil)

type helperRunner interface {
	Run(context.Context, string, []byte) ([]byte, error)
}

type sudoHelperRunner struct{}

type helperRequest struct {
	Version      int    `json:"version"`
	DeviceID     string `json:"device_id,omitempty"`
	RelativeName string `json:"relative_name,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Credential   string `json:"credential_ref,omitempty"`
}

type provisionResponse struct {
	Version      int    `json:"version"`
	State        string `json:"state"`
	INCYDeepLink string `json:"incy_deep_link"`
	ConfigPath   string `json:"config_path,omitempty"`
}

type revokeResponse struct {
	Version int    `json:"version"`
	State   string `json:"state"`
}

type configResponse struct {
	Version      int    `json:"version"`
	VLESSURI     string `json:"vless_uri"`
	INCYDeepLink string `json:"incy_deep_link"`
}

func NewReality() *Reality {
	return &Reality{runner: sudoHelperRunner{}, timeout: 15 * time.Second}
}

func (r *Reality) Provision(ctx context.Context, request DeviceRequest) (Result, error) {
	credentialRef := realityCredentialRef(request.DeviceID)
	result := Result{CredentialRef: credentialRef}
	if err := validateDeviceRequest(request); err != nil {
		return Result{}, err
	}
	payload, err := json.Marshal(helperRequest{
		Version: helperProtocol, DeviceID: request.DeviceID, RelativeName: request.RelativeName,
		DeviceName: request.DeviceName, Platform: request.Platform,
	})
	if err != nil {
		return result, errors.New("encode Reality helper request")
	}

	callCtx, cancel := context.WithTimeout(ctx, r.callTimeout())
	defer cancel()
	output, err := r.runner.Run(callCtx, "provision", payload)
	if err != nil {
		r.bestEffortRevoke(ctx, credentialRef)
		return result, errors.New("Reality helper could not provision device")
	}
	var response provisionResponse
	if err := decodeHelperResponse(output, &response); err != nil ||
		response.Version != helperProtocol || response.State != "active" ||
		!safeINCYDeepLink(response.INCYDeepLink) ||
		!safeDeviceConfigPath(response.ConfigPath, request.DeviceID) {
		r.bestEffortRevoke(ctx, credentialRef)
		return result, errors.New("Reality helper returned an invalid provision response")
	}
	return Result{
		CredentialRef: credentialRef,
		State:         "active",
		INCYDeepLink:  response.INCYDeepLink,
		ConfigPath:    response.ConfigPath,
	}, nil
}

func (r *Reality) Revoke(ctx context.Context, credentialRef string) error {
	if !validRealityCredentialRef(credentialRef) {
		return errors.New("invalid Reality credential reference")
	}
	payload, err := json.Marshal(helperRequest{Version: helperProtocol, Credential: credentialRef})
	if err != nil {
		return errors.New("encode Reality helper request")
	}
	callCtx, cancel := context.WithTimeout(ctx, r.callTimeout())
	defer cancel()
	output, err := r.runner.Run(callCtx, "revoke", payload)
	if err != nil {
		return errors.New("Reality helper could not revoke device")
	}
	var response revokeResponse
	if err := decodeHelperResponse(output, &response); err != nil || response.Version != helperProtocol ||
		(response.State != "revoked" && response.State != "absent") {
		return errors.New("Reality helper returned an invalid revoke response")
	}
	return nil
}

func (r *Reality) ClientConfig(ctx context.Context, credentialRef string) (ClientConfig, error) {
	if !validRealityCredentialRef(credentialRef) {
		return ClientConfig{}, errors.New("invalid Reality credential reference")
	}
	payload, err := json.Marshal(helperRequest{Version: helperProtocol, Credential: credentialRef})
	if err != nil {
		return ClientConfig{}, errors.New("encode Reality helper request")
	}
	callCtx, cancel := context.WithTimeout(ctx, r.callTimeout())
	defer cancel()
	output, err := r.runner.Run(callCtx, "config", payload)
	if err != nil {
		return ClientConfig{}, errors.New("Reality helper could not read device config")
	}
	var response configResponse
	if err := decodeHelperResponse(output, &response); err != nil || response.Version != helperProtocol ||
		!safeVLESSURI(response.VLESSURI) || !safeINCYDeepLink(response.INCYDeepLink) {
		return ClientConfig{}, errors.New("Reality helper returned an invalid config response")
	}
	return ClientConfig{VLESSURI: response.VLESSURI, INCYDeepLink: response.INCYDeepLink}, nil
}

func (r *Reality) bestEffortRevoke(parent context.Context, credentialRef string) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), r.callTimeout())
	defer cancel()
	_ = r.Revoke(cleanupCtx, credentialRef)
}

func (r *Reality) callTimeout() time.Duration {
	if r.timeout <= 0 {
		return 15 * time.Second
	}
	return r.timeout
}

func (sudoHelperRunner) Run(ctx context.Context, action string, input []byte) ([]byte, error) {
	if action != "provision" && action != "revoke" && action != "config" {
		return nil, errors.New("unsupported Reality helper action")
	}
	if filepath.Clean(RealityHelperPath) != RealityHelperPath {
		return nil, errors.New("invalid Reality helper path")
	}
	command := exec.CommandContext(ctx, "sudo", "--non-interactive", "--", RealityHelperPath, action)
	command.Stdin = bytes.NewReader(input)
	var stdout limitedBuffer
	var stderr limitedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		// Helper output can contain a one-time credential if the helper is buggy;
		// intentionally do not include stdout or stderr in the returned error.
		return nil, errors.New("Reality helper execution failed")
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("Reality helper output exceeded limit")
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	remaining := maxHelperOutput - b.buffer.Len()
	if remaining > 0 {
		written := len(value)
		if written > remaining {
			written = remaining
		}
		_, _ = b.buffer.Write(value[:written])
	}
	if len(value) > remaining {
		b.overflow = true
	}
	return len(value), nil
}

func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func decodeHelperResponse(output []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing data in helper response")
	}
	return nil
}

func validateDeviceRequest(request DeviceRequest) error {
	if !deviceIDPattern.MatchString(request.DeviceID) {
		return errors.New("invalid device id")
	}
	if !safeLabel(request.RelativeName) || !safeLabel(request.DeviceName) {
		return errors.New("invalid device label")
	}
	switch request.Platform {
	case "android", "ios", "ipad", "windows", "macos", "linux":
		return nil
	default:
		return errors.New("invalid device platform")
	}
}

func safeLabel(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > 100 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func realityCredentialRef(deviceID string) string { return "vless-reality:" + deviceID }

func validRealityCredentialRef(value string) bool {
	return strings.HasPrefix(value, "vless-reality:") && deviceIDPattern.MatchString(strings.TrimPrefix(value, "vless-reality:"))
}

func safeINCYDeepLink(value string) bool {
	if len(value) == 0 || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "incy" && strings.HasPrefix(value, "incy://") && parsed.User == nil
}

func safeVLESSURI(value string) bool {
	if len(value) == 0 || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil || parsed.Hostname() == "" || parsed.Path != "" {
		return false
	}
	if _, hasPassword := parsed.User.Password(); hasPassword || !uuidPattern.MatchString(parsed.User.Username()) {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	query := parsed.Query()
	return query.Get("security") == "reality" && query.Get("sni") != "" && query.Get("pbk") != ""
}

func safeDeviceConfigPath(value, deviceID string) bool {
	if value == "" {
		return true
	}
	expected := fmt.Sprintf("/api/v1/devices/%s/config", deviceID)
	return value == expected
}
