package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

const (
	helperProtocol  = 1
	maxHelperOutput = 64 << 10
)

var deviceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type ClientConfig struct {
	Body        string
	ContentType string
	Filename    string
	QRContent   string
}

type ConfigProvider interface {
	ClientConfig(context.Context, string) (ClientConfig, error)
}

type helperRunner interface {
	Run(context.Context, string, []byte) ([]byte, error)
}

type helperRequest struct {
	Version      int    `json:"version"`
	DeviceID     string `json:"device_id,omitempty"`
	RelativeName string `json:"relative_name,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Credential   string `json:"credential_ref,omitempty"`
}

type provisionResponse struct {
	Version    int    `json:"version"`
	State      string `json:"state"`
	ConfigPath string `json:"config_path,omitempty"`
}

type revokeResponse struct {
	Version int    `json:"version"`
	State   string `json:"state"`
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

func safeDeviceConfigPath(value, deviceID string) bool {
	return value == fmt.Sprintf("/api/v1/devices/%s/config", deviceID)
}
