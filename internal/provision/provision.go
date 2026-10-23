package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type DeviceRequest struct {
	DeviceID     string
	RelativeName string
	DeviceName   string
	Platform     string
}

type Result struct {
	CredentialRef string
	State         string
	INCYDeepLink  string
	ConfigPath    string
}

type Provisioner interface {
	Provision(context.Context, DeviceRequest) (Result, error)
	Revoke(context.Context, string) error
}

// Noop deliberately never invokes Docker, WireGuard or Amnezia. It records a
// unique opaque reference so the control-plane can be exercised safely before a
// production adapter is explicitly implemented and reviewed.
type Noop struct{}

func (Noop) Provision(_ context.Context, request DeviceRequest) (Result, error) {
	return Result{CredentialRef: "pending:" + request.DeviceID, State: "pending"}, nil
}

func (Noop) Revoke(context.Context, string) error { return nil }

func RandomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
