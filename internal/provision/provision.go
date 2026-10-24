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
	ConfigPath    string
}

type Provisioner interface {
	Provision(context.Context, DeviceRequest) (Result, error)
	Revoke(context.Context, string) error
}

type TrafficCounter struct {
	DeviceID string
	Edge     string
	Uplink   int64
	Downlink int64
}

// TrafficProvider exposes byte counters only. It deliberately contains no
// destinations, domains, IP addresses or connection logs.
type TrafficProvider interface {
	TrafficSnapshot(context.Context) ([]TrafficCounter, error)
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
