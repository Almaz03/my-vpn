package service

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/store"
)

type failingProvisioner struct{}

func (failingProvisioner) Provision(context.Context, provision.DeviceRequest) (provision.Result, error) {
	return provision.Result{}, errors.New("offline")
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
	idempotent, err := application.Revoke(context.Background(), activation.Device.ID)
	if err != nil || idempotent.State != "revoked" {
		t.Fatalf("idempotent=%#v err=%v", idempotent, err)
	}
}
