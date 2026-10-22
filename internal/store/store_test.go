package store

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	database, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestConcurrentInvitationConsumptionHasOneWinner(t *testing.T) {
	database := testStore(t)
	hash := bytes.Repeat([]byte{1}, 32)
	if _, err := database.CreateInvitation(context.Background(), hash, "Мама", "Телефон", time.Now().Add(time.Hour), 5); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wait sync.WaitGroup
	for range 12 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := database.ConsumeInvitation(context.Background(), hash, "android", "", "ip-hmac")
			if err == nil {
				successes.Add(1)
				return
			}
			if !errors.Is(err, ErrUsedInvitation) && !errors.Is(err, ErrTooManyAttempts) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful activations = %d, want 1", got)
	}
}

func TestUnknownCodeAttemptLimitIsPersistent(t *testing.T) {
	database := testStore(t)
	hash := bytes.Repeat([]byte{9}, 32)
	for attempt := 1; attempt <= 5; attempt++ {
		_, err := database.ConsumeInvitation(context.Background(), hash, "android", "", "ip-hmac")
		if !errors.Is(err, ErrInvalidInvitation) {
			t.Fatalf("attempt %d error = %v", attempt, err)
		}
	}
	_, err := database.ConsumeInvitation(context.Background(), hash, "android", "", "ip-hmac")
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("sixth error = %v, want attempt limit", err)
	}
}

func TestExpiredInvitationIsRejected(t *testing.T) {
	database := testStore(t)
	hash := bytes.Repeat([]byte{2}, 32)
	if _, err := database.CreateInvitation(context.Background(), hash, "Папа", "Ноутбук", time.Now().Add(-time.Minute), 5); err != nil {
		t.Fatal(err)
	}
	_, err := database.ConsumeInvitation(context.Background(), hash, "linux", "", "ip-hmac")
	if !errors.Is(err, ErrExpiredInvitation) {
		t.Fatalf("error = %v, want expired", err)
	}
}

func TestInvitationCreationLimitIsPersistent(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	for index := byte(1); index <= 5; index++ {
		hash := bytes.Repeat([]byte{index}, 32)
		if _, err := database.CreateInvitation(context.Background(), hash, "Семья", "Устройство", now.Add(time.Hour), 5); err != nil {
			t.Fatalf("creation %d: %v", index, err)
		}
	}
	_, err := database.CreateInvitation(context.Background(), bytes.Repeat([]byte{8}, 32), "Семья", "Устройство", now.Add(time.Hour), 5)
	if !errors.Is(err, ErrInvitationCreationLimit) {
		t.Fatalf("sixth creation error = %v", err)
	}
	var auditCount int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'invitation.rate_limited'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("rate-limit audit count=%d err=%v", auditCount, err)
	}
}

func TestActivationBackoffStartsAtOneSecond(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	if err := database.ActivationFailure(context.Background(), "ip-hmac"); err != nil {
		t.Fatal(err)
	}
	allowed, retry, err := database.AllowActivationAttempt(context.Background(), "ip-hmac", 10*time.Minute, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if allowed || retry < time.Second {
		t.Fatalf("allowed=%v retry=%s, want at least 1s", allowed, retry)
	}
}

func TestRevokePendingDoesNotSetRevokedAtAndCanRetry(t *testing.T) {
	database := testStore(t)
	hash := bytes.Repeat([]byte{6}, 32)
	invitation, err := database.CreateInvitation(context.Background(), hash, "Семья", "Телефон", time.Now().Add(time.Hour), 5)
	if err != nil {
		t.Fatal(err)
	}
	device, err := database.ConsumeInvitation(context.Background(), hash, "android", "", "ip-hmac")
	if err != nil {
		t.Fatal(err)
	}
	pending, complete, err := database.BeginDeviceRevoke(context.Background(), device.ID)
	if err != nil || complete || pending.State != "revoke_pending" || pending.RevokedAt != nil {
		t.Fatalf("pending=%#v complete=%v err=%v invitation=%s", pending, complete, err, invitation.ID)
	}
	retry, complete, err := database.BeginDeviceRevoke(context.Background(), device.ID)
	if err != nil || complete || retry.RevokedAt != nil {
		t.Fatalf("retry=%#v complete=%v err=%v", retry, complete, err)
	}
	revoked, err := database.CompleteDeviceRevoke(context.Background(), device.ID)
	if err != nil || revoked.State != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked=%#v err=%v", revoked, err)
	}
	if _, _, err := database.BeginDeviceRevoke(context.Background(), device.ID); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("deleted device lookup error=%v", err)
	}
	devices, err := database.ListDevices(context.Background())
	if err != nil || len(devices) != 0 {
		t.Fatalf("devices after revoke=%d err=%v", len(devices), err)
	}
}

func TestOpenPurgesLegacyRevokedDevicesAndSubscriptions(t *testing.T) {
	path := t.TempDir() + "/test.db"
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := bytes.Repeat([]byte{12}, 32)
	if _, err := database.CreateInvitation(context.Background(), hash, "Семья", "Старый телефон", time.Now().Add(time.Hour), 5); err != nil {
		t.Fatal(err)
	}
	device, err := database.ConsumeInvitation(context.Background(), hash, "android", "", "ip-hmac")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateProvisioned(context.Background(), device.ID, "vless-reality:"+device.ID, "active"); err != nil {
		t.Fatal(err)
	}
	if err := database.IssueSubscription(context.Background(), bytes.Repeat([]byte{13}, 32), device.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.Exec(`UPDATE devices SET state = 'revoked', revoked_at = ? WHERE id = ?`, time.Now().Unix(), device.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var devices, subscriptions int
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRow(`SELECT COUNT(*) FROM subscription_tokens`).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if devices != 0 || subscriptions != 0 {
		t.Fatalf("devices=%d subscriptions=%d", devices, subscriptions)
	}
}

func TestSubscriptionExpiresAndDeviceRevokeInvalidatesToken(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	inviteHash := bytes.Repeat([]byte{7}, 32)
	if _, err := database.CreateInvitation(context.Background(), inviteHash, "Семья", "Телефон", now.Add(time.Hour), 5); err != nil {
		t.Fatal(err)
	}
	device, err := database.ConsumeInvitation(context.Background(), inviteHash, "android", "", "ip-hmac")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.UpdateProvisioned(context.Background(), device.ID, "vless-reality:"+device.ID, "active"); err != nil {
		t.Fatal(err)
	}
	tokenHash := bytes.Repeat([]byte{8}, 32)
	if err := database.IssueSubscription(context.Background(), tokenHash, device.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ResolveSubscription(context.Background(), tokenHash); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * time.Second)
	if _, err := database.ResolveSubscription(context.Background(), tokenHash); !errors.Is(err, ErrSubscriptionNotFound) {
		t.Fatalf("expired subscription error=%v", err)
	}

	newHash := bytes.Repeat([]byte{9}, 32)
	if err := database.IssueSubscription(context.Background(), newHash, device.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.BeginDeviceRevoke(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ResolveSubscription(context.Background(), newHash); !errors.Is(err, ErrSubscriptionNotFound) {
		t.Fatalf("revoke-pending subscription error=%v", err)
	}
}

func TestInvitationCanBeExtendedButNotAfterUse(t *testing.T) {
	database := testStore(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	database.now = func() time.Time { return now }
	hash := bytes.Repeat([]byte{10}, 32)
	invitation, err := database.CreateInvitation(context.Background(), hash, "Семья", "Планшет", now.Add(time.Minute), 5)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := database.ExtendInvitation(context.Background(), invitation.ID, now.Add(30*time.Minute))
	if err != nil || !extended.ExpiresAt.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("extended=%#v err=%v", extended, err)
	}
	if _, err := database.ConsumeInvitation(context.Background(), hash, "ipad", "", "ip-hmac"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExtendInvitation(context.Background(), invitation.ID, now.Add(40*time.Minute)); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("extension after use error=%v", err)
	}
}
