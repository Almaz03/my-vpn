package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

var (
	ErrInvalidInvitation       = errors.New("invitation is invalid")
	ErrUsedInvitation          = errors.New("invitation was already used")
	ErrExpiredInvitation       = errors.New("invitation expired")
	ErrRevokedInvitation       = errors.New("invitation revoked")
	ErrTooManyAttempts         = errors.New("invitation attempt limit reached")
	ErrDeviceNotFound          = errors.New("device not found")
	ErrInvitationCreationLimit = errors.New("invitation creation limit reached")
	ErrSubscriptionNotFound    = errors.New("subscription is invalid or expired")
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

type Invitation struct {
	ID           string     `json:"id"`
	RelativeName string     `json:"relative_name"`
	DeviceName   string     `json:"device_name"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

type Device struct {
	ID            string     `json:"id"`
	InvitationID  string     `json:"invitation_id,omitempty"`
	RelativeName  string     `json:"relative_name"`
	DeviceName    string     `json:"device_name"`
	Platform      string     `json:"platform"`
	CredentialRef string     `json:"-"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
}

type Subscription struct {
	DeviceID      string
	CredentialRef string
	ExpiresAt     time.Time
}

type Stats struct {
	InvitationsOpen int `json:"invitations_open"`
	DevicesActive   int `json:"devices_active"`
	DevicesPending  int `json:"devices_pending"`
	DevicesRevoked  int `json:"devices_revoked"`
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("empty database path")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection plus BEGIN IMMEDIATE gives deterministic serialization
	// for one-time-code consumption without relying on process-local locks.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate sqlite: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) CreateInvitation(ctx context.Context, hash []byte, relativeName, deviceName string, expiresAt time.Time, maxAttempts int) (Invitation, error) {
	id, err := randomID()
	if err != nil {
		return Invitation{}, err
	}
	now := s.now().UTC().Truncate(time.Second)
	invitation := Invitation{ID: id, RelativeName: relativeName, DeviceName: deviceName, ExpiresAt: expiresAt.UTC().Truncate(time.Second), CreatedAt: now}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, fmt.Errorf("begin invitation creation: %w", err)
	}
	defer tx.Rollback()
	cutoff := now.Add(-10 * time.Minute).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_invitation_creations WHERE created_at < ?`, cutoff); err != nil {
		return Invitation{}, fmt.Errorf("prune invitation creation limit: %w", err)
	}
	var recent int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_invitation_creations`).Scan(&recent); err != nil {
		return Invitation{}, fmt.Errorf("count invitation creations: %w", err)
	}
	if recent >= 5 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, detail, created_at) VALUES('invitation.rate_limited', 'admin', ?)`, now.Unix()); err != nil {
			return Invitation{}, fmt.Errorf("audit invitation rate limit: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return Invitation{}, fmt.Errorf("commit invitation rate limit: %w", err)
		}
		return Invitation{}, ErrInvitationCreationLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_invitation_creations(created_at) VALUES(?)`, now.Unix()); err != nil {
		return Invitation{}, fmt.Errorf("record invitation creation: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO invitations
        (id, code_hmac, relative_name, device_name, expires_at, max_attempts, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`, id, hash, relativeName, deviceName, invitation.ExpiresAt.Unix(), maxAttempts, now.Unix())
	if err != nil {
		return Invitation{}, fmt.Errorf("insert invitation: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at) VALUES('invitation.created', ?, '', ?)`, id, now.Unix()); err != nil {
		return Invitation{}, fmt.Errorf("audit invitation creation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, fmt.Errorf("commit invitation creation: %w", err)
	}
	return invitation, nil
}

func (s *Store) RevokeInvitation(ctx context.Context, id string) error {
	now := s.now().UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE invitations SET revoked_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, now.Unix(), id)
	if err != nil {
		return fmt.Errorf("revoke invitation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrInvalidInvitation
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at) VALUES('invitation.revoked', ?, '', ?)`, id, now.Unix()); err != nil {
		return fmt.Errorf("audit invitation revoke: %w", err)
	}
	return tx.Commit()
}

func (s *Store) ExtendInvitation(ctx context.Context, id string, expiresAt time.Time) (Invitation, error) {
	now := s.now().UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) || expiresAt.After(now.Add(time.Hour)) {
		return Invitation{}, errors.New("expiry must be within the next hour")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE invitations SET expires_at = ?
		WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, expiresAt.Unix(), id)
	if err != nil {
		return Invitation{}, fmt.Errorf("extend invitation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Invitation{}, ErrInvalidInvitation
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at)
		VALUES('invitation.extended', ?, '', ?)`, id, now.Unix()); err != nil {
		return Invitation{}, fmt.Errorf("audit invitation extension: %w", err)
	}
	invitation, err := queryInvitation(ctx, tx, id)
	if err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, err
	}
	return invitation, nil
}

func (s *Store) ListInvitations(ctx context.Context) ([]Invitation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, relative_name, device_name, expires_at, created_at, used_at, revoked_at
		FROM invitations ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()
	var invitations []Invitation
	for rows.Next() {
		invitation, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		invitations = append(invitations, invitation)
	}
	return invitations, rows.Err()
}

func (s *Store) ConsumeInvitation(ctx context.Context, hash []byte, platform, requestedDeviceName, remoteIPHash string) (Device, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Device{}, fmt.Errorf("acquire sqlite connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return Device{}, fmt.Errorf("begin activation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	now := s.now().UTC().Truncate(time.Second)
	_, err = conn.ExecContext(ctx, `DELETE FROM code_attempts WHERE last_attempt_at < ?`, now.Add(-10*time.Minute).Unix())
	if err != nil {
		return Device{}, fmt.Errorf("prune code attempts: %w", err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO code_attempts(code_hmac, attempts, last_attempt_at) VALUES(?, 1, ?)
        ON CONFLICT(code_hmac) DO UPDATE SET attempts = attempts + 1, last_attempt_at = excluded.last_attempt_at`, hash, now.Unix())
	if err != nil {
		return Device{}, fmt.Errorf("record code attempt: %w", err)
	}
	var codeAttempts int
	if err := conn.QueryRowContext(ctx, `SELECT attempts FROM code_attempts WHERE code_hmac = ?`, hash).Scan(&codeAttempts); err != nil {
		return Device{}, fmt.Errorf("read code attempts: %w", err)
	}
	if codeAttempts > 5 {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return Device{}, fmt.Errorf("commit code attempt limit: %w", err)
		}
		committed = true
		return Device{}, ErrTooManyAttempts
	}

	var id, relativeName, deviceName string
	var expiresAt, usedAt, revokedAt sql.NullInt64
	var failedAttempts, maxAttempts int
	err = conn.QueryRowContext(ctx, `SELECT id, relative_name, device_name, expires_at, used_at, revoked_at, failed_attempts, max_attempts
        FROM invitations WHERE code_hmac = ?`, hash).Scan(&id, &relativeName, &deviceName, &expiresAt, &usedAt, &revokedAt, &failedAttempts, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		if _, commitErr := conn.ExecContext(ctx, "COMMIT"); commitErr != nil {
			return Device{}, fmt.Errorf("commit unknown code attempt: %w", commitErr)
		}
		committed = true
		return Device{}, ErrInvalidInvitation
	}
	if err != nil {
		return Device{}, fmt.Errorf("query invitation: %w", err)
	}

	rejection := error(nil)
	switch {
	case failedAttempts >= maxAttempts:
		rejection = ErrTooManyAttempts
	case revokedAt.Valid:
		rejection = ErrRevokedInvitation
	case usedAt.Valid:
		rejection = ErrUsedInvitation
	case !expiresAt.Valid || now.Unix() >= expiresAt.Int64:
		rejection = ErrExpiredInvitation
	}
	if rejection != nil {
		if _, err := conn.ExecContext(ctx, `UPDATE invitations SET failed_attempts = failed_attempts + 1 WHERE id = ?`, id); err != nil {
			return Device{}, fmt.Errorf("record invitation rejection: %w", err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, remote_ip_hmac, detail, created_at)
			VALUES('invitation.rejected', ?, ?, ?, ?)`, id, remoteIPHash, rejection.Error(), now.Unix()); err != nil {
			return Device{}, fmt.Errorf("audit invitation rejection: %w", err)
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return Device{}, fmt.Errorf("commit rejection audit: %w", err)
		}
		committed = true
		return Device{}, rejection
	}

	if clean := strings.TrimSpace(requestedDeviceName); clean != "" {
		deviceName = clean
	}
	deviceID, err := randomID()
	if err != nil {
		return Device{}, err
	}
	credentialRef := "pending:" + deviceID
	result, err := conn.ExecContext(ctx, `UPDATE invitations SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, now.Unix(), id)
	if err != nil {
		return Device{}, fmt.Errorf("consume invitation: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Device{}, ErrUsedInvitation
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO devices
        (id, invitation_id, relative_name, device_name, platform, credential_ref, state, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`, deviceID, id, relativeName, deviceName, platform, credentialRef, now.Unix())
	if err != nil {
		return Device{}, fmt.Errorf("insert device: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, remote_ip_hmac, detail, created_at)
		VALUES('invitation.used', ?, ?, ?, ?)`, deviceID, remoteIPHash, platform, now.Unix()); err != nil {
		return Device{}, fmt.Errorf("audit invitation use: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Device{}, fmt.Errorf("commit activation: %w", err)
	}
	committed = true
	return Device{ID: deviceID, InvitationID: id, RelativeName: relativeName, DeviceName: deviceName, Platform: platform, CredentialRef: credentialRef, State: "pending", CreatedAt: now}, nil
}

func (s *Store) AllowActivationAttempt(ctx context.Context, ipHash string, window time.Duration, perIPLimit, globalLimit int) (bool, time.Duration, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	now := s.now().UTC()
	var blockedUntil int64
	_ = conn.QueryRowContext(ctx, `SELECT blocked_until FROM rate_limit_state WHERE ip_hmac = ?`, ipHash).Scan(&blockedUntil)
	if blockedUntil > now.Unix() {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return false, 0, fmt.Errorf("commit activation backoff: %w", err)
		}
		committed = true
		return false, time.Unix(blockedUntil, 0).Sub(now), nil
	}
	cutoff := now.Add(-window).Unix()
	if _, err := conn.ExecContext(ctx, `DELETE FROM activation_attempts WHERE created_at < ?`, cutoff); err != nil {
		return false, 0, err
	}
	var perIP, global int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM activation_attempts WHERE ip_hmac = ?`, ipHash).Scan(&perIP); err != nil {
		return false, 0, err
	}
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM activation_attempts`).Scan(&global); err != nil {
		return false, 0, err
	}
	if perIP >= perIPLimit || global >= globalLimit {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return false, 0, fmt.Errorf("commit activation rate limit: %w", err)
		}
		committed = true
		return false, time.Minute, nil
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO activation_attempts(ip_hmac, created_at) VALUES(?, ?)`, ipHash, now.Unix()); err != nil {
		return false, 0, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return false, 0, err
	}
	committed = true
	return true, 0, nil
}

func (s *Store) ActivationFailure(ctx context.Context, ipHash string) error {
	now := s.now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO rate_limit_state(ip_hmac, failures, blocked_until) VALUES(?, 1, ?)
        ON CONFLICT(ip_hmac) DO UPDATE SET
          failures = MIN(failures + 1, 8),
          blocked_until = ? + MIN(30, (1 << MIN(failures, 5)))`, ipHash, now.Add(time.Second).Unix(), now.Unix())
	return err
}

func (s *Store) ActivationSuccess(ctx context.Context, ipHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM rate_limit_state WHERE ip_hmac = ?`, ipHash)
	return err
}

func (s *Store) CompensateActivation(ctx context.Context, deviceID, invitationID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND invitation_id = ? AND state = 'pending'`, deviceID, invitationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE invitations SET used_at = NULL WHERE id = ?`, invitationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at)
		VALUES('activation.compensated', ?, 'provisioner failed', ?)`, invitationID, s.now().UTC().Unix()); err != nil {
		return fmt.Errorf("audit activation compensation: %w", err)
	}
	return tx.Commit()
}

func (s *Store) UpdateProvisioned(ctx context.Context, id, credentialRef, state string) error {
	if state != "pending" && state != "active" {
		return fmt.Errorf("invalid provisioned state %q", state)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE devices SET credential_ref = ?, state = ? WHERE id = ? AND revoked_at IS NULL`, credentialRef, state, id)
	if err != nil {
		return fmt.Errorf("update provisioned device: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return ErrDeviceNotFound
	}
	return nil
}

func (s *Store) IssueSubscription(ctx context.Context, tokenHMAC []byte, deviceID string, expiresAt time.Time) error {
	if len(tokenHMAC) != 32 {
		return errors.New("invalid subscription token HMAC")
	}
	now := s.now().UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now) {
		return errors.New("subscription already expired")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM devices WHERE id = ?`, deviceID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		return err
	}
	if state != "pending" && state != "active" {
		return errors.New("device cannot receive a subscription")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_tokens SET revoked_at = ?
		WHERE device_id = ? AND revoked_at IS NULL`, now.Unix(), deviceID); err != nil {
		return fmt.Errorf("revoke previous subscription: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO subscription_tokens
		(token_hmac, device_id, expires_at, created_at) VALUES(?, ?, ?, ?)`,
		tokenHMAC, deviceID, expiresAt.Unix(), now.Unix()); err != nil {
		return fmt.Errorf("insert subscription token: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at)
		VALUES('subscription.issued', ?, '', ?)`, deviceID, now.Unix()); err != nil {
		return fmt.Errorf("audit subscription issue: %w", err)
	}
	return tx.Commit()
}

func (s *Store) ResolveSubscription(ctx context.Context, tokenHMAC []byte) (Subscription, error) {
	if len(tokenHMAC) != 32 {
		return Subscription{}, ErrSubscriptionNotFound
	}
	now := s.now().UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Subscription{}, err
	}
	defer tx.Rollback()
	var subscription Subscription
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT t.device_id, d.credential_ref, t.expires_at
		FROM subscription_tokens t JOIN devices d ON d.id = t.device_id
		WHERE t.token_hmac = ? AND t.revoked_at IS NULL AND t.expires_at > ?
		AND d.state = 'active' AND d.revoked_at IS NULL`, tokenHMAC, now.Unix()).
		Scan(&subscription.DeviceID, &subscription.CredentialRef, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Subscription{}, ErrSubscriptionNotFound
	}
	if err != nil {
		return Subscription{}, fmt.Errorf("resolve subscription: %w", err)
	}
	subscription.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_tokens SET last_used_at = ? WHERE token_hmac = ?`, now.Unix(), tokenHMAC); err != nil {
		return Subscription{}, fmt.Errorf("touch subscription: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Subscription{}, err
	}
	return subscription, nil
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var stats Stats
	now := s.now().UTC().Unix()
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM invitations
		WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, now).Scan(&stats.InvitationsOpen); err != nil {
		return Stats{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT state, COUNT(*) FROM devices GROUP BY state`)
	if err != nil {
		return Stats{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return Stats{}, err
		}
		switch state {
		case "active":
			stats.DevicesActive = count
		case "pending", "revoke_pending":
			stats.DevicesPending += count
		case "revoked":
			stats.DevicesRevoked = count
		}
	}
	return stats, rows.Err()
}

func (s *Store) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, invitation_id, relative_name, device_name, platform, credential_ref, state, created_at, revoked_at
        FROM devices ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	var devices []Device
	for rows.Next() {
		var device Device
		var created int64
		var revoked sql.NullInt64
		if err := rows.Scan(&device.ID, &device.InvitationID, &device.RelativeName, &device.DeviceName, &device.Platform, &device.CredentialRef, &device.State, &created, &revoked); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		device.CreatedAt = time.Unix(created, 0).UTC()
		if revoked.Valid {
			value := time.Unix(revoked.Int64, 0).UTC()
			device.RevokedAt = &value
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) BeginDeviceRevoke(ctx context.Context, id string) (Device, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, false, err
	}
	defer tx.Rollback()
	device, err := queryDevice(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, false, ErrDeviceNotFound
	}
	if err != nil {
		return Device{}, false, err
	}
	if device.State == "revoked" && device.RevokedAt != nil {
		return device, true, tx.Commit()
	}
	if device.State != "revoke_pending" {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET state = 'revoke_pending', revoked_at = NULL WHERE id = ?`, id); err != nil {
			return Device{}, false, fmt.Errorf("mark revoke pending: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at)
			VALUES('device.revoke_pending', ?, '', ?)`, id, s.now().UTC().Unix()); err != nil {
			return Device{}, false, fmt.Errorf("audit revoke pending: %w", err)
		}
		device.State = "revoke_pending"
		device.RevokedAt = nil
	}
	if err := tx.Commit(); err != nil {
		return Device{}, false, err
	}
	return device, false, nil
}

func (s *Store) CompleteDeviceRevoke(ctx context.Context, id string) (Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	device, err := queryDevice(ctx, tx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	if err != nil {
		return Device{}, err
	}
	if device.State == "revoked" && device.RevokedAt != nil {
		return device, tx.Commit()
	}
	now := s.now().UTC().Truncate(time.Second)
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET state = 'revoked', revoked_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
		return Device{}, fmt.Errorf("complete device revoke: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE subscription_tokens SET revoked_at = ?
		WHERE device_id = ? AND revoked_at IS NULL`, now.Unix(), id); err != nil {
		return Device{}, fmt.Errorf("revoke device subscriptions: %w", err)
	}
	device.RevokedAt = &now
	device.State = "revoked"
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type, subject_id, detail, created_at)
		VALUES('device.revoked', ?, '', ?)`, id, now.Unix()); err != nil {
		return Device{}, fmt.Errorf("audit device revoke: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return device, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type invitationScanner interface {
	Scan(...any) error
}

func scanInvitation(row invitationScanner) (Invitation, error) {
	var invitation Invitation
	var expires, created int64
	var used, revoked sql.NullInt64
	if err := row.Scan(&invitation.ID, &invitation.RelativeName, &invitation.DeviceName,
		&expires, &created, &used, &revoked); err != nil {
		return Invitation{}, fmt.Errorf("scan invitation: %w", err)
	}
	invitation.ExpiresAt = time.Unix(expires, 0).UTC()
	invitation.CreatedAt = time.Unix(created, 0).UTC()
	if used.Valid {
		value := time.Unix(used.Int64, 0).UTC()
		invitation.UsedAt = &value
	}
	if revoked.Valid {
		value := time.Unix(revoked.Int64, 0).UTC()
		invitation.RevokedAt = &value
	}
	return invitation, nil
}

func queryInvitation(ctx context.Context, query queryRower, id string) (Invitation, error) {
	return scanInvitation(query.QueryRowContext(ctx, `SELECT id, relative_name, device_name, expires_at, created_at, used_at, revoked_at
		FROM invitations WHERE id = ?`, id))
}

func queryDevice(ctx context.Context, query queryRower, id string) (Device, error) {
	var device Device
	var created int64
	var revoked sql.NullInt64
	err := query.QueryRowContext(ctx, `SELECT id, invitation_id, relative_name, device_name, platform, credential_ref, state, created_at, revoked_at
		FROM devices WHERE id = ?`, id).Scan(&device.ID, &device.InvitationID, &device.RelativeName, &device.DeviceName, &device.Platform, &device.CredentialRef, &device.State, &created, &revoked)
	if err != nil {
		return Device{}, err
	}
	device.CreatedAt = time.Unix(created, 0).UTC()
	if revoked.Valid {
		value := time.Unix(revoked.Int64, 0).UTC()
		device.RevokedAt = &value
	}
	return device, nil
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
