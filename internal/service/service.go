package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Almaz03/my-vpn/internal/codes"
	"github.com/Almaz03/my-vpn/internal/provision"
	"github.com/Almaz03/my-vpn/internal/store"
)

type Service struct {
	store       *store.Store
	provisioner provision.Provisioner
	hmacKey     []byte
	baseURL     *url.URL
	now         func() time.Time
}

type Activation struct {
	Device            store.Device
	INCYDeepLink      string
	ConfigDownloadURL string
	QRCodeURL         string
	Message           string
}

var (
	ErrProvisioning  = errors.New("device provisioning failed")
	ErrRevokePending = errors.New("device revoke remains pending")
)

func New(database *store.Store, provisioner provision.Provisioner, hmacKey []byte, baseURL *url.URL) *Service {
	return &Service{store: database, provisioner: provisioner, hmacKey: hmacKey, baseURL: baseURL, now: time.Now}
}

func (s *Service) CreateInvitation(ctx context.Context, relativeName, deviceName string, ttl time.Duration) (store.Invitation, string, error) {
	relativeName = strings.TrimSpace(relativeName)
	deviceName = strings.TrimSpace(deviceName)
	if relativeName == "" || len(relativeName) > 100 {
		return store.Invitation{}, "", errors.New("relative_name must contain 1 to 100 characters")
	}
	if deviceName == "" || len(deviceName) > 100 {
		return store.Invitation{}, "", errors.New("device_name must contain 1 to 100 characters")
	}
	if ttl < time.Minute || ttl > time.Hour {
		return store.Invitation{}, "", errors.New("ttl must be between 1 minute and 1 hour")
	}
	code, err := codes.Generate()
	if err != nil {
		return store.Invitation{}, "", err
	}
	invitation, err := s.store.CreateInvitation(ctx, codes.HMAC(s.hmacKey, code), relativeName, deviceName, s.now().Add(ttl), 5)
	if err != nil {
		return store.Invitation{}, "", err
	}
	return invitation, code, nil
}

func (s *Service) Activate(ctx context.Context, code, platform, requestedDeviceName, remoteIP string) (Activation, error) {
	if !codes.Valid(code) {
		return Activation{}, store.ErrInvalidInvitation
	}
	platform = strings.ToLower(strings.TrimSpace(platform))
	if !supportedPlatform(platform) {
		return Activation{}, errors.New("unsupported platform")
	}
	if len(requestedDeviceName) > 100 {
		return Activation{}, errors.New("device_name is too long")
	}
	device, err := s.store.ConsumeInvitation(ctx, codes.HMAC(s.hmacKey, code), platform, requestedDeviceName, s.ipHash(remoteIP))
	if err != nil {
		return Activation{}, err
	}
	result, provisionErr := s.provisioner.Provision(ctx, provision.DeviceRequest{
		DeviceID: device.ID, RelativeName: device.RelativeName, DeviceName: device.DeviceName, Platform: device.Platform,
	})
	activation := Activation{Device: device, Message: "Устройство зарегистрировано; VPN-профиль ожидает безопасной выдачи администратором."}
	if provisionErr != nil {
		return Activation{}, s.compensateProvisioning(ctx, device, result, provisionErr)
	}
	if err := validateProvisionResult(result); err != nil {
		return Activation{}, s.compensateProvisioning(ctx, device, result, err)
	}
	if err := s.store.UpdateProvisioned(ctx, device.ID, result.CredentialRef, result.State); err != nil {
		return Activation{}, s.compensateProvisioning(ctx, device, result, err)
	}
	activation.Device.CredentialRef = result.CredentialRef
	activation.Device.State = result.State
	if strings.HasPrefix(result.INCYDeepLink, "incy://") {
		activation.INCYDeepLink = result.INCYDeepLink
	}
	if safeRelativePath(result.ConfigPath) {
		activation.ConfigDownloadURL = s.baseURL.ResolveReference(&url.URL{Path: result.ConfigPath}).String()
		activation.QRCodeURL = s.baseURL.ResolveReference(&url.URL{Path: "/api/v1/devices/" + device.ID + "/qr"}).String()
	}
	if activation.Device.State == "active" {
		activation.Message = "VPN-профиль готов к импорту."
	}
	return activation, nil
}

func (s *Service) AllowActivationAttempt(ctx context.Context, remoteIP string) (bool, time.Duration, error) {
	return s.store.AllowActivationAttempt(ctx, s.ipHash(remoteIP), 10*time.Minute, 10, 200)
}

func (s *Service) ActivationFailure(ctx context.Context, remoteIP string) error {
	return s.store.ActivationFailure(ctx, s.ipHash(remoteIP))
}

func (s *Service) ActivationSuccess(ctx context.Context, remoteIP string) error {
	return s.store.ActivationSuccess(ctx, s.ipHash(remoteIP))
}

func (s *Service) ipHash(remoteIP string) string {
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte("remote-ip:\x00" + remoteIP))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) ListDevices(ctx context.Context) ([]store.Device, error) {
	return s.store.ListDevices(ctx)
}

func (s *Service) RevokeInvitation(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return store.ErrInvalidInvitation
	}
	return s.store.RevokeInvitation(ctx, id)
}

func (s *Service) Revoke(ctx context.Context, id string) (store.Device, error) {
	target, complete, err := s.store.BeginDeviceRevoke(ctx, id)
	if err != nil {
		return store.Device{}, err
	}
	if complete {
		return target, nil
	}
	if err := s.provisioner.Revoke(ctx, target.CredentialRef); err != nil {
		return target, fmt.Errorf("%w: %v", ErrRevokePending, err)
	}
	return s.store.CompleteDeviceRevoke(ctx, id)
}

func (s *Service) compensateProvisioning(ctx context.Context, device store.Device, result provision.Result, cause error) error {
	var cleanupErr error
	if validCredentialRef(result.CredentialRef) {
		cleanupErr = s.provisioner.Revoke(ctx, result.CredentialRef)
	}
	compensateErr := s.store.CompensateActivation(ctx, device.ID, device.InvitationID)
	return errors.Join(ErrProvisioning, cause, cleanupErr, compensateErr)
}

func validateProvisionResult(result provision.Result) error {
	if !validCredentialRef(result.CredentialRef) {
		return errors.New("provisioner returned an invalid credential reference")
	}
	if result.State != "pending" && result.State != "active" {
		return errors.New("provisioner returned an invalid state")
	}
	if result.INCYDeepLink != "" {
		parsed, err := url.Parse(result.INCYDeepLink)
		if err != nil || parsed.Scheme != "incy" || !strings.HasPrefix(result.INCYDeepLink, "incy://") {
			return errors.New("provisioner returned an invalid INCY deep link")
		}
	}
	if result.ConfigPath != "" && !safeRelativePath(result.ConfigPath) {
		return errors.New("provisioner returned an unsafe config path")
	}
	if result.State == "active" && result.INCYDeepLink == "" && result.ConfigPath == "" {
		return errors.New("active provisioner result has no import mechanism")
	}
	return nil
}

func validCredentialRef(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 512 && !strings.ContainsAny(value, "\r\n\x00")
}

func supportedPlatform(platform string) bool {
	switch platform {
	case "android", "ios", "ipad", "windows", "macos", "linux":
		return true
	default:
		return false
	}
}

func safeRelativePath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return false
	}
	parsed, err := url.Parse(path)
	return err == nil && parsed.IsAbs() == false && parsed.Host == "" && parsed.User == nil && !strings.Contains(path, "..")
}
