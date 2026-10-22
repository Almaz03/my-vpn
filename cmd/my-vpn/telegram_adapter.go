package main

import (
	"context"
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/Almaz03/my-vpn/internal/service"
	"github.com/Almaz03/my-vpn/internal/store"
	"github.com/Almaz03/my-vpn/internal/telegram"
)

type telegramAdapter struct {
	service         *service.Service
	store           *store.Store
	provisionerMode string
}

func (a telegramAdapter) CreateInvitation(ctx context.Context, relativeName, deviceName string, ttl time.Duration) (telegram.Invitation, error) {
	invitation, code, err := a.service.CreateInvitation(ctx, relativeName, deviceName, ttl)
	if err != nil {
		return telegram.Invitation{}, err
	}
	return telegram.Invitation{Code: code, ExpiresAt: invitation.ExpiresAt}, nil
}

func (a telegramAdapter) ListDevices(ctx context.Context) ([]telegram.Device, error) {
	devices, err := a.service.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]telegram.Device, 0, len(devices))
	for _, device := range devices {
		result = append(result, telegram.Device{
			ID: device.ID, RelativeName: device.RelativeName, DeviceName: device.DeviceName,
			Platform: device.Platform, State: device.State, Revoked: device.RevokedAt != nil,
		})
	}
	return result, nil
}

func (a telegramAdapter) RevokeDevice(ctx context.Context, id string) error {
	_, err := a.service.Revoke(ctx, id)
	return err
}

func (a telegramAdapter) SystemStatus(ctx context.Context) (telegram.SystemStatus, error) {
	if err := a.store.Ping(ctx); err != nil {
		return telegram.SystemStatus{}, err
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	disk := "недоступно"
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/var/lib/my-vpn", &stat); err == nil && stat.Blocks > 0 {
		freeGiB := float64(stat.Bavail*uint64(stat.Bsize)) / (1 << 30)
		disk = fmt.Sprintf("%.1f GiB свободно", freeGiB)
	}
	return telegram.SystemStatus{
		Portal: "ok", VPN: a.provisionerMode, Certificate: "Caddy auto-TLS",
		CPU: fmt.Sprintf("%d vCPU", runtime.NumCPU()), Memory: fmt.Sprintf("%.1f MiB app", float64(memory.Alloc)/(1<<20)),
		Disk: disk, Network: "портал 443/tcp; Reality 8443/tcp",
	}, nil
}
