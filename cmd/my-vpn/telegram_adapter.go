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
		traffic, trafficErr := a.service.DeviceTraffic(ctx, device.ID)
		if trafficErr != nil {
			return nil, trafficErr
		}
		result = append(result, telegram.Device{
			ID: device.ID, RelativeName: device.RelativeName, DeviceName: device.DeviceName,
			Platform: device.Platform, State: device.State, Revoked: device.RevokedAt != nil,
			CreatedAt: device.CreatedAt, LastSeenAt: traffic.LastSeenAt, LastEdge: traffic.LastEdge,
			Bytes24Hours: traffic.Bytes24Hours, BytesMonth: traffic.BytesMonth,
		})
	}
	return result, nil
}

func (a telegramAdapter) TrafficSummary(ctx context.Context) ([]telegram.EdgeTraffic, error) {
	edges, err := a.service.EdgeTraffic(ctx)
	if err != nil {
		return nil, err
	}
	values := map[string]store.EdgeTraffic{}
	for _, edge := range edges {
		values[edge.Edge] = edge
	}
	return []telegram.EdgeTraffic{
		{Edge: "lt", Bytes24Hours: values["lt"].Bytes24Hours, BytesMonth: values["lt"].BytesMonth},
		{Edge: "fi", Bytes24Hours: values["fi"].Bytes24Hours, BytesMonth: values["fi"].BytesMonth},
	}, nil
}

func (a telegramAdapter) RevokeDevice(ctx context.Context, id string) error {
	_, err := a.service.Revoke(ctx, id)
	return err
}

func (a telegramAdapter) ApproveAccessRequest(ctx context.Context, id string) (telegram.Invitation, error) {
	request, err := a.service.ApproveAccessRequest(ctx, id)
	if err != nil {
		return telegram.Invitation{}, err
	}
	return telegram.Invitation{Code: request.Code, ExpiresAt: request.ExpiresAt}, nil
}

func (a telegramAdapter) DenyAccessRequest(ctx context.Context, id string) error {
	return a.service.DenyAccessRequest(ctx, id)
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
		Portal: "ok", VPN: a.provisionerMode, Edges: "🇱🇹 Литва 🚀 · 🇫🇮 Финляндия 🚀", Certificate: "Caddy auto-TLS",
		CPU: fmt.Sprintf("%d vCPU", runtime.NumCPU()), Memory: fmt.Sprintf("%.1f MiB app", float64(memory.Alloc)/(1<<20)),
		Disk: disk, Network: "портал и Reality 443/tcp",
	}, nil
}
