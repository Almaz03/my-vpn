package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Almaz03/my-vpn/internal/service"
	"github.com/Almaz03/my-vpn/internal/store"
	"rsc.io/qr"
)

type API struct {
	service   *service.Service
	store     *store.Store
	adminHash [sha256.Size]byte
	inviteTTL time.Duration
	webRoot   string
	startedAt time.Time
}

func New(service *service.Service, database *store.Store, adminToken, webRoot string, inviteTTL time.Duration) *API {
	return &API{
		service: service, store: database, adminHash: sha256.Sum256([]byte(adminToken)),
		inviteTTL: inviteTTL, webRoot: webRoot, startedAt: time.Now(),
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /api/v1/activate", a.activate)
	mux.HandleFunc("GET /s/{token}", a.subscription)
	mux.HandleFunc("GET /s/{token}/qr", a.subscriptionQR)
	mux.HandleFunc("GET /routing/family-ru-direct.json", a.routingProfile)
	mux.HandleFunc("POST /api/v1/admin/invitations", a.requireAdmin(a.createInvitation))
	mux.HandleFunc("GET /api/v1/admin/invitations", a.requireAdmin(a.listInvitations))
	mux.HandleFunc("POST /api/v1/admin/invitations/{id}/revoke", a.requireAdmin(a.revokeInvitation))
	mux.HandleFunc("POST /api/v1/admin/invitations/{id}/extend", a.requireAdmin(a.extendInvitation))
	mux.HandleFunc("GET /api/v1/admin/devices", a.requireAdmin(a.listDevices))
	mux.HandleFunc("POST /api/v1/admin/devices/{id}/revoke", a.requireAdmin(a.revokeDevice))
	mux.HandleFunc("GET /api/v1/admin/status", a.requireAdmin(a.status))
	mux.Handle("/", a.staticHandler())
	return securityHeaders(mux)
}

func (a *API) subscriptionQR(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if _, err := a.service.Subscription(r.Context(), token); err != nil {
		if errors.Is(err, store.ErrSubscriptionNotFound) {
			writeError(w, http.StatusNotFound, "subscription not found or expired")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "subscription temporarily unavailable")
		return
	}
	code, err := qr.Encode(a.service.SubscriptionDeepLink(token), qr.M)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encode QR")
		return
	}
	code.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, private, max-age=0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(code.PNG())
}

func (a *API) subscription(w http.ResponseWriter, r *http.Request) {
	payload, err := a.service.Subscription(r.Context(), r.PathValue("token"))
	if errors.Is(err, store.ErrSubscriptionNotFound) {
		writeError(w, http.StatusNotFound, "subscription not found or expired")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "subscription temporarily unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, private, max-age=0")
	w.Header().Set("Expires", "0")
	w.Header().Set("Profile-Title", "base64:RmFtaWx5IFZQTg==")
	w.Header().Set("Profile-Update-Interval", "0")
	w.Header().Set("Routing-Geo-Update-Interval", "24")
	w.Header().Set("Autorouting", "incy://autorouting/onadd/"+a.service.RoutingProfileURL())
	w.Header().Set("Hide-Url", "1")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="family-vpn.txt"`)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, payload.Body)
}

func (a *API) routingProfile(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, a.service.RoutingProfile())
}

func (a *API) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	if err := a.service.RevokeInvitation(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusNotFound, "invitation not found or no longer revocable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	if err := a.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) activate(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	allowed, retry, limitErr := a.service.AllowActivationAttempt(r.Context(), ip)
	if limitErr != nil {
		writeError(w, http.StatusServiceUnavailable, "Сервис временно недоступен.")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retry.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "Слишком много попыток. Повторите позже.")
		return
	}
	var input struct {
		Code       string `json:"code"`
		Platform   string `json:"platform"`
		DeviceName string `json:"device_name"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		_ = a.service.ActivationFailure(r.Context(), ip)
		writeError(w, http.StatusBadRequest, "Некорректный запрос.")
		return
	}
	activation, err := a.service.Activate(r.Context(), input.Code, input.Platform, input.DeviceName, ip)
	if err != nil {
		_ = a.service.ActivationFailure(r.Context(), ip)
		status := http.StatusUnauthorized
		if err.Error() == "unsupported platform" || err.Error() == "device_name is too long" {
			status = http.StatusBadRequest
		}
		writeError(w, status, "Код недействителен, истёк или уже использован.")
		return
	}
	_ = a.service.ActivationSuccess(r.Context(), ip)
	writeJSON(w, http.StatusCreated, map[string]any{
		"device_id":           activation.Device.ID,
		"device_name":         activation.Device.DeviceName,
		"state":               activation.Device.State,
		"incy_deep_link":      activation.INCYDeepLink,
		"config_download_url": activation.ConfigDownloadURL,
		"qr_code_url":         activation.QRCodeURL,
		"routing_mode":        "ru-direct",
		"message":             activation.Message,
	})
}

func (a *API) createInvitation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RelativeName string `json:"relative_name"`
		DeviceName   string `json:"device_name"`
		TTLSeconds   int    `json:"ttl_seconds"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	ttl := a.inviteTTL
	if input.TTLSeconds != 0 {
		ttl = time.Duration(input.TTLSeconds) * time.Second
	}
	invitation, code, err := a.service.CreateInvitation(r.Context(), input.RelativeName, input.DeviceName, ttl)
	if errors.Is(err, store.ErrInvitationCreationLimit) {
		w.Header().Set("Retry-After", "600")
		writeError(w, http.StatusTooManyRequests, "invitation creation limit reached")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invitation": invitation, "code": code})
}

func (a *API) listInvitations(w http.ResponseWriter, r *http.Request) {
	invitations, err := a.service.ListInvitations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list invitations")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": invitations})
}

func (a *API) extendInvitation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	invitation, err := a.service.ExtendInvitation(r.Context(), r.PathValue("id"), time.Duration(input.TTLSeconds)*time.Second)
	if err != nil {
		writeError(w, http.StatusNotFound, "invitation not found or no longer extendable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitation": invitation})
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := a.service.ListDevices(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	device, err := a.service.Revoke(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrDeviceNotFound) {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if err != nil {
		if errors.Is(err, service.ErrRevokePending) {
			writeError(w, http.StatusServiceUnavailable, "device revoke is pending; retry is safe")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not revoke device")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": device})
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	stats, err := a.service.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "status unavailable")
		return
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "uptime_seconds": int64(time.Since(a.startedAt).Seconds()),
		"go_version": runtime.Version(), "goroutines": runtime.NumGoroutine(),
		"memory_alloc_bytes": memory.Alloc, "database": "ok", "counts": stats,
	})
}

func (a *API) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		candidate := sha256.Sum256([]byte(token))
		if !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(candidate[:], a.adminHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func (a *API) staticHandler() http.Handler {
	root, err := filepath.Abs(a.webRoot)
	if err != nil {
		return http.NotFoundHandler()
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return http.NotFoundHandler()
	}
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." {
			clean = "index.html"
		}
		if _, err := os.Stat(filepath.Join(root, clean)); err != nil {
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain a single JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	parsed := net.ParseIP(host)
	if parsed != nil && parsed.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	if parsed == nil {
		return "unknown"
	}
	return parsed.String()
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
