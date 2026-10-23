package service

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var fullConfigUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var familyDirectDomains = []string{
	"domain:ru", "domain:su", "domain:рф", "domain:xn--p1ai",
	"domain:vk.com", "domain:mail.ru", "domain:ok.ru",
	"domain:yandex.com", "domain:ya.ru", "domain:dzen.ru",
	"domain:gosuslugi.ru", "domain:nalog.gov.ru", "domain:mos.ru",
	"domain:sberbank.ru", "domain:tbank.ru", "domain:alfabank.ru",
	"domain:ozon.ru", "domain:wildberries.ru",
}

var privateNetworks = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
}

func buildFullXrayConfig(vlessURI string) (string, error) {
	parsed, err := url.Parse(vlessURI)
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil || parsed.Hostname() == "" {
		return "", errors.New("invalid VLESS client configuration")
	}
	uuid := parsed.User.Username()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || !fullConfigUUIDPattern.MatchString(uuid) {
		return "", errors.New("invalid VLESS client configuration")
	}
	query := parsed.Query()
	serverName := query.Get("sni")
	publicKey := query.Get("pbk")
	shortID := query.Get("sid")
	fingerprint := query.Get("fp")
	flow := query.Get("flow")
	transport := query.Get("type")
	if query.Get("security") != "reality" || query.Get("encryption") != "none" ||
		serverName == "" || publicKey == "" || shortID == "" || fingerprint == "" ||
		flow != "xtls-rprx-vision" || (transport != "tcp" && transport != "raw") ||
		containsUnsafeConfigText(serverName, publicKey, shortID, fingerprint) {
		return "", errors.New("invalid VLESS client configuration")
	}

	directDomains := append([]string(nil), familyDirectDomains...)
	config := map[string]any{
		"remarks": "Family VPN",
		"log":     map[string]any{"loglevel": "warning"},
		"dns": map[string]any{
			"queryStrategy": "UseIPv4",
			"servers": []any{
				"8.8.8.8",
				"1.1.1.1",
				map[string]any{"address": "77.88.8.8", "domains": directDomains},
			},
			"tag": "dns-out",
		},
		"inbounds": []any{
			map[string]any{
				"tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 10808,
				"settings": map[string]any{"auth": "noauth", "udp": true},
				"sniffing": map[string]any{
					"enabled": true, "destOverride": []string{"http", "tls", "quic"},
					"metadataOnly": false, "routeOnly": false,
				},
			},
			map[string]any{
				"tag": "http-in", "protocol": "http", "listen": "127.0.0.1", "port": 10809,
				"settings": map[string]any{"auth": "noauth"},
				"sniffing": map[string]any{
					"enabled": true, "destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag": "family-proxy", "protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": parsed.Hostname(), "port": port,
					"users": []any{map[string]any{"id": uuid, "encryption": "none", "flow": flow}},
				}}},
				"streamSettings": map[string]any{
					"network": "raw", "security": "reality",
					"rawSettings": map[string]any{"header": map[string]any{"type": "none"}},
					"realitySettings": map[string]any{
						"show":        false,
						"fingerprint": fingerprint, "serverName": serverName,
						"publicKey": publicKey, "shortId": shortID, "spiderX": "/",
					},
				},
				"mux": map[string]any{"enabled": false},
			},
			map[string]any{
				"tag": "direct", "protocol": "freedom", "settings": map[string]any{},
				"streamSettings": map[string]any{"sockopt": map[string]any{"domainStrategy": "ForceIPv4"}},
			},
			map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
			map[string]any{"tag": "dns-out", "protocol": "dns"},
		},
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{
				map[string]any{"type": "field", "ip": privateNetworks, "outboundTag": "direct"},
				map[string]any{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"},
				map[string]any{"type": "field", "domain": directDomains, "outboundTag": "direct"},
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "family-proxy"},
			},
		},
	}
	body, err := json.Marshal(config)
	if err != nil {
		return "", errors.New("encode full Xray configuration")
	}
	return string(body) + "\n", nil
}

func containsUnsafeConfigText(values ...string) bool {
	for _, value := range values {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return true
		}
	}
	return false
}
