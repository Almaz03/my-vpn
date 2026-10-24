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

const (
	familyProfileName = "Family VPN · LT + FI"
	familyAutoGroup   = "🚀 Автовыбор"
)

var privateNetworks = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
	"17.0.0.0/8",
}

type realityClient struct {
	Server      string
	Port        int
	UUID        string
	ServerName  string
	PublicKey   string
	ShortID     string
	Fingerprint string
	Flow        string
}

// buildClashMihomoConfig emits JSON with a YAML content type. JSON is a strict
// subset of YAML, which keeps generation deterministic while Clash Mi/Mihomo
// still receives a native full profile rather than a lossy list of links.
func buildClashMihomoConfig(vlessURIs []string) (string, error) {
	if len(vlessURIs) != 2 {
		return "", errors.New("exactly two VLESS client configurations are required")
	}
	ltProxy, err := buildMihomoRealityProxy(vlessURIs[0], "🇱🇹 Литва 🚀")
	if err != nil {
		return "", err
	}
	fiProxy, err := buildMihomoRealityProxy(vlessURIs[1], "🇫🇮 Финляндия 🚀")
	if err != nil {
		return "", err
	}

	rules := make([]string, 0, len(privateNetworks)+len(familyDirectDomains)+1)
	for _, network := range privateNetworks {
		rules = append(rules, "IP-CIDR,"+network+",DIRECT,no-resolve")
	}
	for _, domainRule := range familyDirectDomains {
		domain := strings.TrimPrefix(domainRule, "domain:")
		if domain == domainRule || domain == "" || containsUnsafeConfigText(domain) {
			return "", errors.New("invalid direct domain rule")
		}
		rules = append(rules, "DOMAIN-SUFFIX,"+domain+",DIRECT")
	}
	rules = append(rules, "MATCH,"+familyAutoGroup)

	config := map[string]any{
		"profile-name":              familyProfileName,
		"mode":                      "rule",
		"log-level":                 "warning",
		"ipv6":                      false,
		"allow-lan":                 false,
		"unified-delay":             true,
		"tcp-concurrent":            true,
		"global-client-fingerprint": "chrome",
		"profile": map[string]any{
			"store-selected": true,
			"store-fake-ip":  true,
		},
		"tun": map[string]any{
			"enable": true, "stack": "mixed", "auto-route": true,
			"auto-detect-interface": true, "strict-route": false,
			"dns-hijack": []string{"any:53"},
		},
		"dns": map[string]any{
			"enable": true, "ipv6": false, "enhanced-mode": "fake-ip",
			"fake-ip-range":           "198.18.0.1/16",
			"fake-ip-filter":          []string{"*.lan", "+.local", "localhost", "+.push.apple.com"},
			"default-nameserver":      []string{"1.1.1.1", "8.8.8.8"},
			"nameserver":              []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"},
			"proxy-server-nameserver": []string{"1.1.1.1", "8.8.8.8"},
		},
		"proxies": []any{ltProxy, fiProxy},
		"proxy-groups": []any{map[string]any{
			"name": familyAutoGroup, "type": "url-test",
			"proxies": []string{"🇱🇹 Литва 🚀", "🇫🇮 Финляндия 🚀"},
			"url":     "https://www.gstatic.com/generate_204", "interval": 30,
			"tolerance": 50, "lazy": false,
		}},
		"rules": rules,
	}
	body, err := json.Marshal(config)
	if err != nil {
		return "", errors.New("encode Clash Mi configuration")
	}
	return string(body) + "\n", nil
}

func buildMihomoRealityProxy(vlessURI, name string) (map[string]any, error) {
	client, err := parseRealityClient(vlessURI)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name": name, "type": "vless", "server": client.Server, "port": client.Port,
		"uuid": client.UUID, "network": "tcp", "tls": true, "udp": true,
		"flow": client.Flow, "servername": client.ServerName,
		"client-fingerprint": client.Fingerprint, "packet-encoding": "xudp",
		"reality-opts": map[string]any{
			"public-key": client.PublicKey, "short-id": client.ShortID,
		},
	}, nil
}

func parseRealityClient(vlessURI string) (realityClient, error) {
	parsed, err := url.Parse(vlessURI)
	if err != nil || parsed.Scheme != "vless" || parsed.User == nil || parsed.Hostname() == "" {
		return realityClient{}, errors.New("invalid VLESS client configuration")
	}
	uuid := parsed.User.Username()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 || !fullConfigUUIDPattern.MatchString(uuid) {
		return realityClient{}, errors.New("invalid VLESS client configuration")
	}
	query := parsed.Query()
	client := realityClient{
		Server: parsed.Hostname(), Port: port, UUID: uuid,
		ServerName: query.Get("sni"), PublicKey: query.Get("pbk"),
		ShortID: query.Get("sid"), Fingerprint: query.Get("fp"), Flow: query.Get("flow"),
	}
	transport := query.Get("type")
	if query.Get("security") != "reality" || query.Get("encryption") != "none" ||
		client.ServerName == "" || client.PublicKey == "" || client.ShortID == "" || client.Fingerprint == "" ||
		client.Flow != "xtls-rprx-vision" || (transport != "tcp" && transport != "raw") ||
		containsUnsafeConfigText(client.Server, client.ServerName, client.PublicKey, client.ShortID, client.Fingerprint) {
		return realityClient{}, errors.New("invalid VLESS client configuration")
	}
	return client, nil
}

func containsUnsafeConfigText(values ...string) bool {
	for _, value := range values {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return true
		}
	}
	return false
}
