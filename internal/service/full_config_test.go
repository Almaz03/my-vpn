package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFullXrayConfigUsesRawRealityTransport(t *testing.T) {
	body, err := buildFullXrayConfig("vless://00000000-0000-4000-8000-000000000001@vpn.example.test:8443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=vpn.example.test&fp=chrome&pbk=public&sid=0123456789abcdef#Family")
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Outbounds []struct {
			Tag            string `json:"tag"`
			StreamSettings struct {
				Network         string `json:"network"`
				Security        string `json:"security"`
				RealitySettings struct {
					Show    bool   `json:"show"`
					SpiderX string `json:"spiderX"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range config.Outbounds {
		if outbound.Tag != "family-proxy" {
			continue
		}
		if outbound.StreamSettings.Network != "raw" || outbound.StreamSettings.Security != "reality" ||
			outbound.StreamSettings.RealitySettings.Show || outbound.StreamSettings.RealitySettings.SpiderX != "/" {
			t.Fatalf("unexpected Reality stream settings: %#v", outbound.StreamSettings)
		}
		return
	}
	t.Fatal("family-proxy outbound not found")
}

func TestFullXrayConfigDoesNotDependOnClientGeodata(t *testing.T) {
	body, err := buildFullXrayConfig("vless://00000000-0000-4000-8000-000000000001@tcp.example.test:443?encryption=none&security=reality&type=raw&flow=xtls-rprx-vision&sni=tcp.example.test&fp=chrome&pbk=public&sid=0123456789abcdef#Family")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "geosite:") || strings.Contains(body, "geoip:") {
		t.Fatal("INCY config must not depend on possibly stale geosite.dat or geoip.dat assets")
	}
	if !strings.Contains(body, `"domain:ru"`) || !strings.Contains(body, `"outboundTag":"family-proxy"`) {
		t.Fatal("expected self-contained RU direct rule and proxy fallback")
	}
	if len(familyDirectDomains) < 230 {
		t.Fatalf("RU-direct allowlist unexpectedly shrank to %d entries", len(familyDirectDomains))
	}
	if !strings.Contains(body, `"domain:2gis.com"`) || !strings.Contains(body, `"domain:ozon.com"`) ||
		!strings.Contains(body, `"domain:yandex.com"`) || !strings.Contains(body, `"17.0.0.0/8"`) {
		t.Fatal("expected extended known-good direct routing rules")
	}
}

func TestFullXrayConfigRoutesDNSBypassAndProxyExplicitly(t *testing.T) {
	body, err := buildFullXrayConfig("vless://00000000-0000-4000-8000-000000000001@tcp.example.test:443?encryption=none&security=reality&type=raw&flow=xtls-rprx-vision&sni=tcp.example.test&fp=chrome&pbk=public&sid=0123456789abcdef#Family")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"tag":"dns_out"`,
		`"inboundTag":["dns_out"],"ip":["77.88.8.8"],"outboundTag":"direct"`,
		`"inboundTag":["dns_out"],"outboundTag":"family-proxy"`,
		`"outboundTag":"dns-out","port":53`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("missing explicit DNS route %q", expected)
		}
	}
}
