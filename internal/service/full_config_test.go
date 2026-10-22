package service

import (
	"encoding/json"
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
