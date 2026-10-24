package service

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

type testMihomoConfig struct {
	ProfileName string `json:"profile-name"`
	IPv6        bool   `json:"ipv6"`
	Tun         struct {
		Enable bool `json:"enable"`
	} `json:"tun"`
	DNS struct {
		Enable       bool   `json:"enable"`
		IPv6         bool   `json:"ipv6"`
		EnhancedMode string `json:"enhanced-mode"`
	} `json:"dns"`
	Proxies []struct {
		Name              string `json:"name"`
		Type              string `json:"type"`
		Server            string `json:"server"`
		Port              int    `json:"port"`
		UUID              string `json:"uuid"`
		Flow              string `json:"flow"`
		TLS               bool   `json:"tls"`
		Network           string `json:"network"`
		ClientFingerprint string `json:"client-fingerprint"`
		RealityOptions    struct {
			PublicKey string `json:"public-key"`
			ShortID   string `json:"short-id"`
		} `json:"reality-opts"`
	} `json:"proxies"`
	ProxyGroups []struct {
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Proxies   []string `json:"proxies"`
		URL       string   `json:"url"`
		Interval  int      `json:"interval"`
		Tolerance int      `json:"tolerance"`
		Lazy      bool     `json:"lazy"`
	} `json:"proxy-groups"`
	Rules []string `json:"rules"`
}

func parseTestMihomoConfig(t *testing.T) testMihomoConfig {
	t.Helper()
	body, err := buildClashMihomoConfig(testDualURIs())
	if err != nil {
		t.Fatal(err)
	}
	var config testMihomoConfig
	if err := json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestClashMihomoConfigUsesDualRealityAndAutomaticSelection(t *testing.T) {
	config := parseTestMihomoConfig(t)
	if config.ProfileName != familyProfileName || len(config.Proxies) != 2 || len(config.ProxyGroups) != 1 {
		t.Fatalf("unexpected profile shape: %#v", config)
	}
	for _, proxy := range config.Proxies {
		if proxy.Type != "vless" || proxy.Port != 443 || !proxy.TLS || proxy.Network != "tcp" ||
			proxy.Flow != "xtls-rprx-vision" || proxy.ClientFingerprint != "chrome" ||
			proxy.RealityOptions.PublicKey == "" || proxy.RealityOptions.ShortID == "" {
			t.Fatalf("unexpected Reality proxy: %#v", proxy)
		}
	}
	group := config.ProxyGroups[0]
	if group.Name != familyAutoGroup || group.Type != "url-test" || group.Lazy || group.Interval != 30 ||
		group.Tolerance != 50 || len(group.Proxies) != 2 || group.URL != "https://www.gstatic.com/generate_204" {
		t.Fatalf("automatic group is not ready by default: %#v", group)
	}
	if got := config.Rules[len(config.Rules)-1]; got != "MATCH,"+familyAutoGroup {
		t.Fatalf("default traffic does not use automatic group: %q", got)
	}
}

func TestClashMihomoConfigIsSelfContainedAndRoutesRussianSitesDirect(t *testing.T) {
	config := parseTestMihomoConfig(t)
	if !config.Tun.Enable || !config.DNS.Enable || config.IPv6 || config.DNS.IPv6 || config.DNS.EnhancedMode != "fake-ip" {
		t.Fatalf("unexpected tunnel or DNS config: %#v", config)
	}
	for _, expected := range []string{
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,17.0.0.0/8,DIRECT,no-resolve",
		"DOMAIN-SUFFIX,ru,DIRECT",
		"DOMAIN-SUFFIX,xn--p1ai,DIRECT",
		"DOMAIN-SUFFIX,2gis.com,DIRECT",
		"DOMAIN-SUFFIX,ozon.com,DIRECT",
		"DOMAIN-SUFFIX,yandex.com,DIRECT",
	} {
		if !slices.Contains(config.Rules, expected) {
			t.Fatalf("missing direct rule %q", expected)
		}
	}
	if len(familyDirectDomains) < 230 || len(config.Rules) < len(familyDirectDomains) {
		t.Fatalf("RU-direct allowlist unexpectedly shrank: domains=%d rules=%d", len(familyDirectDomains), len(config.Rules))
	}
	joined := strings.Join(config.Rules, "\n")
	if strings.Contains(joined, "GEOSITE") || strings.Contains(joined, "GEOIP") {
		t.Fatal("client config must not depend on separately downloaded geodata")
	}
}

func TestClashMihomoConfigRejectsMalformedEdges(t *testing.T) {
	bad := testDualURIs()
	bad[1] = strings.Replace(bad[1], "security=reality", "security=none", 1)
	if _, err := buildClashMihomoConfig(bad); err == nil {
		t.Fatal("malformed Reality edge was accepted")
	}
	if _, err := buildClashMihomoConfig(testDualURIs()[:1]); err == nil {
		t.Fatal("single-edge profile was accepted")
	}
}

func testDualURIs() []string {
	return []string{
		"vless://00000000-0000-4000-8000-000000000001@lt.example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=lt.example.test&fp=chrome&pbk=public&sid=0123456789abcdef#LT",
		"vless://00000000-0000-4000-8000-000000000001@fi.example.test:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=fi.example.test&fp=chrome&pbk=public&sid=0123456789abcdef#FI",
	}
}
