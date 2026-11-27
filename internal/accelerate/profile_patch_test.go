package accelerate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/xtls/xray-core/proxy/tun"
)

func TestPublicRouteCIDRsExcludePrivateAndOverlayRanges(t *testing.T) {
	v4, v6 := PublicRoutePrefixes()
	contains := func(prefixes []netip.Prefix, ip string) bool {
		addr := netip.MustParseAddr(ip)
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}

	for _, excluded := range []string{"10.67.0.4", "10.0.0.2", "192.168.0.113", "172.17.109.201", "100.64.0.1", "127.0.0.1", "169.254.1.1"} {
		if contains(v4, excluded) {
			t.Fatalf("public IPv4 routes unexpectedly include private/overlay address %s", excluded)
		}
	}
	for _, pub := range []string{"1.1.1.1", "8.8.8.8", "140.82.112.4"} {
		if !contains(v4, pub) {
			t.Fatalf("public IPv4 routes missing public address %s", pub)
		}
	}
	if !contains(v6, "2606:4700:4700::1111") {
		t.Fatal("public IPv6 routes missing public address")
	}
	if contains(v6, "fd42:7863:6163::1") {
		t.Fatal("public IPv6 routes unexpectedly include ULA overlay address")
	}
}

func TestDecodeProfileWithSystemRoutes(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]node{
			{ID: "jp", VLESS: "vless://test@jp.example:443?security=tls&type=xhttp&path=%2Fxhttp"},
		})
	}))
	defer server.Close()

	raw, err := Profile(context.Background(), server.Client(), credential.UserSession{
		Server: server.URL, AccessToken: "tok",
	}, "jp")
	if err != nil {
		t.Fatal(err)
	}

	// macOS uses empty name to auto-assign utunN
	cfgDarwin, err := decodeProfileWithSystemRoutes(raw, "", PublicRouteCIDRs())
	if err != nil {
		t.Fatalf("decodeProfileWithSystemRoutes(darwin): %v", err)
	}
	tunCfg, err := cfgDarwin.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	tc, ok := tunCfg.(*tun.Config)
	if !ok {
		t.Fatalf("expected *tun.Config, got %T", tunCfg)
	}
	if !strings.HasPrefix(tc.Name, "utun") {
		t.Fatalf("expected auto-assigned utunN name, got %q", tc.Name)
	}
	if tc.AutoOutboundsInterface != "auto" {
		t.Fatalf("expected AutoOutboundsInterface=auto, got %q", tc.AutoOutboundsInterface)
	}
	if len(tc.AutoSystemRoutingTable) == 0 {
		t.Fatal("expected non-empty AutoSystemRoutingTable")
	}

	// Windows uses explicit adapter name
	cfgWin, err := decodeProfileWithSystemRoutes(raw, tunName, PublicRouteCIDRs())
	if err != nil {
		t.Fatalf("decodeProfileWithSystemRoutes(windows): %v", err)
	}
	winTunCfg, err := cfgWin.Inbound[0].ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	wtc := winTunCfg.(*tun.Config)
	if wtc.Name != tunName {
		t.Fatalf("expected Windows TUN name %q, got %q", tunName, wtc.Name)
	}
}
