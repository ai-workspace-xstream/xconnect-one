//go:build linux

package accelerate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime/embedded"
	"github.com/vishvananda/netlink"
)

func TestLinuxTUNCoexistsWithExistingAndLaterPrivateRoutes(t *testing.T) {
	if os.Getenv("XCONNECT_TEST_ISOLATED_NETNS") != "1" {
		t.Skip("requires an isolated Linux network and mount namespace")
	}
	if _, err := os.Stat("/run/xconnect-accelerate"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("requires an empty isolated /run")
	}

	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("ip %v: %v (%s)", args, err, out)
		}
		return string(out)
	}
	route := func(family, destination, uid, expected string) {
		t.Helper()
		if out := ip(family, "route", "get", destination, "uid", uid); !strings.Contains(out, "dev "+expected+" ") {
			t.Fatalf("route to %s for UID %s: expected %s, got %s", destination, uid, expected, out)
		}
	}

	ip("link", "set", "lo", "up")
	ip("link", "add", "test-uplink", "type", "dummy")
	ip("link", "set", "test-uplink", "up")
	ip("addr", "add", "192.168.91.2/24", "dev", "test-uplink")
	ip("addr", "add", "fd00:91::2/64", "dev", "test-uplink", "nodad")
	ip("route", "add", "default", "via", "192.168.91.1", "dev", "test-uplink")
	ip("-6", "route", "add", "default", "via", "fd00:91::1", "dev", "test-uplink")
	ip("link", "add", "test-vpn", "type", "dummy")
	ip("link", "set", "test-vpn", "up")

	// Simulate a killed earlier instance whose TUN vanished with the process.
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, r := range rulesFor(family, 1000) {
			if err := netlink.RuleAdd(&r); err != nil {
				t.Fatal(err)
			}
		}
	}
	profile, requests := localVLESSTarget(t)
	for _, vpnFirst := range []bool{true, false} {
		if vpnFirst {
			ip("route", "add", "10.67.0.0/16", "dev", "test-vpn")
		}
		start, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(start, 1000, func(context.Context) ([]byte, error) {
				return profile, nil
			}, io.Discard)
		}()
		t.Cleanup(cancel)

		deadline := time.Now().Add(5 * time.Second)
		for {
			var status bytes.Buffer
			_ = Control(start, false, &status)
			if strings.Contains(status.String(), "UID 1000") {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("start acceleration: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("waited for acceleration control socket")
			}
			time.Sleep(50 * time.Millisecond)
		}

		if !vpnFirst {
			ip("route", "add", "10.67.0.0/16", "dev", "test-vpn")
		}
		route("-4", "10.67.0.5", "1000", "test-vpn")
		route("-4", "192.168.91.9", "1000", "test-uplink")
		route("-4", "169.254.169.254", "1000", "test-uplink")
		route("-4", "1.1.1.1", "1000", tunName)
		route("-6", "2606:4700::1111", "1000", tunName)
		route("-4", "1.1.1.1", "0", "test-uplink")
		route("-4", "1.1.1.1", "1001", "test-uplink")

		cmd := exec.Command("setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "curl",
			"--noproxy", "*", "--max-time", "4", "--fail", "--silent", "http://1.1.1.1/")
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != "via-vless" {
			t.Fatalf("public TCP through TUN: %v (%s)", err, out)
		}
		select {
		case requestErr := <-requests:
			if requestErr != nil {
				t.Fatal(requestErr)
			}
		case <-time.After(time.Second):
			t.Fatal("VLESS endpoint did not receive the tunneled TCP request")
		}

		if err := Control(start, true, io.Discard); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("waited for acceleration cleanup")
		}
		cancel()
		route("-4", "10.67.0.5", "1000", "test-vpn")
		route("-4", "1.1.1.1", "1000", "test-uplink")
		route("-6", "2606:4700::1111", "1000", "test-uplink")
		if strings.Contains(ip("rule", "show"), "45230") || strings.Contains(ip("-6", "rule", "show"), "45230") {
			t.Fatal("acceleration routing rules were not removed")
		}
		ip("route", "del", "10.67.0.0/16", "dev", "test-vpn")
	}
}

// localVLESSTarget is a TLS endpoint for the test's one VLESS TCP request. It
// replies locally, so the isolated namespace never needs internet access.
func localVLESSTarget(t *testing.T) ([]byte, <-chan error) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	u, err := url.Parse("vless://00000000-0000-4000-8000-000000000001@" + listener.Addr().String() + "?security=tls")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := buildProfile(u)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Log       any              `json:"log"`
		Inbounds  any              `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	stream := profile.Outbounds[0]["streamSettings"].(map[string]any)
	tlsSettings := stream["tlsSettings"].(map[string]any)
	tlsSettings["certificates"] = []any{map[string]any{
		"usage": "verify",
		"certificate": strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: cert.Certificate[0],
		}))), "\n"),
	}}
	raw, err = json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}

	requests := make(chan error, 2)
	go func() {
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				requests <- err
				return
			}
			requests <- respondVLESS(conn)
		}
	}()
	return raw, requests
}

func respondVLESS(conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	var header [26]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	// VLESS v0, no addons, TCP, port 80, IPv4 1.1.1.1.
	if header[0] != 0 || !bytes.Equal(header[17:], []byte{0, 1, 0, 80, 1, 1, 1, 1, 1}) {
		return errors.New("VLESS target did not match the public TCP request")
	}
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	_ = req.Body.Close()
	_, err = conn.Write([]byte("\x00\x00HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-vless"))
	return err
}
