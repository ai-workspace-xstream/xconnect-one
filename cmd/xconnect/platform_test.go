package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
)

func TestPlatformHelpers(t *testing.T) {
	sysPath := defaultSystemDeviceIDPath()
	if strings.TrimSpace(sysPath) == "" {
		t.Fatal("expected non-empty defaultSystemDeviceIDPath")
	}
	if goruntime.GOOS == "windows" {
		if !strings.Contains(sysPath, "xconnect-one") || !strings.Contains(sysPath, "device-id") {
			t.Fatalf("unexpected windows system device id path: %s", sysPath)
		}
		if platformElevatedCmdPrefix() != "" {
			t.Fatalf("expected empty elevated prefix on windows, got %q", platformElevatedCmdPrefix())
		}
		pingCmd := platformPingCmdString(4, "10.66.0.1")
		if !strings.Contains(pingCmd, "-n 4") {
			t.Fatalf("expected ping -n 4 on windows, got %q", pingCmd)
		}
	} else {
		if sysPath != "/etc/xconnect-one/device-id" {
			t.Fatalf("expected /etc/xconnect-one/device-id on unix, got %s", sysPath)
		}
		if platformElevatedCmdPrefix() != "sudo " {
			t.Fatalf("expected 'sudo ' on unix, got %q", platformElevatedCmdPrefix())
		}
		pingCmd := platformPingCmdString(4, "10.66.0.1")
		if !strings.Contains(pingCmd, "-c 4") {
			t.Fatalf("expected ping -c 4 on unix, got %q", pingCmd)
		}
	}

	_ = isProcessPrivileged()
	_ = effectiveProcessUID()
}

func TestStatusAndDebugAllFormats(t *testing.T) {
	stateDir := t.TempDir()
	store := state.NewStore(stateDir)
	cfg := cliTestConfig()
	cfg.Network.GatewayID = "ph-gw-test"
	cfg.WireGuard.Address = "10.88.0.5/32"
	cfg.WireGuard.PeerAllowedIPs = []string{"10.88.0.0/16"}
	_ = store.SaveLastKnown(state.LastKnown{
		Server:           "https://accounts.example",
		DeviceID:         "dev_platform_test",
		NetworkID:        "net_platform_test",
		Phase:            state.PhaseAcknowledged,
		Config:           cfg,
		SignedGeneration: 3,
	})

	fakeRT := &overlayruntime.Fake{
		StatusResult: overlayruntime.Status{
			Available:      true,
			Applied:        true,
			ManagedRuntime: true,
			RuntimeVersion: "embedded",
			Revision:       cfg.Revision,
			CoreID:         "xray",
			AdapterID:      "desktop-embedded-xray",
			Interface:      "xconone0",
			Address:        "10.88.0.5/32",
			DaemonPID:      9999,
		},
	}
	creds := &credential.MemoryStore{}

	for _, format := range []string{"json", "text", "markdown"} {
		t.Run("status_format_"+format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"status", "--state-dir", stateDir, "--format=" + format}
			if err := runWithFactories(context.Background(), args, &stdout, &stderr, http.DefaultClient,
				func(string) overlayruntime.Interface { return fakeRT },
				func(string) credential.Store { return creds },
			); err != nil {
				t.Fatalf("status format %s failed: %v", format, err)
			}
			out := stdout.String()
			if !strings.Contains(out, "10.88.0.5") {
				t.Fatalf("status format %s output missing IP: %s", format, out)
			}
		})
	}

	for _, format := range []string{"json", "markdown", "prompt"} {
		t.Run("debug_format_"+format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"debug", "--state-dir", stateDir, "--format=" + format}
			if err := runWithFactories(context.Background(), args, &stdout, &stderr, http.DefaultClient,
				func(string) overlayruntime.Interface { return fakeRT },
				func(string) credential.Store { return creds },
			); err != nil {
				t.Fatalf("debug format %s failed: %v", format, err)
			}
			out := stdout.String()
			if !strings.Contains(out, "10.88.0.5") {
				t.Fatalf("debug format %s output missing IP: %s", format, out)
			}
			if format == "json" {
				var report debugReport
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatalf("unmarshal json debug report: %v", err)
				}
				if report.System.Platform != goruntime.GOOS {
					t.Fatalf("expected platform %s, got %s", goruntime.GOOS, report.System.Platform)
				}
			}
		})
	}
}
