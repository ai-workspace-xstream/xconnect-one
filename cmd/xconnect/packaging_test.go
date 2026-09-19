package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagingNoticeFileExists(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	noticePath := filepath.Join(root, "NOTICE")
	content, err := os.ReadFile(noticePath)
	if err != nil {
		t.Fatalf("expected NOTICE file to exist at %s, but got err: %v", noticePath, err)
	}

	text := string(content)
	if !strings.Contains(text, "18d328e5c7b171a4c53f6e2a1d387155901c9715") {
		t.Errorf("NOTICE must reference upstream pinned source commit 18d328e5c7b171a4c53f6e2a1d387155901c9715")
	}
	if !strings.Contains(text, "Apache License, Version 2.0") {
		t.Errorf("NOTICE must specify Apache License, Version 2.0")
	}
}

func normalizeLineEndings(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\r\n", "\n")
}

func TestPackagingSystemdUnitMatchesGolden(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	goldenPath := filepath.Join(root, "cmd/xconnect/testdata/xconnect-one-sync.service.golden")
	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read golden unit: %v", err)
	}

	cmd := exec.Command("bash", filepath.Join(root, "scripts/install-xconnect-one.sh"), "--print-unit")
	cmd.Env = append(os.Environ(), "XCONNECT_ONE_INSTALL_DIR=/usr/local/bin", "XCONNECT_ONE_STATE_DIR=/var/lib/xconnect-one")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to execute install-xconnect-one.sh --print-unit: %v", err)
	}

	got := normalizeLineEndings(string(out))
	want := normalizeLineEndings(string(expected))
	if got != want {
		t.Errorf("systemd unit mismatch.\nGot:\n%s\nExpected:\n%s", got, want)
	}
}

func TestPackagingHomebrewFormulaHasService(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	formulaPath := filepath.Join(root, "Formula/xconnect-one.rb")
	content, err := os.ReadFile(formulaPath)
	if err != nil {
		t.Fatalf("failed to read Formula: %v", err)
	}

	text := string(content)
	required := []string{
		"service do",
		`opt_bin/"xconnect"`,
		`"sync"`,
		`"--watch"`,
		`"--interval=60s"`,
		"keep_alive true",
		"require_root true",
	}
	for _, req := range required {
		if !strings.Contains(text, req) {
			t.Errorf("Formula must contain %q", req)
		}
	}
}

func TestPackagingWindowsInstallerHasScheduledTask(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	scriptPath := filepath.Join(root, "scripts/install-xconnect-one.ps1")
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read install-xconnect-one.ps1: %v", err)
	}

	text := string(content)
	required := []string{
		"XConnectOneSync",
		"SYSTEM",
		"sync",
		"--watch",
		"--interval=60s",
	}
	for _, req := range required {
		if !strings.Contains(text, req) {
			t.Errorf("install-xconnect-one.ps1 must contain %q", req)
		}
	}
}

func TestPackagingShellSyntaxCompliance(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("failed to resolve repo root: %v", err)
	}

	shellScripts := []string{
		"scripts/install-xconnect-one.sh",
		"scripts/one.sh",
		"scripts/test-desktop-verification.sh",
		"scripts/verify-desktop-macos.sh",
	}
	for _, relPath := range shellScripts {
		fullPath := filepath.Join(root, relPath)
		cmd := exec.Command("bash", "-n", fullPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("bash -n %s failed: %v\nOutput: %s", relPath, err, string(out))
		}
	}
}
