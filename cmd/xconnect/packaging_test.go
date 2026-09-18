package main

import (
	"os"
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
