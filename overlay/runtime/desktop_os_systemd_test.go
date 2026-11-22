//go:build linux

package runtime

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

type fakeDirInfo struct{ isDir bool }

func (f fakeDirInfo) Name() string       { return "systemd" }
func (f fakeDirInfo) Size() int64        { return 0 }
func (f fakeDirInfo) Mode() os.FileMode  { return os.ModeDir | 0o755 }
func (f fakeDirInfo) ModTime() time.Time { return time.Time{} }
func (f fakeDirInfo) IsDir() bool        { return f.isDir }
func (f fakeDirInfo) Sys() any           { return nil }

func TestSystemdRunArgumentsKeepRuntimeOutsideLoginScope(t *testing.T) {
	got := systemdRunArguments("xconnect-one-xray-test", "/usr/local/bin/xray", []string{"run", "-config", "/state/xray.json"})
	want := []string{
		"--unit", "xconnect-one-xray-test", "--collect", "--quiet",
		"--property=Type=exec", "--property=Restart=no",
		"--property=StandardOutput=null", "--property=StandardError=null",
		"--", "/usr/local/bin/xray", "run", "-config", "/state/xray.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("systemd-run arguments = %#v", got)
	}
}

func TestShouldUseSystemdModesAndContainerFallback(t *testing.T) {
	hasDir := func(string) (os.FileInfo, error) { return fakeDirInfo{isDir: true}, nil }
	noDir := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	hasTools := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	noTools := func(string) (string, error) { return "", errors.New("missing") }

	if !shouldUseSystemd("auto", hasDir, hasTools) {
		t.Fatal("expected auto with /run/systemd/system + tools to select systemd")
	}
	if shouldUseSystemd("auto", noDir, hasTools) {
		t.Fatal("expected auto without /run/systemd/system (container/tini) to select direct mode")
	}
	if shouldUseSystemd("auto", hasDir, noTools) {
		t.Fatal("expected auto without systemd-run/systemctl to select direct mode")
	}
	if shouldUseSystemd("direct", hasDir, hasTools) {
		t.Fatal("expected explicit direct mode to disable systemd")
	}
	if !shouldUseSystemd("systemd", noDir, noTools) {
		t.Fatal("expected explicit systemd mode to force systemd")
	}
}
