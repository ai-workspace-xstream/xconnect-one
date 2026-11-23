//go:build linux

package runtime

import (
	"errors"
	"reflect"
	"testing"
)

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
	isLive := func() bool { return true }
	notLive := func() bool { return false }
	hasTools := func(name string) (string, error) { return "/usr/bin/" + name, nil }
	noTools := func(string) (string, error) { return "", errors.New("missing") }

	if !shouldUseSystemd("auto", isLive, hasTools) {
		t.Fatal("expected auto with live systemd + tools to select systemd")
	}
	if shouldUseSystemd("auto", notLive, hasTools) {
		t.Fatal("expected auto without live systemd (container/tini) to select direct mode")
	}
	if shouldUseSystemd("auto", isLive, noTools) {
		t.Fatal("expected auto without systemd-run/systemctl to select direct mode")
	}
	if shouldUseSystemd("direct", isLive, hasTools) {
		t.Fatal("expected explicit direct mode to disable systemd")
	}
	if !shouldUseSystemd("systemd", notLive, noTools) {
		t.Fatal("expected explicit systemd mode to force systemd")
	}
}
