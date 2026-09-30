package runtime

import (
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"testing"
)

func TestDesktopRecoversMissingWireGuardWithOwnedXray(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex = 0
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if len(backend.stops) != 1 || len(backend.starts) != 2 {
		t.Fatalf("stops=%v starts=%v", backend.stops, backend.starts)
	}
	status, err := runtime.Status(t.Context())
	if err != nil || !status.Applied {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestDesktopMissingWireGuardStillRejectsUnownedXray(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	active, err := runtime.loadManifest(runtime.activeManifestPath())
	if err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex = 0
	backend.stale[active.Xray.PID] = true
	_, err = runtime.Apply(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeProcessStale || len(backend.stops) != 0 {
		t.Fatalf("err=%v stops=%v", err, backend.stops)
	}
}

func TestDesktopRejectsReplacedWireGuardInterface(t *testing.T) {
	backend := newFakeDesktopBackend()
	runtime := newDesktop(t.TempDir(), backend)
	request := desktopApplyRequest("revision-1")
	if _, err := runtime.Apply(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	backend.interfaceIndex++
	_, err := runtime.Apply(t.Context(), request)
	if fault.Code(err) != fault.CodeRuntimeProcessStale || len(backend.stops) != 0 {
		t.Fatalf("err=%v stops=%v", err, backend.stops)
	}
}
