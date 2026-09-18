package controlplane_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
)

// AccountsCommitSHA records the accounts commit from which the golden route inventory was generated.
// Source: accounts commit bb00131e51b3a5360980c657cefa13dcfae5ba09 (Task A4 / PR #163).
const AccountsCommitSHA = "bb00131e51b3a5360980c657cefa13dcfae5ba09"

type accountsRouteEntry struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func TestOverlayV1RoutesContract(t *testing.T) {
	goldenPath := "testdata/accounts_overlay_v1_routes.json"
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", goldenPath, err)
	}

	var accountsRoutes []accountsRouteEntry
	if err := json.Unmarshal(data, &accountsRoutes); err != nil {
		t.Fatalf("failed to unmarshal accounts routes: %v", err)
	}

	accountsRouteSet := make(map[string]bool)
	for _, r := range accountsRoutes {
		key := r.Method + " " + r.Path
		accountsRouteSet[key] = true
	}

	for _, route := range controlplane.ClientOverlayRoutes {
		key := route.Method + " " + route.Path
		if !accountsRouteSet[key] {
			t.Errorf("route %s is called by controlplane client but does NOT exist in accounts overlay v1 routes (source accounts %s)",
				key, AccountsCommitSHA)
		}
	}
}
