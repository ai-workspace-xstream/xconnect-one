package controlplane_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/model"
)

func TestClientListGatewaysAndEnrollDevice(t *testing.T) {
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-jwt-token" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/overlay/v1/gateways":
			_ = json.NewEncoder(w).Encode(controlplane.GatewaysResponse{
				Gateways: []controlplane.GatewayEndpoint{
					{
						NetworkID:           "net_uat",
						NetworkDisplayName:  "UAT Network",
						GatewayID:           "gw-uat-tw-xconnect",
						DisplayName:         "Taiwan Gateway",
						EndpointHost:        "tw-xconnect.svc.plus",
						EndpointPort:        51820,
						TransportServerName: "tw-xconnect.svc.plus",
						TransportPort:       443,
						ConnectionMode:      "wg_vless_l3",
						RuntimeHealthy:      true,
						LastSeenAt:          &now,
					},
				},
			})
		case "/api/overlay/v1/devices/enroll":
			var req controlplane.DeviceEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(controlplane.JoinTokenExchangeResponse{
				EnrollmentToken: "test-enroll-tok",
				TokenType:       "Bearer",
				ExpiresAt:       now.Add(time.Hour),
				DeviceCredential: controlplane.DeviceCredential{
					CredentialID: "xdcid_0123456789abcdef0123456789abcdef",
					Credential:   "xdc_0123456789abcdef0123456789abcdef.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				},
				Device: model.Device{
					ID: req.DeviceID,
				},
				Network: model.Network{
					ID: req.NetworkID,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := controlplane.New(server.URL, "test-jwt-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}

	gateways, err := client.ListGateways(context.Background())
	if err != nil {
		t.Fatalf("ListGateways failed: %v", err)
	}
	if len(gateways) != 1 || gateways[0].GatewayID != "gw-uat-tw-xconnect" {
		t.Fatalf("unexpected gateways: %+v", gateways)
	}

	enrollResp, err := client.EnrollDevice(context.Background(), controlplane.DeviceEnrollRequest{
		NetworkID:          "net_uat",
		GatewayID:          "gw-uat-tw-xconnect",
		DeviceID:           "one-macbook",
		Platform:           "darwin",
		WireGuardPublicKey: "test-pubkey",
	})
	if err != nil {
		t.Fatalf("EnrollDevice failed: %v", err)
	}
	if enrollResp.EnrollmentToken != "test-enroll-tok" || enrollResp.Device.ID != "one-macbook" {
		t.Fatalf("unexpected enroll response: %+v", enrollResp)
	}
}
