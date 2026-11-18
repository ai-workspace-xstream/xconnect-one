package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

type GatewayEndpoint struct {
	NetworkID           string     `json:"network_id"`
	NetworkDisplayName  string     `json:"network_display_name"`
	GatewayID           string     `json:"gateway_id"`
	DisplayName         string     `json:"display_name"`
	EndpointHost        string     `json:"gateway_endpoint_host"`
	EndpointPort        int        `json:"gateway_endpoint_port"`
	TransportServerName string     `json:"transport_server_name"`
	TransportPort       int        `json:"transport_port"`
	ConnectionMode      string     `json:"connection_mode"`
	RuntimeHealthy      bool       `json:"runtime_healthy"`
	LastSeenAt          *time.Time `json:"last_seen_at,omitempty"`
}

type GatewaysResponse struct {
	Gateways []GatewayEndpoint `json:"gateways"`
}

type DeviceEnrollRequest struct {
	NetworkID          string `json:"network_id"`
	GatewayID          string `json:"gateway_id,omitempty"`
	DeviceID           string `json:"device_id"`
	Name               string `json:"name,omitempty"`
	Platform           string `json:"platform"`
	Hostname           string `json:"hostname,omitempty"`
	WireGuardPublicKey string `json:"wireguard_public_key"`
}

func (c *Client) ListGateways(ctx context.Context) ([]GatewayEndpoint, error) {
	if c.token == "" {
		return nil, fault.New(fault.CodeAuthenticationFailed, "list gateways requires user authentication token", nil)
	}
	var resp GatewaysResponse
	err := c.doJSON(ctx, http.MethodGet, RouteGateways.Path, nil, nil, &resp, nil)
	if err != nil {
		return nil, err
	}
	return resp.Gateways, nil
}

func (c *Client) EnrollDevice(ctx context.Context, request DeviceEnrollRequest) (JoinTokenExchangeResponse, error) {
	if c.token == "" {
		return JoinTokenExchangeResponse{}, fault.New(fault.CodeAuthenticationFailed, "device enroll requires user authentication token", nil)
	}
	var resp JoinTokenExchangeResponse
	err := c.doJSON(ctx, http.MethodPost, RouteDevicesEnroll.Path, nil, request, &resp, nil)
	if err != nil {
		return JoinTokenExchangeResponse{}, err
	}
	return resp, nil
}
