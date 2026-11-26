package accelerate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
)

const nodesPath = "/api/agent-server/v1/nodes"

type node struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Display string `json:"display_name"`
	XHTTP   string `json:"uri_scheme_xhttp"`
	TCP     string `json:"uri_scheme_tcp"`
	VLESS   string `json:"vless_uri"`
	URI     string `json:"uri"`
}

func Profile(ctx context.Context, client *http.Client, session credential.UserSession, gateway string) ([]byte, error) {
	if session.AccessToken == "" || (!session.ExpiresAt.IsZero() && !time.Now().Before(session.ExpiresAt)) {
		return nil, errors.New("login session expired; run xconnect accelerate login")
	}
	server, err := url.Parse(session.Server)
	if err != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil ||
		server.RawQuery != "" || server.Fragment != "" {
		return nil, errors.New("acceleration requires an HTTPS Accounts server")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.JoinPath(nodesPath).String(), nil)
	if err != nil {
		return nil, errors.New("invalid Accounts endpoint")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if requestClient.Timeout == 0 {
		requestClient.Timeout = 20 * time.Second
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		return nil, errors.New("could not reach the Accounts node service")
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil, errors.New("Accounts session rejected; run xconnect accelerate login")
	case http.StatusForbidden:
		return nil, errors.New("Accounts did not authorize acceleration")
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("Accounts node service returned HTTP %d", resp.StatusCode)
	}
	const maxBytes = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	var nodes []node
	if err != nil || len(body) > maxBytes || json.Unmarshal(body, &nodes) != nil {
		return nil, errors.New("invalid Accounts node response")
	}
	return selectProfile(nodes, gateway)
}

func selectProfile(nodes []node, gateway string) ([]byte, error) {
	var selected []byte
	for _, n := range nodes {
		for _, share := range []string{n.XHTTP, n.TCP, n.VLESS, n.URI} {
			u, err := url.Parse(strings.TrimSpace(share))
			if err != nil || u.Scheme != "vless" {
				continue
			}
			if gateway != "" && gateway != n.ID && gateway != n.Address &&
				!strings.EqualFold(gateway, n.Name) && !strings.EqualFold(gateway, n.Display) &&
				!strings.EqualFold(gateway, u.Hostname()) && !strings.EqualFold(gateway, u.Host) {
				continue
			}
			profile, err := buildProfile(u)
			if err != nil {
				continue
			}
			if gateway == "" {
				return profile, nil
			}
			if selected != nil {
				return nil, errors.New("gateway matches multiple acceleration nodes; use the exact node ID")
			}
			selected = profile
			break
		}
	}
	if selected == nil {
		return nil, errors.New("no authorized VLESS/TLS acceleration node matches; check the account and gateway")
	}
	return selected, nil
}

const (
	tunName = "xconnect-accel"
	tunIPv4 = "198.18.0.1/32"
	tunIPv6 = "fd42:7863:6163::1/128"
)

func buildProfile(u *url.URL) ([]byte, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || u.User == nil || u.User.Username() == "" || u.Hostname() == "" || q.Get("security") != "tls" {
		return nil, errors.New("unsupported acceleration profile")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, errors.New("unsupported VLESS user information")
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid acceleration port")
	}
	if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
		return nil, errors.New("unsupported VLESS encryption")
	}
	network := q.Get("type")
	if network == "" || network == "raw" {
		network = "tcp"
	}
	if network != "tcp" && network != "xhttp" {
		return nil, errors.New("unsupported acceleration transport")
	}
	if header := q.Get("headerType"); header != "" && header != "none" {
		return nil, errors.New("unsupported transport header")
	}
	if q.Has("extra") {
		return nil, errors.New("unsupported split HTTP options")
	}
	serverName := q.Get("sni")
	if serverName == "" {
		serverName = u.Hostname()
	}
	tls := map[string]any{"serverName": serverName}
	if fingerprint := q.Get("fp"); fingerprint != "" {
		tls["fingerprint"] = fingerprint
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	stream := map[string]any{"network": network, "security": "tls", "tlsSettings": tls}
	if network == "xhttp" {
		stream["xhttpSettings"] = map[string]string{"host": q.Get("host"), "path": q.Get("path"), "mode": q.Get("mode")}
	}
	user := map[string]string{"id": u.User.Username(), "encryption": "none"}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	return json.Marshal(map[string]any{
		"log": map[string]string{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"protocol": "tun",
			"settings": map[string]any{
				"name": tunName, "mtu": 1400,
				"gateway": []string{tunIPv4, tunIPv6},
			},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": u.Hostname(), "port": port, "users": []any{user},
			}}},
			"streamSettings": stream,
		}},
	})
}
