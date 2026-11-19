package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
)

// openBrowserFunc is swappable in tests so no real browser is launched.
var openBrowserFunc = openBrowser

// sessionJoinOptions drives the simplified "login -> join -> up" flow.
type sessionJoinOptions struct {
	StateDirectory string
	DeviceID       string
	DeviceName     string
	Gateway        string
	NetworkID      string
	ConsoleURL     string
	OpenBrowser    bool
	Wait           time.Duration
	PollInterval   time.Duration
}

// runJoinWithSession joins a private network using the saved login session:
//  1. list gateways authorized for the logged-in account;
//  2. if none, open the console binding page (select gateway, select network,
//     authorize the current account) and wait until the authorization shows up;
//  3. select the gateway/network and enroll this device;
//  4. tell the user to run `xconnect-one up`.
func runJoinWithSession(
	ctx context.Context,
	session credential.UserSession,
	opts sessionJoinOptions,
	stdin io.Reader,
	stdout, stderr io.Writer,
	httpClient *http.Client,
	newCredentials credentialFactory,
) error {
	client, err := controlplane.New(session.Server, session.AccessToken, httpClient)
	if err != nil {
		return err
	}
	gateways, err := client.ListGateways(ctx)
	if err != nil {
		return err
	}
	gateways = filterGatewaysByNetwork(gateways, opts.NetworkID)

	if len(gateways) == 0 {
		gateways, err = awaitConsoleBinding(ctx, client, session, opts, stderr)
		if err != nil {
			return err
		}
	}

	enrolled, err := enrollResolvedGateway(ctx, client, session, opts.StateDirectory, opts.DeviceID, opts.DeviceName, gateways, opts.Gateway, stdin, stderr, newCredentials)
	if err != nil {
		return err
	}
	host := enrolled.Gateway.EndpointHost
	if host == "" {
		host = enrolled.Gateway.TransportServerName
	}
	fmt.Fprintf(stdout, "Joined network %s via gateway %s (%s).\n", enrolled.Gateway.NetworkID, enrolled.Gateway.GatewayID, host)
	fmt.Fprintln(stdout, "Next: run 'xconnect-one up' to connect to the private network.")
	return nil
}

// awaitConsoleBinding guides the user to the console binding page and polls
// the control plane until a gateway network is authorized for this account.
func awaitConsoleBinding(ctx context.Context, client *controlplane.Client, session credential.UserSession, opts sessionJoinOptions, stderr io.Writer) ([]controlplane.GatewayEndpoint, error) {
	bindURL, err := buildConsoleBindingURL(opts.ConsoleURL, opts.NetworkID, opts.Gateway)
	if err != nil {
		return nil, err
	}
	account := strings.TrimSpace(session.Email)
	if account == "" {
		account = "the current account"
	}
	if strings.TrimSpace(opts.NetworkID) != "" {
		fmt.Fprintf(stderr, "Network %s is not authorized for %s yet.\n", opts.NetworkID, account)
	} else {
		fmt.Fprintf(stderr, "No gateway network is authorized for %s yet.\n", account)
	}
	fmt.Fprintln(stderr, "Complete the binding in the console:")
	fmt.Fprintln(stderr, "  1. Select a gateway   (e.g. ph-xconnect-gateway-01)")
	fmt.Fprintln(stderr, "  2. Select a network   (e.g. net-ph-xconnect)")
	fmt.Fprintf(stderr, "  3. Authorize account  %s\n", account)
	fmt.Fprintf(stderr, "Console: %s\n", bindURL)
	if opts.OpenBrowser {
		if err := openBrowserFunc(bindURL); err != nil {
			fmt.Fprintln(stderr, "(Could not open a browser automatically; open the URL above manually.)")
		}
	}
	if opts.Wait <= 0 {
		return nil, fault.New(fault.CodeNotJoined, "gateway network not authorized yet; re-run 'xconnect-one join' after binding in the console", nil)
	}

	interval := opts.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	fmt.Fprintf(stderr, "Waiting for authorization (up to %s, Ctrl-C to cancel)...\n", opts.Wait)
	waitCtx, cancel := context.WithTimeout(ctx, opts.Wait)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fault.New(fault.CodeNotJoined, fmt.Sprintf("timed out after %s waiting for console binding; re-run 'xconnect-one join' once the network is authorized", opts.Wait), nil)
		case <-ticker.C:
			gateways, err := client.ListGateways(waitCtx)
			if err != nil {
				// Transient control-plane errors should not abort the wait.
				continue
			}
			gateways = filterGatewaysByNetwork(gateways, opts.NetworkID)
			if len(gateways) > 0 {
				fmt.Fprintln(stderr, "Authorization detected.")
				return gateways, nil
			}
		}
	}
}

func filterGatewaysByNetwork(gateways []controlplane.GatewayEndpoint, networkID string) []controlplane.GatewayEndpoint {
	networkID = strings.TrimSpace(networkID)
	if networkID == "" {
		return gateways
	}
	filtered := make([]controlplane.GatewayEndpoint, 0, len(gateways))
	for _, gw := range gateways {
		if strings.EqualFold(gw.NetworkID, networkID) {
			filtered = append(filtered, gw)
		}
	}
	return filtered
}

// buildConsoleBindingURL appends optional network/gateway hints so the console
// page can preselect them. Only non-secret identifiers are ever added.
func buildConsoleBindingURL(base, networkID, gateway string) (string, error) {
	base = strings.TrimSpace(base)
	if base == "" {
		base = defaultConsoleBindingURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return "", fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid --console-url %q", base), err)
	}
	query := parsed.Query()
	if v := strings.TrimSpace(networkID); v != "" {
		query.Set("network", v)
	}
	if v := normalizeGatewaySelector(gateway); v != "" {
		query.Set("gateway", v)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
