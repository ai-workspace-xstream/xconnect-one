package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

func runLogin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	email := flags.String("email", "", "user email or username for credential login")
	passwordStdin := flags.Bool("password-stdin", false, "read password from standard input")
	totp := flags.String("totp", "", "TOTP 6-digit code for MFA (optional)")
	web := flags.Bool("web", false, "authenticate via browser OAuth / SSO")
	provider := flags.String("provider", "google", "OAuth provider for web login (e.g. google, github)")
	status := flags.Bool("status", false, "display current login session status")
	asJSON := flags.Bool("json", false, "output login status or response as JSON")
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil {
		return fault.New(fault.CodeInvalidInput, "parse login arguments", err)
	}

	if *status {
		sess, err := credential.LoadUserSession(*stateDirectory)
		if err != nil {
			if *asJSON {
				return writeJSON(stdout, map[string]any{"logged_in": false})
			}
			fmt.Fprintln(stdout, "Not logged in")
			return nil
		}
		if !sess.ExpiresAt.IsZero() && time.Now().UTC().After(sess.ExpiresAt) {
			if *asJSON {
				return writeJSON(stdout, map[string]any{"logged_in": false, "expired": true, "email": sess.Email})
			}
			fmt.Fprintf(stdout, "Session expired for %s (server: %s)\n", sess.Email, sess.Server)
			return nil
		}
		if *asJSON {
			return writeJSON(stdout, map[string]any{
				"logged_in":  true,
				"email":      sess.Email,
				"server":     sess.Server,
				"user_id":    sess.UserID,
				"expires_at": sess.ExpiresAt,
			})
		}
		fmt.Fprintf(stdout, "Logged in as %s (server: %s, user_id: %s)\n", sess.Email, sess.Server, sess.UserID)
		return nil
	}

	if *web {
		return loginWeb(ctx, *server, *provider, *stateDirectory, stdout, stderr, httpClient)
	}

	if strings.TrimSpace(*email) == "" {
		return fault.New(fault.CodeInvalidInput, "login requires --email (or --web / --status)", nil)
	}

	var password string
	if *passwordStdin {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		password = strings.TrimSpace(string(raw))
	} else {
		fmt.Fprintf(stderr, "Password: ")
		pwd, err := readPassword(os.Stdin)
		if err != nil {
			return err
		}
		password = pwd
	}

	return loginCredentials(ctx, *server, *email, password, *totp, *stateDirectory, stdout, stderr, httpClient)
}

func loginWeb(ctx context.Context, server, provider, stateDir string, stdout, stderr io.Writer, httpClient *http.Client) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fault.New(fault.CodeControlPlaneUnavailable, "listen loopback callback", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			code := r.URL.Query().Get("exchange_code")
			if code == "" {
				code = r.URL.Query().Get("code")
			}
			if code == "" {
				http.Error(w, "missing exchange code", http.StatusBadRequest)
				errChan <- errors.New("missing exchange code in callback")
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<html><body><h2>Authentication successful!</h2><p>You may close this tab and return to XConnect terminal.</p></body></html>")
			codeChan <- code
		}),
	}
	go func() {
		_ = srv.Serve(listener)
	}()
	defer srv.Shutdown(context.Background())

	authURL := fmt.Sprintf("%s/api/auth/oauth/login/%s?redirect_uri=%s", strings.TrimRight(server, "/"), provider, url.QueryEscape(redirectURI))
	fmt.Fprintf(stderr, "Opening browser for authentication:\n%s\n", authURL)
	_ = openBrowser(authURL)

	var exchangeCode string
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return fault.New(fault.CodeAuthenticationFailed, "oauth callback failed", err)
	case exchangeCode = <-codeChan:
	case <-time.After(3 * time.Minute):
		return fault.New(fault.CodeAuthenticationFailed, "authentication timed out", nil)
	}

	exchangeURL := fmt.Sprintf("%s/api/auth/token/exchange", strings.TrimRight(server, "/"))
	bodyJSON, _ := json.Marshal(map[string]string{"exchange_code": exchangeCode})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exchangeURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fault.New(fault.CodeControlPlaneUnavailable, "token exchange request", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBytes, _ := io.ReadAll(resp.Body)
		return fault.New(fault.CodeAuthenticationFailed, fmt.Sprintf("token exchange failed (%d): %s", resp.StatusCode, string(errBytes)), nil)
	}

	var exchangeResp struct {
		Token       string                 `json:"token"`
		AccessToken string                 `json:"access_token"`
		ExpiresAt   *time.Time             `json:"expiresAt"`
		User        map[string]interface{} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&exchangeResp); err != nil {
		return fault.New(fault.CodeInvalidResponse, "decode token exchange", err)
	}
	token := exchangeResp.AccessToken
	if token == "" {
		token = exchangeResp.Token
	}
	email := ""
	userID := ""
	if exchangeResp.User != nil {
		if e, ok := exchangeResp.User["email"].(string); ok {
			email = e
		}
		if id, ok := exchangeResp.User["id"].(string); ok {
			userID = id
		}
	}
	exp := time.Now().Add(24 * time.Hour)
	if exchangeResp.ExpiresAt != nil {
		exp = *exchangeResp.ExpiresAt
	}
	sess := credential.UserSession{
		Server:      server,
		Email:       email,
		UserID:      userID,
		AccessToken: token,
		ExpiresAt:   exp,
	}
	if err := credential.SaveUserSession(stateDir, sess); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Login successful! Logged in as %s\n", email)
	return nil
}

func loginCredentials(ctx context.Context, server, email, password, totpCode, stateDir string, stdout, stderr io.Writer, httpClient *http.Client) error {
	loginURL := fmt.Sprintf("%s/api/auth/login", strings.TrimRight(server, "/"))
	payload := map[string]string{
		"identifier": email,
		"password":   password,
		"totp_code":  totpCode,
	}
	rawPayload, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(rawPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fault.New(fault.CodeControlPlaneUnavailable, "login request", err)
	}
	defer resp.Body.Close()

	var loginResp struct {
		Message     string                 `json:"message"`
		Token       string                 `json:"token"`
		AccessToken string                 `json:"access_token"`
		MFARequired bool                   `json:"mfa_required"`
		ExpiresAt   *time.Time             `json:"expiresAt"`
		User        map[string]interface{} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fault.New(fault.CodeInvalidResponse, "decode login response", err)
	}

	if loginResp.MFARequired {
		if totpCode == "" {
			fmt.Fprintf(stderr, "MFA required. Enter TOTP code: ")
			code, err := readPassword(os.Stdin)
			if err != nil {
				return err
			}
			totpCode = code
		}
		payload["totp_code"] = totpCode
		rawPayload, _ = json.Marshal(payload)
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(rawPayload))
		if err != nil {
			return err
		}
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := httpClient.Do(req2)
		if err != nil {
			return fault.New(fault.CodeControlPlaneUnavailable, "mfa login request", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			errBytes, _ := io.ReadAll(resp2.Body)
			return fault.New(fault.CodeAuthenticationFailed, fmt.Sprintf("MFA authentication failed (%d): %s", resp2.StatusCode, string(errBytes)), nil)
		}
		if err := json.NewDecoder(resp2.Body).Decode(&loginResp); err != nil {
			return fault.New(fault.CodeInvalidResponse, "decode MFA response", err)
		}
	} else if resp.StatusCode != http.StatusOK {
		return fault.New(fault.CodeAuthenticationFailed, fmt.Sprintf("authentication failed (%d): %s", resp.StatusCode, loginResp.Message), nil)
	}

	token := loginResp.AccessToken
	if token == "" {
		token = loginResp.Token
	}
	if token == "" {
		return fault.New(fault.CodeAuthenticationFailed, "no access token returned", nil)
	}
	userID := ""
	if loginResp.User != nil {
		if id, ok := loginResp.User["id"].(string); ok {
			userID = id
		}
	}
	exp := time.Now().Add(24 * time.Hour)
	if loginResp.ExpiresAt != nil {
		exp = *loginResp.ExpiresAt
	}
	sess := credential.UserSession{
		Server:      server,
		Email:       email,
		UserID:      userID,
		AccessToken: token,
		ExpiresAt:   exp,
	}
	if err := credential.SaveUserSession(stateDir, sess); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Login successful! Logged in as %s\n", email)
	return nil
}

func runLogout(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("xconnect logout", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil {
		return fault.New(fault.CodeInvalidInput, "parse logout arguments", err)
	}
	if err := credential.DeleteUserSession(*stateDirectory); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Logged out successfully")
	return nil
}

func runGateway(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	if len(args) == 0 {
		return fault.New(fault.CodeInvalidInput, "expected gateway list or select", nil)
	}
	switch args[0] {
	case "list", "ls":
		return runGatewayList(ctx, args[1:], stdout, stderr, httpClient)
	case "select":
		return runGatewaySelect(ctx, args[1:], stdout, stderr, httpClient, newRuntime, newCredentials)
	default:
		return fault.New(fault.CodeInvalidInput, fmt.Sprintf("unknown gateway command %q", args[0]), nil)
	}
}

func runGatewayList(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client) error {
	flags := flag.NewFlagSet("xconnect gateway list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	asJSON := flags.Bool("json", false, "output gateways as JSON")
	if err := flags.Parse(args); err != nil {
		return fault.New(fault.CodeInvalidInput, "parse gateway list arguments", err)
	}
	session, err := credential.LoadUserSession(*stateDirectory)
	if err != nil {
		return fault.New(fault.CodeAuthenticationFailed, "please login first using 'xconnect login'", err)
	}
	client, err := controlplane.New(session.Server, session.AccessToken, httpClient)
	if err != nil {
		return err
	}
	gateways, err := client.ListGateways(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, map[string]any{"gateways": gateways})
	}
	if len(gateways) == 0 {
		fmt.Fprintln(stdout, "No gateways available for your account")
		return nil
	}
	fmt.Fprintf(stdout, "%-22s %-16s %-20s %-24s %-14s %-8s\n", "GATEWAY ID", "NETWORK", "DISPLAY NAME", "ENDPOINT", "MODE", "HEALTHY")
	for _, gw := range gateways {
		healthy := "no"
		if gw.RuntimeHealthy {
			healthy = "yes"
		}
		endpoint := gw.EndpointHost
		if gw.EndpointPort > 0 {
			endpoint = fmt.Sprintf("%s:%d", gw.EndpointHost, gw.EndpointPort)
		}
		name := gw.DisplayName
		if name == "" {
			name = gw.GatewayID
		}
		fmt.Fprintf(stdout, "%-22s %-16s %-20s %-24s %-14s %-8s\n", gw.GatewayID, gw.NetworkID, name, endpoint, gw.ConnectionMode, healthy)
	}
	return nil
}

func runGatewaySelect(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect gateway select", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID")
	deviceName := flags.String("name", "", "device display name")
	up := flags.Bool("up", false, "bring up tunnel interface after enrolling")
	if err := flags.Parse(args); err != nil || flags.NArg() != 1 {
		return fault.New(fault.CodeInvalidInput, "gateway select requires exactly one <gateway-id>", nil)
	}
	selectedGatewayID := flags.Arg(0)
	session, err := credential.LoadUserSession(*stateDirectory)
	if err != nil {
		return fault.New(fault.CodeAuthenticationFailed, "please login first using 'xconnect login'", err)
	}
	client, err := controlplane.New(session.Server, session.AccessToken, httpClient)
	if err != nil {
		return err
	}
	gateways, err := client.ListGateways(ctx)
	if err != nil {
		return err
	}
	var targetGateway *controlplane.GatewayEndpoint
	for i := range gateways {
		if gateways[i].GatewayID == selectedGatewayID {
			targetGateway = &gateways[i]
			break
		}
	}
	if targetGateway == nil {
		return fault.New(fault.CodeInvalidInput, fmt.Sprintf("gateway %q not found in available gateways", selectedGatewayID), nil)
	}

	stStore := state.NewStore(*stateDirectory)
	privKey, pubKey, err := ensureWireGuardKeyPair(stStore)
	if err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	enrollResp, err := client.EnrollDevice(ctx, controlplane.DeviceEnrollRequest{
		NetworkID:          targetGateway.NetworkID,
		GatewayID:          targetGateway.GatewayID,
		DeviceID:           *deviceID,
		Name:               *deviceName,
		Platform:           runtime.GOOS,
		Hostname:           hostname,
		WireGuardPublicKey: pubKey,
	})
	if err != nil {
		return err
	}

	signedCfg, err := client.GetEnrollmentSignedConfigV2(ctx, enrollResp.EnrollmentToken, controlplane.SignedConfigRequest{
		DeviceID:  *deviceID,
		NetworkID: targetGateway.NetworkID,
	})
	if err != nil {
		return err
	}

	if err := signedconfig.Verify(signedCfg, signedconfig.SigningKeys{Keys: enrollResp.SigningKeys}, time.Now().UTC()); err != nil {
		return err
	}

	compiledModel, err := signedconfig.Compile(signedCfg)
	if err != nil {
		return err
	}

	credStore := newCredentials(*stateDirectory)
	credRecord := credential.Record{
		SchemaVersion:      credential.SchemaVersion,
		Controller:         session.Server,
		DeviceID:           *deviceID,
		NetworkID:          targetGateway.NetworkID,
		Platform:           runtime.GOOS,
		WireGuardPublicKey: pubKey,
		CredentialID:       enrollResp.DeviceCredential.CredentialID,
		Credential:         enrollResp.DeviceCredential.Credential,
		IssuedAt:           enrollResp.DeviceCredential.IssuedAt,
		ExpiresAt:          enrollResp.DeviceCredential.ExpiresAt,
		Scope:              enrollResp.DeviceCredential.Scope,
		SigningKeys:        signedconfig.SigningKeys{Keys: enrollResp.SigningKeys},
	}
	if err := credStore.Save(ctx, credRecord); err != nil {
		return err
	}

	_, _ = client.AckEnrollmentSignedConfig(ctx, enrollResp.EnrollmentToken, controlplane.SignedConfigAckRequest{
		Generation: signedCfg.Generation,
		ConfigID:   signedCfg.ConfigID,
		DeviceID:   *deviceID,
		AppliedAt:  time.Now().UTC(),
	})

	_ = stStore.SaveLastKnown(state.LastKnown{
		Server:              session.Server,
		DeviceID:            *deviceID,
		NetworkID:           targetGateway.NetworkID,
		WireGuardPrivateKey: privKey,
		WireGuardPublicKey:  pubKey,
		Phase:               state.PhaseAcknowledged,
		ConfigContract:      string(usecase.ConfigContractSigned),
		SignedConfigID:      signedCfg.ConfigID,
		SignedGeneration:    signedCfg.Generation,
		Config:              compiledModel,
	})

	if *up {
		rt := newRuntime(*stateDirectory)
		_, err := rt.Apply(ctx, overlayruntime.ApplyRequest{
			Config:              compiledModel,
			WireGuardPrivateKey: privKey,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Enrolled and connected to gateway %s on network %s (generation %d)\n", targetGateway.GatewayID, targetGateway.NetworkID, signedCfg.Generation)
		return nil
	}

	result := map[string]any{
		"gateway_id": targetGateway.GatewayID,
		"network_id": targetGateway.NetworkID,
		"device_id":  *deviceID,
		"config_id":  signedCfg.ConfigID,
		"generation": signedCfg.Generation,
		"status":     "enrolled",
	}
	return writeJSON(stdout, result)
}

func ensureWireGuardKeyPair(stStore *state.Store) (string, string, error) {
	if lk, err := stStore.LoadLastKnown(); err == nil && lk.WireGuardPrivateKey != "" && lk.WireGuardPublicKey != "" {
		return lk.WireGuardPrivateKey, lk.WireGuardPublicKey, nil
	}
	return usecase.GenerateWireGuardKeyPair()
}

func readPassword(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func openBrowser(targetURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", targetURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	default:
		return exec.Command("xdg-open", targetURL).Start()
	}
}
