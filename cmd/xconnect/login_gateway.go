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
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/controlplane"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	overlayruntime "github.com/ai-workspace-xstream/XConnect-One/overlay/runtime"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/signedconfig"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

var (
	isTerminalFD         = term.IsTerminal
	readTerminalPassword = term.ReadPassword
)

func runLogin(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	defaultStateDir, primaryStateDir, fallbackReason := resolveDefaultStateDirectory()
	flags := flag.NewFlagSet("xconnect login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server := flags.String("server", defaultAccountsServer, "accounts service base URL")
	email := flags.String("email", "", "user email or username for credential login")
	passwordStdin := flags.Bool("password-stdin", false, "read password from standard input")
	showPassword := flags.Bool("show-password", false, "echo password input visibly in terminal (insecure)")
	totp := flags.String("totp", "", "TOTP 6-digit code for MFA (optional)")
	web := flags.Bool("web", false, "authenticate via browser OAuth / SSO")
	provider := flags.String("provider", "google", "OAuth provider for web login (e.g. google, github)")
	status := flags.Bool("status", false, "display current login session status")
	asJSON := flags.Bool("json", false, "output login status or response as JSON")
	gatewayTarget := flags.String("gateway", "", "optional gateway ID, endpoint host, or URL (e.g. "+defaultKnownGateway+")")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID (used with --gateway)")
	deviceName := flags.String("name", "", "device display name (used with --gateway)")
	stateDirectory := flags.String("state-dir", defaultStateDir, "local XConnect-One state directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse login arguments", err)
	}
	if flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "unexpected positional arguments for login", nil)
	}

	explicitFlags := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	*stateDirectory = expandUserPath(*stateDirectory)

	if *status {
		sess, err := credential.LoadUserSession(*stateDirectory)
		if errors.Is(err, credential.ErrNotFound) {
			if *asJSON {
				return writeJSON(stdout, map[string]any{"logged_in": false})
			}
			fmt.Fprintln(stdout, "Not logged in")
			return nil
		}
		if err != nil {
			return err
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

	interactive := isTerminal(os.Stdin) && !*passwordStdin

	if !explicitFlags["state-dir"] && fallbackReason != "" {
		fmt.Fprintf(stderr, "Note: default state directory %q is %s; using %q (or pass --state-dir)\n", primaryStateDir, fallbackReason, *stateDirectory)
	}
	if !explicitFlags["state-dir"] && interactive {
		fmt.Fprintf(stderr, "State directory [%s]: ", *stateDirectory)
		line, err := readLine(os.Stdin)
		if err != nil {
			return err
		}
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			*stateDirectory = expandUserPath(trimmed)
		}
	}
	if err := credential.EnsureWritableStateDir(*stateDirectory); err != nil {
		return err
	}

	if !explicitFlags["server"] && interactive {
		fmt.Fprintf(stderr, "Accounts server [%s]: ", *server)
		line, err := readLine(os.Stdin)
		if err != nil {
			return err
		}
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			*server = trimmed
		}
	}
	normalizedServer, err := normalizeServerURL(*server)
	if err != nil {
		return err
	}
	*server = normalizedServer

	if *web {
		if err := loginWeb(ctx, *server, *provider, *stateDirectory, stdout, stderr, httpClient); err != nil {
			return err
		}
	} else {
		trimmedEmail := strings.TrimSpace(*email)
		if trimmedEmail == "" {
			if !isTerminal(os.Stdin) {
				return fault.New(fault.CodeInvalidInput, "login requires --email (or --web / --status)", nil)
			}
			fmt.Fprintf(stderr, "Email: ")
			line, err := readLine(os.Stdin)
			if err != nil {
				return err
			}
			trimmedEmail = strings.TrimSpace(line)
			if trimmedEmail == "" {
				return fault.New(fault.CodeInvalidInput, "email cannot be empty", nil)
			}
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
			pwd, err := readPassword(os.Stdin, stderr, *showPassword)
			if err != nil {
				return err
			}
			password = pwd
		}

		if err := loginCredentialsWithPrompt(ctx, *server, trimmedEmail, password, *totp, *stateDirectory, *showPassword, !*passwordStdin, stdout, stderr, httpClient); err != nil {
			return err
		}
	}

	if strings.TrimSpace(*gatewayTarget) != "" {
		session, err := credential.LoadUserSession(*stateDirectory)
		if err != nil {
			return err
		}
		enrolled, err := resolveAndEnrollGateway(ctx, session, *stateDirectory, *deviceID, *deviceName, *gatewayTarget, stderr, httpClient, newCredentials)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Selected gateway %s (%s) on network %s\n", enrolled.Gateway.GatewayID, enrolled.Gateway.EndpointHost, enrolled.Gateway.NetworkID)
	} else if interactive {
		session, err := credential.LoadUserSession(*stateDirectory)
		if err != nil {
			return err
		}
		enrolled, skipped, err := promptAndEnrollGatewayOnLogin(ctx, session, *stateDirectory, *deviceID, *deviceName, os.Stdin, stderr, httpClient, newCredentials)
		if err != nil {
			return err
		}
		if !skipped {
			fmt.Fprintf(stdout, "Selected gateway %s (%s) on network %s\n", enrolled.Gateway.GatewayID, enrolled.Gateway.EndpointHost, enrolled.Gateway.NetworkID)
		}
	}
	return nil
}

func normalizeServerURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fault.New(fault.CodeInvalidInput, "server URL cannot be empty", nil)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid server URL %q (expected http:// or https:// URL)", trimmed), err)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String(), nil
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
	return loginCredentialsWithPrompt(ctx, server, email, password, totpCode, stateDir, false, true, stdout, stderr, httpClient)
}

func loginCredentialsWithPrompt(ctx context.Context, server, email, password, totpCode, stateDir string, showPassword, allowMFAPrompt bool, stdout, stderr io.Writer, httpClient *http.Client) error {
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
		MFATicket   string                 `json:"mfa_ticket"`
		MFAToken    string                 `json:"mfaToken"`
		ExpiresAt   *time.Time             `json:"expiresAt"`
		User        map[string]interface{} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		return fault.New(fault.CodeInvalidResponse, "decode login response", err)
	}

	if loginResp.MFARequired {
		if totpCode == "" {
			if !allowMFAPrompt {
				return fault.New(fault.CodeAuthenticationFailed, "MFA required; pass --totp <code>", nil)
			}
			fmt.Fprintf(stderr, "MFA required. Enter TOTP code: ")
			code, err := readPassword(os.Stdin, stderr, showPassword)
			if err != nil {
				return err
			}
			totpCode = strings.TrimSpace(code)
			if totpCode == "" {
				return fault.New(fault.CodeAuthenticationFailed, "MFA required; TOTP code cannot be empty", nil)
			}
		}
		ticket := strings.TrimSpace(loginResp.MFATicket)
		if ticket == "" {
			ticket = strings.TrimSpace(loginResp.MFAToken)
		}
		var mfaURL string
		var mfaPayload []byte
		if ticket != "" {
			mfaURL = fmt.Sprintf("%s/api/auth/mfa/verify", strings.TrimRight(server, "/"))
			mfaPayload, _ = json.Marshal(map[string]string{
				"mfa_ticket": ticket,
				"totpCode":   totpCode,
			})
		} else {
			mfaURL = loginURL
			payload["totp_code"] = totpCode
			mfaPayload, _ = json.Marshal(payload)
		}
		req2, err := http.NewRequestWithContext(ctx, http.MethodPost, mfaURL, bytes.NewReader(mfaPayload))
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
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse logout arguments", err)
	}
	*stateDirectory = expandUserPath(*stateDirectory)
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
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse gateway list arguments", err)
	}
	*stateDirectory = expandUserPath(*stateDirectory)
	session, err := credential.LoadUserSession(*stateDirectory)
	if err != nil {
		if fault.Code(err) == fault.CodeCredentialStorage {
			return err
		}
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

type enrolledGatewayResult struct {
	Gateway    controlplane.GatewayEndpoint
	Credential credential.Record
	ConfigID   string
	Generation uint64
	PrivateKey string
}

func runGatewaySelect(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	flags := flag.NewFlagSet("xconnect gateway select", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDirectory(), "local XConnect-One state directory")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID")
	deviceName := flags.String("name", "", "device display name")
	up := flags.Bool("up", false, "bring up tunnel interface after enrolling")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse gateway select arguments", err)
	}
	if flags.NArg() != 1 {
		return fault.New(fault.CodeInvalidInput, "gateway select requires exactly one <gateway-id>", nil)
	}
	*stateDirectory = expandUserPath(*stateDirectory)
	selectedGateway := flags.Arg(0)
	session, err := credential.LoadUserSession(*stateDirectory)
	if err != nil {
		if fault.Code(err) == fault.CodeCredentialStorage {
			return err
		}
		return fault.New(fault.CodeAuthenticationFailed, "please login first using 'xconnect login'", err)
	}
	enrolled, err := resolveAndEnrollGateway(ctx, session, *stateDirectory, *deviceID, *deviceName, selectedGateway, stderr, httpClient, newCredentials)
	if err != nil {
		return err
	}

	if *up {
		rt := newRuntime(*stateDirectory)
		stStore := state.NewStore(*stateDirectory)
		lk, lkErr := stStore.LoadLastKnown()
		if lkErr != nil {
			return lkErr
		}
		_, err := rt.Apply(ctx, overlayruntime.ApplyRequest{
			Config:              lk.Config,
			WireGuardPrivateKey: enrolled.PrivateKey,
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Enrolled and connected to gateway %s on network %s (generation %d)\n", enrolled.Gateway.GatewayID, enrolled.Gateway.NetworkID, enrolled.Generation)
		return nil
	}

	result := map[string]any{
		"gateway_id": enrolled.Gateway.GatewayID,
		"network_id": enrolled.Gateway.NetworkID,
		"device_id":  *deviceID,
		"config_id":  enrolled.ConfigID,
		"generation": enrolled.Generation,
		"status":     "enrolled",
	}
	return writeJSON(stdout, result)
}

func resolveAndEnrollGateway(
	ctx context.Context,
	session credential.UserSession,
	stateDirectory string,
	deviceID string,
	deviceName string,
	gatewaySelector string,
	stderr io.Writer,
	httpClient *http.Client,
	newCredentials credentialFactory,
) (enrolledGatewayResult, error) {
	client, err := controlplane.New(session.Server, session.AccessToken, httpClient)
	if err != nil {
		return enrolledGatewayResult{}, err
	}
	gateways, err := client.ListGateways(ctx)
	if err != nil {
		return enrolledGatewayResult{}, err
	}
	if len(gateways) == 0 {
		if strings.TrimSpace(gatewaySelector) != "" {
			return enrolledGatewayResult{}, fault.New(
				fault.CodeNotJoined,
				fmt.Sprintf("no gateways are bound to your account on %s; cannot enroll gateway %q yet (run 'xconnect-one join' to bind a gateway network in the console first)", session.Server, strings.TrimSpace(gatewaySelector)),
				nil,
			)
		}
		return enrolledGatewayResult{}, fault.New(
			fault.CodeNotJoined,
			fmt.Sprintf("no gateways are bound to your account on %s (run 'xconnect-one join' to bind a gateway network in the console first)", session.Server),
			nil,
		)
	}
	return enrollResolvedGateway(ctx, client, session, stateDirectory, deviceID, deviceName, gateways, gatewaySelector, os.Stdin, stderr, newCredentials)
}

func enrollResolvedGateway(
	ctx context.Context,
	client *controlplane.Client,
	session credential.UserSession,
	stateDirectory string,
	deviceID string,
	deviceName string,
	gateways []controlplane.GatewayEndpoint,
	gatewaySelector string,
	stdin io.Reader,
	stderr io.Writer,
	newCredentials credentialFactory,
) (enrolledGatewayResult, error) {
	targetGateway, err := matchOrSelectGateway(gateways, gatewaySelector, stdin, stderr)
	if err != nil {
		return enrolledGatewayResult{}, err
	}

	stStore := state.NewStore(stateDirectory)
	privKey, pubKey, err := ensureWireGuardKeyPair(stStore)
	if err != nil {
		return enrolledGatewayResult{}, err
	}

	hostname, _ := os.Hostname()
	enrollResp, err := client.EnrollDevice(ctx, controlplane.DeviceEnrollRequest{
		NetworkID:          targetGateway.NetworkID,
		GatewayID:          targetGateway.GatewayID,
		DeviceID:           deviceID,
		Name:               deviceName,
		Platform:           runtime.GOOS,
		Hostname:           hostname,
		WireGuardPublicKey: pubKey,
	})
	if err != nil {
		return enrolledGatewayResult{}, err
	}

	signedCfg, err := client.GetEnrollmentSignedConfigV2(ctx, enrollResp.EnrollmentToken, controlplane.SignedConfigRequest{
		DeviceID:  deviceID,
		NetworkID: targetGateway.NetworkID,
	})
	if err != nil {
		return enrolledGatewayResult{}, err
	}

	if err := signedconfig.Verify(signedCfg, signedconfig.SigningKeys{Keys: enrollResp.SigningKeys}, time.Now().UTC()); err != nil {
		return enrolledGatewayResult{}, err
	}

	compiledModel, err := signedconfig.Compile(signedCfg)
	if err != nil {
		return enrolledGatewayResult{}, err
	}

	credStore := newCredentials(stateDirectory)
	credRecord := credential.Record{
		SchemaVersion:      credential.SchemaVersion,
		Controller:         session.Server,
		DeviceID:           deviceID,
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
		return enrolledGatewayResult{}, err
	}

	_, _ = client.AckEnrollmentSignedConfig(ctx, enrollResp.EnrollmentToken, controlplane.SignedConfigAckRequest{
		Generation: signedCfg.Generation,
		ConfigID:   signedCfg.ConfigID,
		DeviceID:   deviceID,
		AppliedAt:  time.Now().UTC(),
	})

	_ = stStore.SaveLastKnown(state.LastKnown{
		Server:              session.Server,
		DeviceID:            deviceID,
		NetworkID:           targetGateway.NetworkID,
		WireGuardPrivateKey: privKey,
		WireGuardPublicKey:  pubKey,
		Phase:               state.PhaseAcknowledged,
		ConfigContract:      string(usecase.ConfigContractSigned),
		SignedConfigID:      signedCfg.ConfigID,
		SignedGeneration:    signedCfg.Generation,
		Config:              compiledModel,
	})

	return enrolledGatewayResult{
		Gateway:    *targetGateway,
		Credential: credRecord,
		ConfigID:   signedCfg.ConfigID,
		Generation: signedCfg.Generation,
		PrivateKey: privKey,
	}, nil
}

func promptAndEnrollGatewayOnLogin(
	ctx context.Context,
	session credential.UserSession,
	stateDirectory string,
	deviceID string,
	deviceName string,
	stdin io.Reader,
	stderr io.Writer,
	httpClient *http.Client,
	newCredentials credentialFactory,
) (enrolledGatewayResult, bool, error) {
	client, err := controlplane.New(session.Server, session.AccessToken, httpClient)
	if err != nil {
		return enrolledGatewayResult{}, false, err
	}
	gateways, listErr := client.ListGateways(ctx)
	if listErr == nil && len(gateways) > 0 {
		defaultIdx := preferredGatewayIndex(gateways)
		fmt.Fprintln(stderr, "Available gateways:")
		for i, gw := range gateways {
			host := gw.EndpointHost
			if host == "" {
				host = gw.TransportServerName
			}
			fmt.Fprintf(stderr, "  [%d] %s (%s, %s)\n", i+1, gw.GatewayID, host, gw.NetworkID)
		}
		fmt.Fprintln(stderr, "  [s] Skip (select later on 'xconnect-one up')")
		fmt.Fprintf(stderr, "Select gateway [%d] (or enter gateway ID/URL, 's' to skip): ", defaultIdx+1)
		line, err := readLine(stdin)
		if err != nil {
			return enrolledGatewayResult{}, false, err
		}
		choice := strings.TrimSpace(line)
		if isSkipChoice(choice) {
			fmt.Fprintln(stderr, "Skipped gateway selection; run 'xconnect-one up' to select and connect later.")
			return enrolledGatewayResult{}, true, nil
		}
		selector := ""
		if choice == "" {
			selector = gateways[defaultIdx].GatewayID
		} else if idx, convErr := strconv.Atoi(choice); convErr == nil {
			if idx < 1 || idx > len(gateways) {
				return enrolledGatewayResult{}, false, fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid gateway selection %q", choice), nil)
			}
			selector = gateways[idx-1].GatewayID
		} else {
			selector = choice
		}
		enrolled, err := enrollResolvedGateway(ctx, client, session, stateDirectory, deviceID, deviceName, gateways, selector, stdin, stderr, newCredentials)
		return enrolled, false, err
	}

	if listErr == nil && len(gateways) == 0 {
		fmt.Fprintf(stderr, "Note: no gateways or networks are currently bound to your account on %s yet.\n", session.Server)
		fmt.Fprintln(stderr, "Your login session has been saved. Next steps:")
		fmt.Fprintln(stderr, "  1. xconnect-one join   (opens the console to bind a gateway/network, e.g. ph-xconnect-gateway-01 / net-ph-xconnect)")
		fmt.Fprintln(stderr, "  2. xconnect-one up     (connect to the private network)")
		return enrolledGatewayResult{}, true, nil
	}

	fmt.Fprintf(stderr, "Note: could not fetch gateway list from server (%v).\n", listErr)
	fmt.Fprintln(stderr, "Gateway options:")
	fmt.Fprintf(stderr, "  [1] %s\n", defaultKnownGateway)
	fmt.Fprintln(stderr, "  [s] Skip (select later on 'xconnect-one up')")
	fmt.Fprintf(stderr, "Select gateway [s] (or enter 1 / gateway ID / URL): ")
	line, err := readLine(stdin)
	if err != nil {
		return enrolledGatewayResult{}, false, err
	}
	choice := strings.TrimSpace(line)
	if choice == "" || isSkipChoice(choice) {
		fmt.Fprintln(stderr, "Skipped gateway selection; run 'xconnect-one up' to select and connect later.")
		return enrolledGatewayResult{}, true, nil
	}
	selector := choice
	if choice == "1" {
		selector = defaultKnownGateway
	}
	enrolled, err := resolveAndEnrollGateway(ctx, session, stateDirectory, deviceID, deviceName, selector, stderr, httpClient, newCredentials)
	return enrolled, false, err
}

func isSkipChoice(choice string) bool {
	return strings.EqualFold(choice, "s") || strings.EqualFold(choice, "skip") || strings.EqualFold(choice, "none")
}

func preferredGatewayIndex(gateways []controlplane.GatewayEndpoint) int {
	for i, gw := range gateways {
		if gw.RuntimeHealthy {
			return i
		}
	}
	return 0
}

func normalizeGatewaySelector(selector string) string {
	trimmed := strings.TrimSpace(selector)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return strings.TrimRight(trimmed, "/")
}

func matchOrSelectGateway(gateways []controlplane.GatewayEndpoint, selector string, stdin io.Reader, stderr io.Writer) (*controlplane.GatewayEndpoint, error) {
	if len(gateways) == 0 {
		return nil, fault.New(fault.CodeNotJoined, "no gateways available for your account", nil)
	}
	trimmed := normalizeGatewaySelector(selector)
	if trimmed != "" {
		for i := range gateways {
			gw := &gateways[i]
			endpointWithPort := ""
			if gw.EndpointHost != "" && gw.EndpointPort > 0 {
				endpointWithPort = fmt.Sprintf("%s:%d", gw.EndpointHost, gw.EndpointPort)
			}
			if strings.EqualFold(gw.GatewayID, trimmed) ||
				strings.EqualFold(gw.EndpointHost, trimmed) ||
				strings.EqualFold(gw.TransportServerName, trimmed) ||
				(endpointWithPort != "" && strings.EqualFold(endpointWithPort, trimmed)) {
				return gw, nil
			}
		}
		return nil, fault.New(fault.CodeInvalidInput, fmt.Sprintf("gateway %q not found in available gateways", strings.TrimSpace(selector)), nil)
	}
	if len(gateways) == 1 {
		return &gateways[0], nil
	}

	// Multiple gateways available without explicit --gateway
	defaultIdx := preferredGatewayIndex(gateways)

	stdinFile, ok := stdin.(*os.File)
	if !ok || !isTerminal(stdinFile) {
		var ids []string
		for _, gw := range gateways {
			ids = append(ids, fmt.Sprintf("%s (%s)", gw.GatewayID, gw.EndpointHost))
		}
		return nil, fault.New(fault.CodeInvalidInput, fmt.Sprintf("multiple gateways available; pass --gateway (%s)", strings.Join(ids, ", ")), nil)
	}

	fmt.Fprintln(stderr, "Available gateways:")
	for i, gw := range gateways {
		host := gw.EndpointHost
		if host == "" {
			host = gw.TransportServerName
		}
		fmt.Fprintf(stderr, "  [%d] %s (%s, %s)\n", i+1, gw.GatewayID, host, gw.NetworkID)
	}
	fmt.Fprintf(stderr, "Select gateway [%d]: ", defaultIdx+1)
	line, err := readLine(stdin)
	if err != nil {
		return nil, err
	}
	choice := strings.TrimSpace(line)
	if choice == "" {
		return &gateways[defaultIdx], nil
	}
	idx, convErr := strconv.Atoi(choice)
	if convErr != nil || idx < 1 || idx > len(gateways) {
		return nil, fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid gateway selection %q", choice), convErr)
	}
	return &gateways[idx-1], nil
}

func runUpWithDependencies(ctx context.Context, args []string, stdout, stderr io.Writer, httpClient *http.Client, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	defaultStateDir, primaryStateDir, fallbackReason := resolveDefaultStateDirectory()
	flags := flag.NewFlagSet("xconnect up", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDir, "local XConnect-One state directory")
	gatewayTarget := flags.String("gateway", "", "gateway ID, endpoint host, or URL to connect to (e.g. "+defaultKnownGateway+")")
	deviceID := flags.String("device-id", defaultDeviceID(), "stable local device ID")
	deviceName := flags.String("name", "", "device display name")
	bootstrapRuntime := flags.Bool("bootstrap", false, "install or repair the approved managed runtime before starting")
	runtimeReleaseBaseURL := flags.String("runtime-release-base-url", os.Getenv("XCONNECT_RUNTIME_RELEASE_BASE_URL"), "approved Xray release mirror base URL")
	watch := flags.Bool("watch", false, "keep running and synchronize periodically")
	interval := flags.Duration("interval", time.Minute, "watch sync interval")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse up arguments", err)
	}
	if flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse up arguments", nil)
	}
	explicitFlags := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})
	*stateDirectory = expandUserPath(*stateDirectory)
	if !explicitFlags["state-dir"] && fallbackReason != "" {
		fmt.Fprintf(stderr, "Note: default state directory %q is %s; using %q (or pass --state-dir)\n", primaryStateDir, fallbackReason, *stateDirectory)
	}
	if err := credential.EnsureWritableStateDir(*stateDirectory); err != nil {
		return err
	}
	if *watch {
		if err := usecase.ValidateSyncInterval(*interval); err != nil {
			return err
		}
	}

	credentials := newCredentials(*stateDirectory)
	record, credErr := credentials.Load(ctx)
	explicitGateway := strings.TrimSpace(*gatewayTarget)

	needEnroll := explicitGateway != "" || errors.Is(credErr, credential.ErrNotFound)
	if credErr != nil && !errors.Is(credErr, credential.ErrNotFound) {
		return credErr
	}

	if needEnroll {
		session, sessErr := credential.LoadUserSession(*stateDirectory)
		if errors.Is(sessErr, credential.ErrNotFound) || sessErr != nil {
			if sessErr != nil && fault.Code(sessErr) == fault.CodeCredentialStorage {
				return sessErr
			}
			if explicitGateway == "" && errors.Is(credErr, credential.ErrNotFound) {
				// Preserve strict anti-downgrade contract when neither device credential nor login session exists.
				result, upErr := usecase.Up(ctx, state.NewStore(*stateDirectory), newRuntime(*stateDirectory))
				if upErr != nil {
					return upErr
				}
				return writeJSON(stdout, result)
			}
			return fault.New(fault.CodeAuthenticationFailed, "please login first using 'xconnect-one login'", sessErr)
		}
		if explicitGateway != "" || errors.Is(credErr, credential.ErrNotFound) {
			enrolled, enrollErr := resolveAndEnrollGateway(ctx, session, *stateDirectory, *deviceID, *deviceName, explicitGateway, stderr, httpClient, newCredentials)
			if enrollErr != nil {
				return enrollErr
			}
			record = enrolled.Credential
		}
	}

	if *bootstrapRuntime {
		if _, err := overlayruntime.Bootstrap(ctx, overlayruntime.BootstrapOptions{
			StateDirectory:        *stateDirectory,
			ReleaseBaseURL:        *runtimeReleaseBaseURL,
			InstallSystemPackages: true,
		}); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "xconnect: managed runtime ready")
	}

	client, err := controlplane.New(record.Controller, "", httpClient)
	if err != nil {
		return err
	}
	runtimeInstance := newRuntime(*stateDirectory)
	manager := usecase.NewDeviceSessionManager(client, state.NewStore(*stateDirectory), credentials, runtimeInstance).WithSignedConfigV2()
	if *watch {
		if firstResult, err := manager.Sync(ctx); err != nil {
			if fault.Code(err) == fault.CodeAuthenticationFailed || fault.Code(err) == fault.CodeAccessDenied || fault.Code(err) == fault.CodeCredentialExpired || fault.Code(err) == fault.CodeCredentialMissing || fault.Code(err) == fault.CodeNotJoined {
				return err
			}
			_, _ = fmt.Fprintf(stderr, "xconnect: initial sync warning: %v\n", err)
		} else {
			_ = writeJSON(stdout, firstResult)
		}
		loop := &usecase.SyncLoop{
			Interval: *interval,
			Runtime:  runtimeInstance,
			Sync:     manager.Sync,
			OnResult: func(res usecase.SyncResult) {
				_ = writeJSON(stdout, res)
			},
			OnError: func(err error) {
				_, _ = fmt.Fprintf(stderr, "xconnect: sync warning: %v\n", err)
			},
		}
		return loop.Run(ctx)
	}
	result, err := manager.Sync(ctx)
	if err != nil {
		if fault.Code(err) == fault.CodeRuntimePermission {
			_, _ = fmt.Fprintf(stderr, "xconnect: root/administrator privileges required to configure network interface.\n")
			_, _ = fmt.Fprintf(stderr, "Run: sudo xconnect-one up --state-dir %s\n", *stateDirectory)
		}
		return err
	}
	return writeJSON(stdout, result)
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	return isTerminalFD(int(file.Fd()))
}

func ensureWireGuardKeyPair(stStore *state.Store) (string, string, error) {
	if lk, err := stStore.LoadLastKnown(); err == nil && lk.WireGuardPrivateKey != "" && lk.WireGuardPublicKey != "" {
		return lk.WireGuardPrivateKey, lk.WireGuardPublicKey, nil
	}
	return usecase.GenerateWireGuardKeyPair()
}

func readLine(r io.Reader) (string, error) {
	if _, ok := r.(*os.File); ok {
		var buf []byte
		b := make([]byte, 1)
		for {
			n, err := r.Read(b)
			if n > 0 {
				if b[0] == '\n' {
					break
				}
				buf = append(buf, b[0])
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return "", err
			}
		}
		return strings.TrimRight(string(buf), "\r\n"), nil
	}
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readPassword(r io.Reader, stderr io.Writer, showPassword bool) (string, error) {
	if !showPassword {
		if file, ok := r.(*os.File); ok && isTerminal(file) {
			raw, err := readTerminalPassword(int(file.Fd()))
			if stderr != nil {
				_, _ = fmt.Fprintln(stderr)
			}
			if err != nil {
				return "", err
			}
			return strings.TrimRight(string(raw), "\r\n"), nil
		}
	}
	return readLine(r)
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
