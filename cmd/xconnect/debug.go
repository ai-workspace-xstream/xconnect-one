package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ai-workspace-xstream/XConnect-One/overlay/credential"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/fault"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/state"
	"github.com/ai-workspace-xstream/XConnect-One/overlay/usecase"
)

type debugSystemInfo struct {
	Version        string `json:"version"`
	BuildNumber    string `json:"build_number,omitempty"`
	GitCommit      string `json:"git_commit,omitempty"`
	Platform       string `json:"platform"`
	Architecture   string `json:"architecture"`
	EffectiveUID   int    `json:"effective_uid"`
	Privileged     bool   `json:"privileged"`
	RuntimeMode    string `json:"runtime_mode"`
	StateDirectory string `json:"state_directory"`
	SystemDeviceID string `json:"system_device_id,omitempty"`
}

type debugDaemonInfo struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid,omitempty"`
	LogFile string `json:"log_file"`
	LogTail string `json:"log_tail,omitempty"`
}

type debugSessionInfo struct {
	LoggedIn  bool      `json:"logged_in"`
	Expired   bool      `json:"expired,omitempty"`
	Server    string    `json:"server,omitempty"`
	Email     string    `json:"email,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type debugIssue struct {
	Code           string `json:"code"`
	Summary        string `json:"summary"`
	Recommendation string `json:"recommendation"`
}

type debugReport struct {
	GeneratedAt time.Time                  `json:"generated_at"`
	System      debugSystemInfo            `json:"system"`
	Daemon      debugDaemonInfo            `json:"daemon"`
	Session     debugSessionInfo           `json:"session"`
	Status      usecase.StatusResult       `json:"status"`
	Diagnostics []usecase.DiagnosticResult `json:"diagnostics"`
	Issues      []debugIssue               `json:"issues,omitempty"`
	AgentPrompt string                     `json:"agent_prompt"`
}

func runDebug(ctx context.Context, args []string, stdout, stderr io.Writer, newRuntime runtimeFactory, newCredentials credentialFactory) error {
	defaultStateDir, _, _ := resolveDefaultStateDirectory()
	flags := flag.NewFlagSet("xconnect debug", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDirectory := flags.String("state-dir", defaultStateDir, "local XConnect-One state directory")
	format := flags.String("format", "markdown", "output format: markdown, prompt, or json")
	asJSON := flags.Bool("json", false, "output debug bundle as JSON (shorthand for --format=json)")
	onlyPrompt := flags.Bool("prompt", false, "output only the AI Agent debug prompt (shorthand for --format=prompt)")
	tailLines := flags.Int("tail", 20, "number of recent daemon log lines to include")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fault.New(fault.CodeInvalidInput, "parse debug arguments", err)
	}
	if flags.NArg() != 0 {
		return fault.New(fault.CodeInvalidInput, "parse debug arguments", nil)
	}

	selectedFormat := strings.ToLower(strings.TrimSpace(*format))
	if *asJSON {
		selectedFormat = "json"
	} else if *onlyPrompt {
		selectedFormat = "prompt"
	}
	switch selectedFormat {
	case "markdown", "md", "text", "prompt", "json":
	default:
		return fault.New(fault.CodeInvalidInput, fmt.Sprintf("invalid --format %q (expected markdown, prompt, or json)", *format), nil)
	}

	*stateDirectory = expandUserPath(*stateDirectory)
	report, err := collectDebugReport(ctx, *stateDirectory, *tailLines, newRuntime, newCredentials)
	if err != nil {
		return err
	}

	switch selectedFormat {
	case "json":
		return writeJSON(stdout, report)
	case "prompt":
		_, err := fmt.Fprintln(stdout, report.AgentPrompt)
		return err
	default:
		_, err := fmt.Fprint(stdout, renderDebugMarkdown(report))
		return err
	}
}

func collectDebugReport(ctx context.Context, stateDir string, tailLines int, newRuntime runtimeFactory, newCredentials credentialFactory) (debugReport, error) {
	now := time.Now().UTC()
	store := state.NewStore(stateDir)
	rt := newRuntime(stateDir)
	creds := newCredentials(stateDir)

	statusRes, statusErr := usecase.StatusWithCredential(ctx, store, rt, creds)
	if statusErr != nil && !errors.Is(statusErr, state.ErrNotFound) {
		// Record partial status when possible so debug never hides actionable root causes.
		statusRes = usecase.StatusResult{}
	}
	diags, diagErr := usecase.DiagnoseWithCredential(ctx, store, rt, creds)
	if diagErr != nil {
		diags = nil
	}

	runtimeMode := strings.ToLower(strings.TrimSpace(os.Getenv("XCONNECT_ONE_RUNTIME")))
	if runtimeMode == "" {
		if statusRes.Runtime.RuntimeVersion != "" {
			runtimeMode = statusRes.Runtime.RuntimeVersion
		} else {
			runtimeMode = "embedded"
		}
	}

	privileged := isProcessPrivileged()
	for _, d := range diags {
		if d.Code == "runtime_privileged" && d.Healthy {
			privileged = true
		}
	}

	logPath := defaultDaemonLogPath(stateDir)
	daemonPID := statusRes.Runtime.DaemonPID
	daemonAlive := false
	if pid, err := readDaemonPID(stateDir); err == nil && pid > 0 {
		daemonPID = pid
		daemonAlive = isDaemonProcessAlive(pid)
	} else if daemonPID > 0 {
		daemonAlive = isDaemonProcessAlive(daemonPID)
	}
	logTail := ""
	if tailLines > 0 {
		logTail = readLogTail(logPath, tailLines, daemonLogTailBytes)
	}

	sessInfo := inspectLoginSession(stateDir, now)
	sysInfo := debugSystemInfo{
		Version:        version,
		BuildNumber:    buildNumber,
		GitCommit:      gitCommit,
		Platform:       runtime.GOOS,
		Architecture:   runtime.GOARCH,
		EffectiveUID:   effectiveProcessUID(),
		Privileged:     privileged,
		RuntimeMode:    runtimeMode,
		StateDirectory: stateDir,
		SystemDeviceID: loadSystemDeviceID(),
	}
	daemonInfo := debugDaemonInfo{
		Running: daemonAlive || statusRes.Runtime.Applied,
		PID:     daemonPID,
		LogFile: logPath,
		LogTail: logTail,
	}

	issues := analyzeDebugIssues(sysInfo, daemonInfo, sessInfo, statusRes, diags, statusErr, diagErr)
	report := debugReport{
		GeneratedAt: now,
		System:      sysInfo,
		Daemon:      daemonInfo,
		Session:     sessInfo,
		Status:      statusRes,
		Diagnostics: diags,
		Issues:      issues,
	}
	report.AgentPrompt = buildAgentDebugPrompt(report)
	return report, nil
}

func inspectLoginSession(stateDir string, now time.Time) debugSessionInfo {
	sess, err := credential.LoadUserSession(stateDir)
	if err != nil {
		return debugSessionInfo{LoggedIn: false}
	}
	expired := !sess.ExpiresAt.IsZero() && !now.Before(sess.ExpiresAt)
	return debugSessionInfo{
		LoggedIn:  !expired,
		Expired:   expired,
		Server:    sess.Server,
		Email:     sess.Email,
		UserID:    sess.UserID,
		ExpiresAt: sess.ExpiresAt,
	}
}

func windowsAdminSuffix() string {
	if runtime.GOOS == "windows" {
		return " (Run as Administrator)"
	}
	return ""
}

func analyzeDebugIssues(
	sys debugSystemInfo,
	daemon debugDaemonInfo,
	sess debugSessionInfo,
	status usecase.StatusResult,
	diags []usecase.DiagnosticResult,
	statusErr, diagErr error,
) []debugIssue {
	var issues []debugIssue
	if statusErr != nil {
		rec := fmt.Sprintf("Check file ownership/permissions on %s (e.g. sudo chown -R $(id -un):$(id -gn) %s).", sys.StateDirectory, sys.StateDirectory)
		if runtime.GOOS == "windows" {
			rec = fmt.Sprintf("Verify file permissions on %s (ensure current user has full read/write access).", sys.StateDirectory)
		}
		issues = append(issues, debugIssue{
			Code:           fault.Code(statusErr),
			Summary:        fmt.Sprintf("Failed to read overlay status: %s", formatFaultError(statusErr)),
			Recommendation: rec,
		})
	}
	if diagErr != nil {
		issues = append(issues, debugIssue{
			Code:           fault.Code(diagErr),
			Summary:        fmt.Sprintf("Failed to run diagnostics: %s", formatFaultError(diagErr)),
			Recommendation: "Verify state directory permissions and device credential storage.",
		})
	}
	if !status.Credential.Present {
		issues = append(issues, debugIssue{
			Code:           "device_not_enrolled",
			Summary:        "Device credential is missing; this node has not joined an overlay network yet.",
			Recommendation: "Run 'xconnect-one login' followed by 'xconnect-one join --gateway https://ph-xconnect-gateway-01.svc.plus'.",
		})
	} else if status.Credential.Expired {
		issues = append(issues, debugIssue{
			Code:           "device_credential_expired",
			Summary:        "Stored device credential has expired.",
			Recommendation: "Re-enroll the device with 'xconnect-one join' (or 'xconnect-one login' if login session expired).",
		})
	}
	embeddedManifestBlocked := false
	if !status.Runtime.Applied {
		manifestPath := filepath.Join(sys.StateDirectory, "runtime", "embedded-active.json")
		if _, lstatErr := os.Lstat(manifestPath); lstatErr == nil {
			if _, readErr := os.ReadFile(manifestPath); errors.Is(readErr, os.ErrPermission) {
				embeddedManifestBlocked = true
				elevatedCmd := fmt.Sprintf("%sxconnect-one --state-dir %s status%s", platformElevatedCmdPrefix(), sys.StateDirectory, windowsAdminSuffix())
				issues = append(issues, debugIssue{
					Code:           "embedded_manifest_permission_denied",
					Summary:        fmt.Sprintf("%s exists on disk but is unreadable by uid %d (typically held by an older service writing 0600).", manifestPath, sys.EffectiveUID),
					Recommendation: fmt.Sprintf("Run '%s' to inspect, or update/restart the service so embedded-active.json uses readable permissions.", elevatedCmd),
				})
			}
		}
	}
	if status.Credential.Present && !status.Runtime.Applied && !embeddedManifestBlocked {
		issues = append(issues, debugIssue{
			Code:           "tunnel_not_running",
			Summary:        "Device is enrolled, but the overlay tunnel runtime is not currently active.",
			Recommendation: fmt.Sprintf("Start the background embedded daemon with: %sxconnect-one up -D --state-dir %s%s", platformElevatedCmdPrefix(), sys.StateDirectory, windowsAdminSuffix()),
		})
	}
	if status.Generations.PolicyExpired && status.Generations.State > 0 {
		issues = append(issues, debugIssue{
			Code:           "policy_expired",
			Summary:        fmt.Sprintf("Local policy generation %d is marked expired.", status.Generations.Policy),
			Recommendation: fmt.Sprintf("Refresh signed config and policy with: %sxconnect-one up -D --state-dir %s%s", platformElevatedCmdPrefix(), sys.StateDirectory, windowsAdminSuffix()),
		})
	}
	for _, d := range diags {
		if d.Healthy {
			continue
		}
		if d.Code == "runtime_privileged" && status.Runtime.Applied {
			// Running debug as non-root while the root daemon is already applied is normal.
			continue
		}
		issues = append(issues, debugIssue{
			Code:           d.Code,
			Summary:        explainDiagnosticFailure(d.Code),
			Recommendation: recommendDiagnosticFix(d.Code, sys.StateDirectory),
		})
	}
	return issues
}

func explainDiagnosticFailure(code string) string {
	switch code {
	case "last_known_state_present":
		return "No last-known state.json found in the state directory."
	case "state_file_permissions_0600":
		return "state.json does not have strict 0600 permissions."
	case "runtime_privileged":
		return "Current process lacks root/CAP_NET_ADMIN privileges required to mutate TUN interfaces."
	case "runtime_revision":
		return "Overlay tunnel runtime has no active applied config revision."
	case "device_credential_present":
		return "No device credential found in protected storage."
	case "device_credential_not_expired":
		return "Device credential is missing or expired."
	case "policy_generation":
		return "Signed policy state is missing or expired."
	default:
		return fmt.Sprintf("Diagnostic check %q reported unhealthy.", code)
	}
}

func recommendDiagnosticFix(code, stateDir string) string {
	switch code {
	case "last_known_state_present", "device_credential_present", "device_credential_not_expired":
		return "Run 'xconnect-one login' and 'xconnect-one join' to enroll this device."
	case "state_file_permissions_0600":
		if runtime.GOOS == "windows" {
			return fmt.Sprintf("Ensure private permissions on %s\\state.json (read/write restricted to current user/Administrators).", stateDir)
		}
		return fmt.Sprintf("Fix permissions with: chmod 0600 %s/state.json", stateDir)
	case "runtime_privileged", "runtime_revision", "policy_generation":
		return fmt.Sprintf("Start or refresh the tunnel daemon with: %sxconnect-one up -D --state-dir %s%s", platformElevatedCmdPrefix(), stateDir, windowsAdminSuffix())
	default:
		return fmt.Sprintf("Inspect logs at %s and re-run '%sxconnect-one up -D --state-dir %s%s'.", defaultDaemonLogPath(stateDir), platformElevatedCmdPrefix(), stateDir, windowsAdminSuffix())
	}
}

func valueOrNA(v string) string {
	if strings.TrimSpace(v) == "" {
		return "N/A"
	}
	return strings.TrimSpace(v)
}

func renderDebugMarkdown(r debugReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# XConnect-One Debug & Diagnostic Report\n\n")
	fmt.Fprintf(&b, "- **Generated At**: `%s`\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **CLI Version**: `xconnect-one %s (build %s, %s/%s)`\n", r.System.Version, r.System.BuildNumber, r.System.Platform, r.System.Architecture)
	fmt.Fprintf(&b, "- **Runtime Mode**: `%s` (Managed: `%v`, Core: `%s/%s`)\n", r.System.RuntimeMode, r.Status.Runtime.ManagedRuntime, valueOrNA(r.Status.Runtime.CoreID), valueOrNA(r.Status.Runtime.AdapterID))
	fmt.Fprintf(&b, "- **State Directory**: `%s` (euid=%d, privileged=%v)\n", r.System.StateDirectory, r.System.EffectiveUID, r.System.Privileged)
	if r.System.SystemDeviceID != "" {
		fmt.Fprintf(&b, "- **Global Device ID (`%s`)**: `%s`\n", resolveSystemDeviceIDPath(), r.System.SystemDeviceID)
	}
	fmt.Fprintf(&b, "- **Daemon Status**: running=`%v`, pid=`%d`, log=`%s`\n\n", r.Daemon.Running, r.Daemon.PID, r.Daemon.LogFile)

	fmt.Fprintf(&b, "## 1. Overlay Network & IP Topology\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Joined & Active | `%v` (Runtime Applied: `%v`) |\n", r.Status.Joined, r.Status.Runtime.Applied)
	fmt.Fprintf(&b, "| Device ID | `%s` |\n", valueOrNA(r.Status.DeviceID))
	fmt.Fprintf(&b, "| Network ID | `%s` |\n", valueOrNA(r.Status.NetworkID))
	fmt.Fprintf(&b, "| Overlay IP / CIDR | `%s` (IP: `%s`) |\n", valueOrNA(r.Status.Address), valueOrNA(r.Status.OverlayIP))
	fmt.Fprintf(&b, "| TUN Interface | `%s` (MTU: `%d`) |\n", valueOrNA(r.Status.Interface), r.Status.MTU)
	allowed := "N/A"
	if len(r.Status.AllowedIPs) > 0 {
		allowed = strings.Join(r.Status.AllowedIPs, ", ")
	}
	fmt.Fprintf(&b, "| Allowed IPs (Routes) | `%s` |\n", allowed)
	fmt.Fprintf(&b, "| Config Revision | `%s` (State Gen: `%d`, Policy Gen: `%d`, Policy Expired: `%v`) |\n",
		valueOrNA(r.Status.Revision), r.Status.Generations.State, r.Status.Generations.Policy, r.Status.Generations.PolicyExpired)
	fmt.Fprintf(&b, "| Controller | `%s` |\n\n", valueOrNA(r.Status.Controller))

	fmt.Fprintf(&b, "## 2. Gateway & Transport\n\n")
	if gw := r.Status.Gateway; gw != nil {
		fmt.Fprintf(&b, "| Field | Value |\n|---|---|\n")
		fmt.Fprintf(&b, "| Gateway ID | `%s` |\n", valueOrNA(gw.ID))
		fmt.Fprintf(&b, "| Gateway Overlay IP | `%s` |\n", valueOrNA(gw.OverlayIP))
		fmt.Fprintf(&b, "| Gateway Public Endpoint | `%s` (SNI: `%s`) |\n", valueOrNA(gw.Endpoint), valueOrNA(gw.ServerName))
		fmt.Fprintf(&b, "| Transport Protocol | `%s` (mode=`%s`, path=`%s`) |\n", valueOrNA(gw.Transport), valueOrNA(gw.TransportMode), valueOrNA(gw.TransportPath))
		fmt.Fprintf(&b, "| Local Xray Loopback | `%s` |\n", valueOrNA(gw.LocalProxyEndpoint))
		fmt.Fprintf(&b, "| Gateway WireGuard PubKey | `%s` |\n\n", valueOrNA(gw.WireGuardPublicKey))
	} else {
		fmt.Fprintf(&b, "_No gateway configuration present in local state._\n\n")
	}

	fmt.Fprintf(&b, "## 3. Credentials & Session (Secrets Redacted)\n\n")
	fmt.Fprintf(&b, "- **User Login Session**: logged_in=`%v`, email=`%s`, server=`%s`, expires_at=`%s`\n",
		r.Session.LoggedIn, valueOrNA(r.Session.Email), valueOrNA(r.Session.Server), formatTimeOrNA(r.Session.ExpiresAt))
	fmt.Fprintf(&b, "- **Device Credential**: present=`%v`, backend=`%s`, id=`%s`, expired=`%v`, expires_at=`%s`\n\n",
		r.Status.Credential.Present, valueOrNA(r.Status.Credential.Backend), valueOrNA(r.Status.Credential.CredentialID),
		r.Status.Credential.Expired, formatTimeOrNA(r.Status.Credential.ExpiresAt))

	fmt.Fprintf(&b, "## 4. Health Diagnostics\n\n")
	if len(r.Diagnostics) == 0 {
		fmt.Fprintf(&b, "_No diagnostic items available._\n\n")
	} else {
		for _, d := range r.Diagnostics {
			mark := "PASS"
			if !d.Healthy {
				mark = "WARN"
			}
			extra := ""
			if d.Generation > 0 {
				extra = fmt.Sprintf(" (generation=%d)", d.Generation)
			} else if d.Revision != "" {
				extra = fmt.Sprintf(" (revision=%s)", d.Revision)
			}
			fmt.Fprintf(&b, "- `[%s]` `%s`%s\n", mark, d.Code, extra)
		}
		fmt.Fprintln(&b)
	}

	if len(r.Issues) > 0 {
		fmt.Fprintf(&b, "## 5. Detected Issues & Recommended Actions\n\n")
		for i, issue := range r.Issues {
			fmt.Fprintf(&b, "%d. **`%s`**: %s\n   - **Fix**: `%s`\n", i+1, issue.Code, issue.Summary, issue.Recommendation)
		}
		fmt.Fprintln(&b)
	}

	if strings.TrimSpace(r.Daemon.LogTail) != "" {
		fmt.Fprintf(&b, "## 6. Recent Daemon Log (`%s`)\n\n```text\n%s\n```\n\n", r.Daemon.LogFile, r.Daemon.LogTail)
	}

	fmt.Fprintf(&b, "## 7. AI Agent Debug Prompt (Copy & Paste)\n\n```markdown\n%s\n```\n", r.AgentPrompt)
	return b.String()
}

func buildAgentDebugPrompt(r debugReport) string {
	var b strings.Builder
	gwIP := "10.66.0.1"
	gwEndpoint := "N/A"
	gwID := "N/A"
	transportInfo := "vless-xhttp"
	localLoopback := "127.0.0.1:51830"
	if gw := r.Status.Gateway; gw != nil {
		if gw.OverlayIP != "" {
			gwIP = gw.OverlayIP
		}
		if gw.Endpoint != "" {
			gwEndpoint = gw.Endpoint
		}
		if gw.ID != "" {
			gwID = gw.ID
		}
		if gw.Transport != "" {
			transportInfo = fmt.Sprintf("%s (mode=%s, path=%s, sni=%s)", gw.Transport, valueOrNA(gw.TransportMode), valueOrNA(gw.TransportPath), valueOrNA(gw.ServerName))
		}
		if gw.LocalProxyEndpoint != "" {
			localLoopback = gw.LocalProxyEndpoint
		}
	}
	allowed := "N/A"
	if len(r.Status.AllowedIPs) > 0 {
		allowed = strings.Join(r.Status.AllowedIPs, ", ")
	}

	fmt.Fprintf(&b, "请协助排查并验证当前节点的 XConnect-One 内嵌 Overlay 隧道工作状态：\n\n")
	fmt.Fprintf(&b, "### 节点与网络上下文\n")
	fmt.Fprintf(&b, "- 版本与平台: xconnect-one %s (build %s, %s/%s), runtime=%s\n", r.System.Version, r.System.BuildNumber, r.System.Platform, r.System.Architecture, r.System.RuntimeMode)
	fmt.Fprintf(&b, "- 状态目录: %s (euid=%d, daemon_pid=%d, daemon_running=%v)\n", r.System.StateDirectory, r.System.EffectiveUID, r.Daemon.PID, r.Daemon.Running)
	fmt.Fprintf(&b, "- 设备标识: device_id=%s (global=%s: %s)\n", valueOrNA(r.Status.DeviceID), resolveSystemDeviceIDPath(), valueOrNA(r.System.SystemDeviceID))
	fmt.Fprintf(&b, "- 虚拟网络: network_id=%s, joined=%v, runtime_applied=%v\n", valueOrNA(r.Status.NetworkID), r.Status.Joined, r.Status.Runtime.Applied)
	fmt.Fprintf(&b, "- 本机 Overlay IP: %s (网卡=%s, MTU=%d, 路由 AllowedIPs=%s)\n", valueOrNA(r.Status.Address), valueOrNA(r.Status.Interface), r.Status.MTU, allowed)
	fmt.Fprintf(&b, "- 网关信息: gateway_id=%s, gateway_overlay_ip=%s, endpoint=%s\n", gwID, gwIP, gwEndpoint)
	fmt.Fprintf(&b, "- 传输通道: %s, 本地回环=%s\n", transportInfo, localLoopback)
	fmt.Fprintf(&b, "- 策略版本: revision=%s, state_gen=%d, policy_gen=%d, policy_expired=%v\n",
		valueOrNA(r.Status.Revision), r.Status.Generations.State, r.Status.Generations.Policy, r.Status.Generations.PolicyExpired)
	fmt.Fprintf(&b, "- 凭据状态: login_session=%v (%s), device_credential_present=%v (id=%s, expired=%v)\n",
		r.Session.LoggedIn, valueOrNA(r.Session.Email), r.Status.Credential.Present, valueOrNA(r.Status.Credential.CredentialID), r.Status.Credential.Expired)

	if len(r.Issues) > 0 {
		fmt.Fprintf(&b, "\n### 已检测到的异常项\n")
		for _, issue := range r.Issues {
			fmt.Fprintf(&b, "- [%s] %s\n  建议操作: %s\n", issue.Code, issue.Summary, issue.Recommendation)
		}
	} else {
		fmt.Fprintf(&b, "\n### 诊断结论\n- 本地所有核心健康检查均已通过（joined=true, applied=true）。\n")
	}

	if strings.TrimSpace(r.Daemon.LogTail) != "" {
		fmt.Fprintf(&b, "\n### 最近守护进程日志 (%s)\n```text\n%s\n```\n", r.Daemon.LogFile, r.Daemon.LogTail)
	}

	fmt.Fprintf(&b, "\n### 常用排查与验证命令\n")
	fmt.Fprintf(&b, "1. 查看状态与网关/IP: `xconnect-one status --state-dir %s`\n", r.System.StateDirectory)
	fmt.Fprintf(&b, "2. 完整诊断与提示词: `xconnect-one debug --state-dir %s`\n", r.System.StateDirectory)
	fmt.Fprintf(&b, "3. 启动/重启后台内嵌隧道: `%sxconnect-one up -D --state-dir %s%s`\n", platformElevatedCmdPrefix(), r.System.StateDirectory, windowsAdminSuffix())
	fmt.Fprintf(&b, "4. 验证网关 Overlay 连通性: `%s`\n", platformPingCmdString(4, gwIP))
	return strings.TrimSpace(b.String())
}

func formatTimeOrNA(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.UTC().Format(time.RFC3339)
}
