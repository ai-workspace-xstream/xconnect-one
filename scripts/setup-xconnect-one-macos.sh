#!/usr/bin/env bash
set -euo pipefail
umask 077

# Install the enrolled CLI as a root LaunchDaemon. No credentials are printed.
[[ $(uname -s) == Darwin ]] || { echo 'macOS is required' >&2; exit 1; }
operator="${XCONNECT_ONE_OPERATOR:-${SUDO_USER:-$(id -un)}}"
operator_uid="$(id -u "$operator")"
operator_gid="$(id -g "$operator")"
operator_home="$(dscl . -read "/Users/$operator" NFSHomeDirectory | sed 's/^NFSHomeDirectory: //')"

if [[ -n ${XCONNECT_ONE_STATE_DIR:-} ]]; then
  state_dir="$XCONNECT_ONE_STATE_DIR"
elif [[ -f $operator_home/.xconnect-one-user/protected/device-credential.json ]] && \
     [[ ! -f $operator_home/.xconnect-one/protected/device-credential.json || "$(stat -f '%u' "$operator_home/.xconnect-one" 2>/dev/null || echo 0)" == "0" ]]; then
  state_dir="$operator_home/.xconnect-one-user"
else
  state_dir="$operator_home/.xconnect-one"
fi

source_binary="${XCONNECT_ONE_BINARY:-$(command -v xconnect-one || command -v xconnect || true)}"
if [[ -z $source_binary && -x /opt/homebrew/bin/xconnect-one ]]; then
  source_binary=/opt/homebrew/bin/xconnect-one
fi
service_binary=/usr/local/libexec/xconnect-one.bin
label=com.xconnect.one
plist=/Library/LaunchDaemons/$label.plist
log_file=/var/log/xconnect-one.log
[[ $(id -u) == 0 ]] || { echo 'Run this setup with sudo.' >&2; exit 1; }
[[ $state_dir == /* && $source_binary == /* && -x $source_binary ]] || { echo 'Set an absolute XCONNECT_ONE_BINARY and XCONNECT_ONE_STATE_DIR.' >&2; exit 1; }
[[ -f $state_dir/state.json ]] || { echo "Enroll the device before enabling the daemon (missing $state_dir/state.json)." >&2; exit 1; }

install -d -m 0755 /usr/local/libexec
backup=$(mktemp -d /usr/local/libexec/xconnect-one-setup.XXXXXX)
[[ ! -f $service_binary ]] || cp -p "$service_binary" "$backup/xconnect-one.bin"
[[ ! -f $plist ]] || cp -p "$plist" "$backup/daemon.plist"
if [[ ! -f $state_dir/protected/device-credential.json ]]; then
  XCONNECT_CREDENTIAL_BACKEND=keychain XCONNECT_KEYCHAIN_PATH="${XCONNECT_KEYCHAIN_PATH:-$operator_home/Library/Keychains/login.keychain-db}" \
    "$source_binary" credential migrate-to-protected --state-dir "$state_dir"
fi
[[ -f $state_dir/protected/device-credential.json ]] || { echo "Missing device credential at $state_dir/protected/device-credential.json; run 'xconnect-one join' first." >&2; exit 1; }

if launchctl print "system/$label" >/dev/null 2>&1; then
  launchctl bootout "system/$label" || true
fi
restore_service() {
  result=$?
  if [[ -f $plist ]] && ! launchctl bootstrap system "$plist"; then
    echo 'LaunchDaemon bootstrap failed; inspect launchctl and preserved backup.' >&2
    result=1
  fi
  exit "$result"
}
trap restore_service EXIT
SUDO_UID="$operator_uid" SUDO_GID="$operator_gid" XCONNECT_CREDENTIAL_BACKEND=file \
  "$source_binary" down --state-dir "$state_dir" >/dev/null 2>&1 || true

install -d -m 0755 /usr/local/libexec
if [[ $source_binary != "$service_binary" ]]; then
  install -o root -g wheel -m 0755 "$source_binary" "$service_binary"
fi
chown root:wheel "$service_binary"
chmod 0755 "$service_binary"

if [[ -f $log_file ]]; then
  log_size="$(stat -f '%z' "$log_file" 2>/dev/null || echo 0)"
  if (( log_size > 5242880 )); then
    cp -f "$log_file" "$log_file.prev" 2>/dev/null || true
    : > "$log_file"
  fi
fi

xml_escape() { printf '%s' "$1" | sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }
state_xml=$(xml_escape "$state_dir")
home_xml=$(xml_escape "$operator_home")
operator_xml=$(xml_escape "$operator")
cat > "$backup/daemon.plist.new" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$label</string>
	<key>ProgramArguments</key>
	<array>
		<string>$service_binary</string>
		<string>up</string>
		<string>--foreground</string>
		<string>--no-sudo</string>
		<string>--interval</string>
		<string>1m</string>
		<string>--state-dir</string>
		<string>$state_xml</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>HOME</key>
		<string>$home_xml</string>
		<key>USER</key>
		<string>$operator_xml</string>
		<key>LOGNAME</key>
		<string>$operator_xml</string>
		<key>SUDO_UID</key>
		<string>$operator_uid</string>
		<key>SUDO_GID</key>
		<string>$operator_gid</string>
		<key>XCONNECT_CREDENTIAL_BACKEND</key>
		<string>file</string>
		<key>PATH</key>
		<string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>$log_file</string>
	<key>StandardErrorPath</key>
	<string>$log_file</string>
</dict>
</plist>
EOF
plutil -lint "$backup/daemon.plist.new"
install -o root -g wheel -m 0644 "$backup/daemon.plist.new" "$plist"
launchctl enable "system/$label"
printf 'One autostart configured using %s (state dir: %s); previous files preserved in %s\n' "$service_binary" "$state_dir" "$backup"
