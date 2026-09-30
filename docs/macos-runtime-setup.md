# macOS enrolled One autostart and runtime recovery

Use a binary built from this revision; older releases may not support protected credential migration or partial-runtime recovery. Enroll first as the login user. Keep Xray and wireguard-go installed (or use the CLI managed runtime bootstrap). From this checkout:

```sh
sudo env XCONNECT_ONE_BINARY=/absolute/path/to/xconnect \
  bash scripts/setup-xconnect-one-macos.sh
```

Optional `XCONNECT_ONE_OPERATOR`, `XCONNECT_ONE_STATE_DIR` and `XCONNECT_KEYCHAIN_PATH` select the enrolled user/state/login Keychain. The default state is the sudo user's `~/.xconnect-one`. Unlock the login Keychain when prompted during initial migration. No credential is printed. A root-owned 0700 directory/0600 file stores the durable device credential; the original Keychain entry is retained. Subsequent setup runs do not overwrite an existing protected credential. Run root maintenance commands with `sudo env XCONNECT_CREDENTIAL_BACKEND=file ...` to use the same backend as the service.

Setup preserves previous binary/plist, stops only the enrolled runtime through validated CLI ownership checks, installs a direct root LaunchDaemon with RunAtLoad/KeepAlive and sync watch, then bootstraps it. It does not delete enrollment or blindly kill Xray processes. Short-lived enrollment expiry retries session renewal; a missing tunnel is rebuilt even if Xray survived. Darwin process identity checks normalize locale/timezone while accepting verifiable legacy tokens. Revoked durable credentials still require operator action.

Verify `sudo launchctl print system/com.xconnect.one`, `sudo wg show`, actual overlay routes and remote TCP/SSH access. Plain `wg` may hide root-owned interfaces, and very fast ping through another VPN is not proof of this tunnel. Test recovery/reboot during a maintenance window; a bootstrap failure is visible in launchctl and `/var/log/xconnect-one.log`. No Vault token, unseal key or topology-specific address belongs in this setup.
