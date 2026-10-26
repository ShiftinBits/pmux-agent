# CLAUDE.md — pmux-agent

Go agent binary for Pocketmux. `pmux` is a transparent tmux wrapper that proxies all commands to `tmux -L pmux` while running a background WebRTC agent for mobile access.

## Quick Reference

| Task | Command |
|------|---------|
| Build | `make build` — sets `main.version=dev`, `main.installMethod=dev`, `main.hmacSecret=$PMUX_HMAC_SECRET` |
| Build (release-like) | `make build-obfuscated` (needs `garble`) |
| Unit tests | `make test` (tmux-dependent tests skip if tmux absent) |
| Integration tests | `make test-integration` (tag `integration`, `-race`, needs tmux) |
| Stress tests | `make test-stress` (tag `stress`, `-race`, several minutes) |
| All tests | `make test-all` |
| Vet (only static check; no golangci config) | `go vet ./...` |
| Release snapshot | `make snapshot` |

CI (`.github/workflows/`): `build.yml` = vet + build; `test.yml` = unit tests + coverage on ubuntu (no `-race`, no integration/stress). Go `1.25.13`.

## Architecture

| Package | Purpose |
|---------|---------|
| `cmd/pmux/main.go` | CLI routing, ldflag vars (`version`, `hmacSecret`, `installMethod`), `runAgent()` exit-code handling |
| `internal/agent/` | `Run()` (agent main loop), `EnsureRunning()`/`spawn()` (supervisor.go), `Handler` (DataChannel request handling), tmux monitor, PID file, keep-awake, sleep watcher (Linux logind, macOS IOKit via purego), `pmux init/pair/status/unpair/uninstall` impls |
| `internal/auth/` | Ed25519 identity, JWT exchange, X25519 pairing, `SecretStore` (keyring/file), build HMAC request signing (hmac.go), server pairing session (pair_session.go) |
| `internal/config/` | TOML config + env overrides, `DefaultPaths()` |
| `internal/firewall/` | Detect-only host firewall probe (macOS `socketfilterfw`, Linux ufw/firewalld); never modifies settings |
| `internal/protocol/` | MessagePack codec, message types (mirror `@pocketmux/shared`), `Validate()` limits, per-peer deflate (`OutputCompressor`) |
| `internal/proxy/` | `ExecTmux()` — `syscall.Exec` into `tmux -L <socket>` |
| `internal/tmux/` | `Client` (tmux CLI wrapper), `PaneBridge` (pipe-pane → FIFO streaming), `PaneSizeTracker`, `TitleFilter` |
| `internal/update/` | GitHub Releases checker, banner, install-method `Detect()`, per-method `Updater` |
| `internal/webrtc/` | Pion `PeerManager` (peer.go), `SignalingClient` (signaling.go) |

### Commands

Intercepted in `main()`: `init`, `pair`, `config`, `status`, `unpair`, `uninstall [--keep-config] [-y]`, `update`, `agent`, `--version/-v`, `--help/-h`. `agent` subcommands: `start`, `stop`, `restart`, `status`, and internal `run` (what `spawn()` execs). Everything else (and no args) → `ensureAgent()` then `proxy.ExecTmux()`.

**There is no OS service layer** (no launchd/systemd install). The agent is spawned by `EnsureRunning()` on any `pmux` command: `flock` on `agent.pid` → if the PID is the agent (alive and its argv is `pmux agent run`, `IsAgentProcess`) send SIGUSR1; otherwise the pid file is treated as stale and a new `pmux agent run` is spawned with `Setsid`. On macOS a launchd-spawned agent is faceless and never auto-allowed by the Application Firewall, forcing TURN relay.

### Signals (agent process)

| Signal | Effect |
|--------|--------|
| SIGUSR1 | Activity ping from CLI — wakes signaling from dormancy (`SignalActivity()`) |
| SIGUSR2 | Reload pairing state, close all peers, then reopen the `PeerManager` for new connections (`CloseAllAndReopen`; sent by `pmux pair`) |
| SIGTERM/SIGINT | Graceful stop (10s cap; `CloseAll` leaves the `PeerManager` closed); second signal → `os.Exit(1)` |

Both closes run `OnPeerDisconnect` for each peer before its Pion `Close` (which can block 30s+), so pane teardown (window-size restore, pipe release) finishes within the shutdown cap. Before each peer's `OnPeerDisconnect` the peer stops dispatching DataChannel requests to the handler (waiting out one in flight, after releasing its backpressured output send), so an attach arriving mid-teardown cannot rebuild state. Every peer teardown takes this path, including the `ConnectionCleaner` sweep (`PeerManager.DisconnectPeer`). While closed, `handleConnectRequest` drops connect requests (no `connection_rejected`); the mobile retries after the server's `peer_unavailable`. The reload reopens once the disconnect handlers finish, without waiting for the old peers' Pion `Close` or for Pion closes already running in the background (failed-peer cleanup, a replaced peer), so a re-paired phone is not held off by an unreachable old one. Shutdown (`CloseAll`) still waits for those closes, within the 10s cap.

### Files (`~/.config/pmux/`, hardcoded via `os.UserHomeDir`, not XDG)

`config.toml`, `keys/` (0700; relocatable via `identity.key_path`), `paired_devices.json`, `agent.pid`, `agent.log` (rotated at 10 MiB → `agent.log.1`), `update-state.json`.

Always get paths via `resolvePaths()` in `main.go` (`DefaultPaths()` + `Paths.WithKeyPath()`), never bare `config.DefaultPaths()` — that ignores `key_path`.

## Configuration

Load order: `Defaults()` → file → env (`LoadConfig`). Booleans from env: `true`/`1`/`yes`, anything else = false. `Config.Validate()` is advisory: it warns in `agent.log` and `pmux config` but never rejects the config (falling back to defaults could silently switch the tmux socket).

| Env Variable | Override |
|-------------|---------|
| `PMUX_SERVER_URL` | Signaling server (default `https://signal.pmux.io`); wins over legacy `PMUX_AGENT_SIGNAL_URL` |
| `PMUX_API_VERSION` | URL prefix (default `v1`); explicitly set `""` = legacy unversioned paths (uses `LookupEnv`) |
| `PMUX_SOCKET_NAME` | tmux socket (default `pmux`) |
| `PMUX_TMUX_PATH` | Absolute tmux path |
| `PMUX_KEY_PATH` | Keys dir; `~` expands, relative resolves against config dir. Only meaningful before `pmux init` — changing it later orphans the identity (re-init + re-pair). `init` preserves a pre-existing `config.toml` |
| `PMUX_SECRET_BACKEND` | `auto` (default), `keyring`, `file` |
| `PMUX_MAX_CONNECTIONS` | → `PeerManager.MaxPeers` (default 1) |
| `PMUX_LOG_LEVEL` | `debug`/`info`/`warn`/`error` |
| `PMUX_UPDATE_ENABLED` / `PMUX_UPDATE_INTERVAL` | Background update check (default on, `24h`) |
| `PMUX_FORCE_RELAY` | Relay-only (TURN) ICE, for debugging |
| `PMUX_KEEP_AWAKE` | Inhibit host sleep (macOS `caffeinate -i -w`, Linux logind inhibitor, WSL powershell) |

`PMUX_HMAC_SECRET` is **build-time only** (Makefile/goreleaser ldflag), not read at runtime.

**Adding a config field/env var** touches: `Config` + `fileConfig` (pointer fields distinguish absent vs false), `applyEnvOverrides` **and** `applyEnvOverridesTracked` (duplicated), `ConfigSources`/`FormatEffective`, `CommentedDefaultConfig()`.

## Key Design Decisions

- **PTY streaming**: `tmux pipe-pane` → FIFO (not `creack/pty`). `AttachPane` runs `pipe-pane` without `-o`, so it replaces any existing pipe on the pane (a user's own pipe-pane is replaced; `-o` would toggle it off instead). The `Client` records which bridge owns each pane's pipe: a newer attach makes the older bridge's `Read` return `ErrBridgeDisplaced`, and `Close` disables the pipe only if it still owns it. macOS FIFO `Read()` doesn't unblock on `Close()`, so `relayFIFOToPipe` waits on a non-blocking fd with `poll(2)` (wakes on data, rechecks shutdown every 50ms) and copies into an `os.Pipe`. Input goes through `load-buffer` (bytes on stdin) + `paste-buffer -d -r` (`internal/tmux/tmux.go`), not `send-keys`, so typed input (including passwords) never appears in process arguments or `ps`. Backpressure: `Peer.SendMessageContext` waits on a >512KB DataChannel buffer (5s timeout, or until the stream's ctx is canceled or the peer's teardown stops its dispatch, so neither a detach nor a teardown waits it out) only for `output`; control messages send immediately (still SCTP-ordered behind buffered output) and are refused above a 1MB hard ceiling. When an output send fails or the bridge is displaced, `streamOutput` detaches the peer and sends `error` code `stream_reset` so the mobile can re-attach (needs mobile handling; the mobile currently only logs it). It is skipped when a detach or re-attach is already waiting on that stream.
- **Two auth layers — don't confuse**: (1) build HMAC (`auth.SignRequest`) proves an official build to the server; empty secret = no headers, server 401s. (2) DataChannel mutual key-possession handshake (auth v2) using the per-device X25519 shared secret: agent sends `auth_challenge` (host nonce) → mobile replies `auth_response` {`mac`, `nonce`} → agent verifies it (`sendAuthChallenge`/`verifyAuthResponse`) and replies `auth_confirm`. Both MACs are `authMAC` = HMAC-SHA256(secret, label || T) with T = hostNonce || mobileNonce || hostCertFp || mobileCertFp and direction labels `pocketmux-auth-v2 mobile->host` / `pocketmux-auth-v2 host->mobile`; the cert fingerprints are sha-256 digests read from the live Pion DTLS transport (`pcDTLSFingerprints`), never from SDP. `SendMessage` refuses everything but the handshake messages until `authConfirmed`, so `auth_confirm` is the first message after the handshake. A shared secret that can't be loaded rejects the connect with `connection_rejected` reason `secret_unavailable`. Before auth only `auth_response` is accepted; `protocol.IsRequest` excludes it afterward.
- **Exit codes**: `FatalInitError` and `*auth.HMACRejectedError` exit **0** (no point restarting); other runtime errors exit 1.
- **Fail-closed pairing**: unpaired/load-error states set allowed device ID to `"!"`-prefixed sentinels.
- **Single-pairing**: enforced at runtime by `PeerManager.MaxPeers` (default 1) + `SetAllowedDeviceID`. Re-pairing replaces the old device with confirmation.
- **Wire limits** in `protocol/validation.go` must match `@pocketmux/shared` `src/codec.ts`. `TestCrossLanguageFixtures` reads `packages/shared/src/__tests__/fixtures` (skips if shared isn't cloned alongside).
- **Compression**: one stateful raw-deflate stream per peer (window persists across messages); negotiated via `AttachRequest.Compression == "deflate"`; each output stream owns its compressor. A compression error, or a failed send of compressed output (including the pre-stream initial content), ends the stream and sends `stream_reset` so the mobile can re-attach (needs mobile handling).
- **Signaling** (`signaling.go`): reconnect backoff with jitter (×1–1.5, intentionally not capped), reset only after a connection stays up for `stableConnectionThreshold` (30s); `DormancyTimeout` 5m stops retrying until SIGUSR1. Presence interval capped at 45s (server reaper is 90s). `Suspend`/`Resume` driven by Linux logind `PrepareForSleep` and by macOS IOKit `IORegisterForSystemPower` (purego, no cgo). The kernel hides DarkWakes from `IORegisterForSystemPower` clients, so macOS needs no wake debounce. SIGUSR1 never clears a suspension; only the watcher's `Resume` does.
- **ICE recovery** (`peer.go`): `disconnectTimers` (10s grace, rescheduled if fired early after sleep) → `attemptICERestart` → separate `iceRestartTimers` 20s watchdog closes the peer if not Connected.
- **TURN**: `fetchTurnCredentials` (JWT + HMAC), cached 10m, falls back to STUN-only on failure.
- **Updates**: `update.Detect()` order: ldflag `dev` → `/snap/` → `/Caskroom/`, `/Cellar/` or `/opt/homebrew/` → `dpkg -s` → `rpm -q` → github. Only the github method self-replaces (`minio/selfupdate`, SHA256-verified, host allow-list); homebrew runs `brew upgrade`; deb/rpm/snap install nothing and return `*ErrElevationRequired{Command}` — `pmux update` prints the command and leaves update state untouched. The CLI banner and mobile `SessionsEvent.UpdateAvailable` are gated on `State.IsStale(runningVersion)`, so state written by an older binary is ignored. Release builds leave `installMethod` empty. `Checker.Check` no-ops when version is `dev`.
- **Firewall warning** shown in agent log, `pmux status`, `pmux init`. macOS 15+ always reports low-confidence "not authorized" when the firewall is on (`--listapps` is unreliable there).
- **zsh**: `Run()` sets tmux global env `PROMPT_EOL_MARK=""` so the `%` marker doesn't appear on mobile.

## Testing

- **tmux is not mocked**: tests run real tmux on isolated sockets (`pmux-test`, `pmux-handler-test`, `pmux-integ-*`, `pmux-stress-*`), `skipIfNoTmux`, `kill-server` in `t.Cleanup`. Use a new unique socket name for new tests.
- **Test seams are package-level func vars** (`firewall.execCommand`, `firewall.osMajor`, `update.executablePath`, `proxy.sysExec`, `agent.runAgentStop/Start`) — swapped in tests, so no `t.Parallel()` (repo uses none).
- **Subprocess fakes**: `firewall/exec_test.go` `TestHelperProcess` re-exec pattern (`GO_WANT_HELPER_PROCESS`).
- **Paths**: tests build `config.Paths{}` from `t.TempDir()`; no `HOME` override. Secrets via `auth.NewMemorySecretStore()`.
- ⚠ `secretstore_detect_test.go` / `ProbeKeyring` touch the **real OS keyring**.
- ⚠ Running a built `pmux` with a fake `HOME` (e.g. `HOME=$tmp pmux init`): **always also set `PMUX_SECRET_BACKEND=file`**. On macOS the keyring probe shells out to `security add-generic-password`, which can't find a default keychain under a fake `HOME` (`errSecNoDefaultKeychain`) and pops a blocking "Keychain Not Found … `__probe__`" GUI dialog on the user's desktop for every invocation.
- Platform code split by filename suffix (`_darwin.go`, `_linux.go`) plus `_other.go` with `!darwin && !linux` / `!linux` tags.

## Release Pipeline

`.goreleaser.yaml` (tag `v*` → `release.yml`): linux amd64/arm64 + darwin universal, `CGO_ENABLED=0`, built through `scripts/garble.sh`. Darwin stays `CGO_ENABLED=0` because IOKit is reached through purego.
- **garble** obfuscates literals to protect the embedded HMAC secret. `GOGARBLE` is limited to this module — obfuscating godbus/go-keyring breaks D-Bus type assertions and panics on Linux.
- Archive names must match `githubUpdater.matchArchiveName` or self-update breaks.
- `checksums.txt` GPG-signed; macOS sign/notarize gated on `MACOS_SIGN_P12`.
- Homebrew cask → `ShiftinBits/homebrew-tap` (`uninstall_preflight_steps` pkills `pmux agent run`).
- DEB/RPM via nFPM (depends on tmux). No Snap publishing configured; no Windows target.
