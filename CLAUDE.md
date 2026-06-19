# CLAUDE.md — pmux-agent

Go agent binary for Pocketmux. `pmux` is a transparent tmux wrapper that proxies all commands to `tmux -L pmux` while running a background WebRTC agent for mobile access.

## Quick Reference

| Task | Command |
|------|---------|
| Build | `make build` (or `go build -o bin/pmux ./cmd/pmux`) |
| Unit tests | `make test` |
| Integration tests | `make test-integration` (requires tmux) |
| Stress tests | `make test-stress` (requires tmux, several minutes) |
| All tests | `make test-all` |
| Release snapshot | `make snapshot` (goreleaser dry-run) |
| Clean | `make clean` |

## Architecture

| Package | Purpose |
|---------|---------|
| `cmd/pmux/main.go` | CLI entry point, command routing, `handlePair()`, `handleAgent()` |
| `internal/agent/` | Agent lifecycle — `Run()`, `EnsureRunning()`, `Handler`, `Supervisor`, `ConnectionCleaner`, tmux monitor, PID file management |
| `internal/auth/` | Ed25519 identity, JWT signing, X25519 pairing, secret store (keyring/file backends), `PairedDevice` storage |
| `internal/config/` | TOML config parsing (`~/.config/pmux/config.toml`), env overrides, path resolution |
| `internal/protocol/` | MessagePack codec, message types (mirrors `@pocketmux/shared`) |
| `internal/proxy/` | tmux passthrough via `syscall.Exec` |
| `internal/tmux/` | tmux CLI wrapper (`Client`), `PaneBridge` (FIFO-based PTY streaming), `PaneSizeTracker`, `TitleFilter` |
| `internal/webrtc/` | Pion WebRTC `PeerManager`, `SignalingClient`, dormancy handling |

## Key Design Decisions

- **Command routing**: `init`, `pair`, `config`, `status`, `unpair`, `agent`, `--version` are intercepted; everything else passes through to `tmux -L pmux`
- **PTY streaming**: Uses FIFO + non-blocking relay pipe (not `creack/pty`). macOS FIFO `Read()` doesn't unblock on `Close()` — the relay goroutine polls with short timeouts and checks a done channel
- **Agent lifecycle**: Persistent background process, spawned by `EnsureRunning()` on any `pmux` command (idempotent via flock + PID file). No OS service layer — on macOS a launchd-spawned agent is a faceless process the Application Firewall never auto-allows, forcing TURN relay; foreground spawn by `pmux` in the GUI session gets direct P2P. Fatal init errors exit 0; runtime errors exit 1
- **Secret storage**: Auto-detects backend — OS keyring (`go-keyring`) preferred, falls back to encrypted file. Configurable via `identity.secret_backend` or `PMUX_SECRET_BACKEND`
- **Single-pairing model**: One mobile per host. Re-pairing replaces old device with confirmation prompt

## Configuration

Config file: `~/.config/pmux/config.toml`

| Env Variable | Override |
|-------------|---------|
| `PMUX_SERVER_URL` | Signaling server URL (default: `https://signal.pmux.io`) |
| `PMUX_SOCKET_NAME` | tmux socket name (default: `pmux`) |
| `PMUX_TMUX_PATH` | Absolute path to tmux binary |
| `PMUX_KEY_PATH` | Key storage directory |
| `PMUX_SECRET_BACKEND` | `keyring` or `file` |
| `PMUX_MAX_CONNECTIONS` | Max concurrent WebRTC connections |
| `PMUX_LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error` (default: `info`) |
| `PMUX_KEEP_AWAKE` | Inhibit host sleep while the agent runs (default: `false`) |

## Dependencies

| Module | Purpose |
|--------|---------|
| `pion/webrtc/v4` | WebRTC DataChannels |
| `pion/ice/v4` | ICE transport |
| `vmihailenco/msgpack/v5` | Wire protocol codec |
| `gorilla/websocket` | Signaling WebSocket client |
| `skip2/go-qrcode` | QR code for pairing |
| `pelletier/go-toml/v2` | Config file parsing |
| `zalando/go-keyring` | OS keychain/keyring access |
| `golang.org/x/crypto` | Ed25519 signing, X25519 key exchange |

## Testing

- Unit tests: co-located `*_test.go` files in each package
- Integration tests: `test/integration/` — build tag `//go:build integration`, uses isolated tmux sockets (`pmux-integ-*`)
- Stress tests: `test/stress/` — build tag `//go:build stress`, sockets `pmux-stress-*`
- Integration/stress tests require tmux installed and use `-race` flag

## Release Pipeline

`.goreleaser.yaml` — builds linux (amd64, arm64) + darwin universal binary. Supports:
- macOS code signing/notarization (env-gated)
- Homebrew cask publishing to `ShiftinBits/homebrew-tap` (env-gated)
- DEB and RPM packages via nFPM (tmux as dependency)
- Snap package publishing to the Snap Store (classic confinement, core24 base, `SNAPCRAFT_STORE_CREDENTIALS` env-gated)
