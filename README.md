# pmux — Pocketmux Agent

[![Current Release](https://img.shields.io/github/v/release/shiftinbits/pmux-agent)](https://github.com/ShiftinBits/pmux-agent/releases) [![Test Results](https://img.shields.io/github/actions/workflow/status/shiftinbits/pmux-agent/test.yml?branch=main&logo=go&logoColor=white&label=tests)](https://github.com/shiftinbits/pmux-agent/actions/workflows/test.yml?query=branch%3Amain) [![Code Coverage](https://img.shields.io/codecov/c/github/shiftinbits/pmux-agent?logo=codecov&logoColor=white)](https://app.codecov.io/gh/shiftinbits/pmux-agent/) [![CodeQL Results](https://github.com/ShiftinBits/pmux-agent/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/ShiftinBits/pmux-agent/actions/workflows/github-code-scanning/codeql) [![Snyk Security Monitored](https://img.shields.io/badge/security-monitored-8A2BE2?logo=snyk)](https://snyk.io/test/github/shiftinbits/pmux-agent) [![License](https://img.shields.io/badge/license-MIT-3DA639?logo=opensourceinitiative&logoColor=white)](LICENSE)

`pmux` is a transparent drop-in replacement for `tmux` that makes your terminal sessions accessible from your phone. Replace `tmux` with `pmux` in your workflow — every command works identically, but sessions are automatically accessible from the [Pocketmux](https://pmux.io) mobile app over an encrypted peer-to-peer connection.

```bash
pmux new-session -s work      # just like tmux, but now accessible from your phone
pmux attach -t work
pmux ls
```

## Highlights

- **Drop-in tmux replacement** — all tmux commands pass through unchanged via a dedicated socket (`-L pmux`)
- **Peer-to-peer encrypted** — terminal data flows directly between host and phone over WebRTC DataChannels; the signaling server never sees your content
- **Zero-knowledge architecture** — the server only relays connection metadata, never terminal data or session information
- **Ed25519 identity** — no passwords, no accounts; cryptographic keypair generated locally at setup
- **QR code pairing** — scan once from the mobile app to establish a secure link
- **OS service integration** — runs as a launchd (macOS) or systemd (Linux) service with automatic restart
- **Cross-platform** — macOS (universal binary) and Linux (amd64, arm64)

## Install

```bash
# Homebrew
brew install shiftinbits/tap/pmux
```

Pre-built binaries and DEB/RPM/Snap packages are available on [GitHub Releases](https://github.com/ShiftinBits/pmux-agent/releases).

## Getting Started

```bash
pmux init     # generate identity, install service
pmux pair     # scan the QR code with the Pocketmux app
pmux          # start a session — it's now on your phone
```

## Documentation

Full documentation is available at **[docs.pmux.io](https://docs.pmux.io)**:

- [Installation](https://docs.pmux.io/getting-started/installation) — platform-specific setup instructions
- [Initialization](https://docs.pmux.io/getting-started/initialization) — first-time setup walkthrough
- [Pairing](https://docs.pmux.io/getting-started/pairing) — connecting your mobile device
- [CLI Reference](https://docs.pmux.io/reference/cli) — all commands and options
- [Configuration](https://docs.pmux.io/reference/configuration) — config file, environment variables
- [Architecture](https://docs.pmux.io/architecture/design) — how it all works under the hood

## License

MIT — see [LICENSE](./LICENSE)
