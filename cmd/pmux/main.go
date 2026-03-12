package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/proxy"
	"github.com/shiftinbits/pmux-agent/internal/service"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

var version = "dev"
var hmacSecret string

// loadEffectiveConfig loads the config from disk with env overrides.
// Returns a usable config even if the config file doesn't exist.
func loadEffectiveConfig() config.Config {
	paths, err := config.DefaultPaths()
	if err != nil {
		return config.Defaults()
	}
	cfg, err := config.LoadConfig(paths.ConfigFile)
	if err != nil {
		return config.Defaults()
	}
	return cfg
}

// initSecretStore creates a SecretStore using the config's secret_backend setting.
// Uses the keys directory for the encrypted file fallback.
func initSecretStore(paths config.Paths, cfg config.Config) (auth.SecretStore, error) {
	return auth.NewSecretStore(paths.KeysDir, cfg.Identity.SecretBackend, slog.Default())
}

func main() {
	args := os.Args[1:]

	// Load effective config for socket name and other settings
	cfg := loadEffectiveConfig()
	socketName := cfg.Tmux.SocketName

	// No args: default to new session (or attach if server running)
	if len(args) == 0 {
		ensureAgent(cfg)
		if err := proxy.ExecTmux(socketName, cfg.Tmux.TmuxPath); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Intercept PocketMux-only commands
	switch args[0] {
	case "init":
		handleInit()
		return
	case "pair":
		handlePair()
		return
	case "config":
		handleConfig()
		return
	case "status":
		handleStatus()
		return
	case "unpair":
		handleUnpair()
		return
	case "uninstall":
		handleUninstall(args[1:])
		return
	case "agent":
		handleAgent(args[1:])
		return
	case "--version", "-v":
		fmt.Printf("pmux version %s\n", version)
		return
	case "--help", "-h":
		printHelp()
		return
	}

	// Everything else: ensure agent is running, then passthrough to tmux -L <socket>
	ensureAgent(cfg)
	if err := proxy.ExecTmux(socketName, cfg.Tmux.TmuxPath, args...); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

// ensureAgent starts the background agent if it's not already running.
func ensureAgent(cfg config.Config) {
	paths, err := config.DefaultPaths()
	if err != nil {
		return // Non-fatal: agent is optional if not initialized
	}

	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: agent not started (secret store unavailable: %v)\n", err)
		return
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.EnsureRunning(paths, store, mgr); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to start agent: %v\n", err)
	}
}

// runAgent runs the background WebRTC agent process.
// cpuProfile and memProfile are optional file paths for runtime/pprof output.
func runAgent(cpuProfile, memProfile string) {
	paths, err := config.DefaultPaths()
	if err != nil {
		os.Exit(1)
	}

	// Start CPU profiling if requested
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ could not create CPU profile: %v\n", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			fmt.Fprintf(os.Stderr, "⚠ could not start CPU profile: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			pprof.StopCPUProfile()
			f.Close()
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Handle SIGTERM and SIGINT for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	agentErr := agent.Run(ctx, paths, hmacSecret)

	// Write memory profile on shutdown if requested
	if memProfile != "" {
		f, err := os.Create(memProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ could not create memory profile: %v\n", err)
		} else {
			runtime.GC() // Get up-to-date heap statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "⚠ could not write memory profile: %v\n", err)
			}
			f.Close()
		}
	}

	if agentErr != nil && !errors.Is(agentErr, context.Canceled) {
		// Fatal initialization errors should not trigger service restart.
		// These won't self-resolve, so exit 0 to prevent restart loops.
		if agent.IsFatalInitError(agentErr) {
			fmt.Fprintf(os.Stderr, "fatal: %v\n", agentErr)
			agent.RemovePIDFile(agent.PIDFilePath(paths))
			os.Exit(0)
		}
		// HMAC rejection means this binary doesn't match the server's
		// expected client credentials. Won't self-resolve on restart.
		var hmacErr *auth.HMACRejectedError
		if errors.As(agentErr, &hmacErr) {
			fmt.Fprintf(os.Stderr, "fatal: %v\n", agentErr)
			agent.RemovePIDFile(agent.PIDFilePath(paths))
			os.Exit(0)
		}
		// Runtime errors: exit 1 so service manager restarts us.
		os.Exit(1)
	}
}

func handleInit() {
	// tmux is a hard prerequisite — check before doing anything else.
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ tmux is not installed or not found in PATH.\n")
		fmt.Fprintf(os.Stderr, "  tmux is a prerequisite for pmux. Install it first:\n")
		fmt.Fprintf(os.Stderr, "    macOS:  brew install tmux\n")
		fmt.Fprintf(os.Stderr, "    Ubuntu: sudo apt install tmux\n")
		fmt.Fprintf(os.Stderr, "    Fedora: sudo dnf install tmux\n")
		os.Exit(1)
	}

	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	// Ensure directories exist before creating secret store
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	// Load config (may not exist yet, defaults are fine)
	cfg, _ := config.LoadConfig(paths.ConfigFile)

	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	// Check if identity already exists
	if auth.HasIdentity(paths.KeysDir, store) {
		id, err := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ failed to load existing identity: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Identity already exists.\n")
		fmt.Printf("Device ID: %s\n", id.DeviceID)
		if cfg.Name != "" {
			fmt.Printf("Host name: %s\n", cfg.Name)
		}
		return
	}

	id, err := auth.GenerateIdentity(paths.KeysDir, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to generate identity: %v\n", err)
		os.Exit(1)
	}

	// Prompt for host name (default: OS hostname)
	defaultName := config.DefaultHostName()
	fmt.Printf("Host name [%s]: ", defaultName)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		input = defaultName
	}

	// Write config: start with name, then commented defaults with tmux path injected
	tmuxSection := "# socket_name = \"pmux\""
	if tmuxPath != "" {
		tmuxSection += fmt.Sprintf("\ntmux_path = %q", tmuxPath)
	}
	template := strings.Replace(config.CommentedDefaultConfig(),
		"# socket_name = \"pmux\"", tmuxSection, 1)
	configContent := fmt.Sprintf("name = %q\n\n%s", input, template)
	if err := os.WriteFile(paths.ConfigFile, []byte(configContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nIdentity generated.\n")
	fmt.Printf("Device ID: %s\n", id.DeviceID)
	fmt.Printf("Host name: %s\n", input)
	fmt.Printf("Keys saved to: %s (backend: %s)\n", paths.KeysDir, store.Backend())

	// Install agent as OS service
	exe, exeErr := os.Executable()
	if exeErr == nil {
		mgr := service.NewManager(exe, paths.ConfigDir)
		if err := mgr.Install(); err != nil {
			fmt.Printf("\n⚠ Could not install service: %v\n", err)
			fmt.Println("  The agent will still start automatically when you run pmux commands.")
			fmt.Println("  Run 'pmux agent install' later to enable always-on mode.")
		} else {
			fmt.Println("\nService installed. Agent is running.")
		}
	}
}

func handleConfig() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	cfg, sources, err := config.LoadConfigWithSources(paths.ConfigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to load config: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(config.FormatEffective(cfg, sources))
}

func handlePair() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	// Load config to get server URL, host name, and secret backend
	cfg, _ := config.LoadConfig(paths.ConfigFile)

	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	// Must have identity first
	if !auth.HasIdentity(paths.KeysDir, store) {
		fmt.Fprintf(os.Stderr, "⚠ no identity found. Run 'pmux init' first.\n")
		os.Exit(1)
	}

	id, err := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to load identity: %v\n", err)
		os.Exit(1)
	}

	// Check for existing pairing
	pairedDevicesPath := filepath.Join(paths.ConfigDir, "paired_devices.json")
	existingDevice, err := auth.LoadPairedDevice(pairedDevicesPath, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load paired devices: %v\n", err)
		os.Exit(1)
	}

	if existingDevice != nil {
		name := existingDevice.Name
		if name == "" {
			name = existingDevice.DeviceID[:12] + "..."
		}
		pairedDate := existingDevice.PairedAt.Format("2006-01-02")
		fmt.Printf("A device is already paired: %s (paired %s). Replace it? [y/N] ", name, pairedDate)

		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Pairing cancelled.")
			return
		}

		if err := auth.RemovePairedDevice(pairedDevicesPath, existingDevice.DeviceID, store); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove paired device: %v\n", err)
			os.Exit(1)
		}
	}

	serverURL := cfg.ServerURL()

	// Warn if using unencrypted HTTP for non-local server
	if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "ws://") {
		host := strings.TrimPrefix(strings.TrimPrefix(serverURL, "http://"), "ws://")
		host = strings.Split(host, "/")[0] // strip path
		host = strings.Split(host, ":")[0] // strip port
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			fmt.Fprintf(os.Stderr, "WARNING: Server URL %q uses unencrypted HTTP.\n", serverURL)
			fmt.Fprintf(os.Stderr, "  Pairing data (public keys, device IDs) will be sent in cleartext.\n")
			fmt.Fprintf(os.Stderr, "  Use https:// for production servers.\n\n")
		}
	}

	// Generate X25519 ephemeral keypair for key exchange
	x25519kp, err := auth.GenerateX25519Keypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to generate X25519 keypair: %v\n", err)
		os.Exit(1)
	}

	hostName := cfg.Name
	if hostName == "" {
		hostName = config.DefaultHostName()
	}

	// Initiate pairing with signaling server
	fmt.Println("Contacting signaling server...")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	pairResp, err := auth.InitiatePairing(id, x25519kp.PublicKeyBase64(), serverURL, httpClient, hostName, hmacSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initiate pairing: %v\n", err)
		os.Exit(1)
	}

	// Build and display QR code
	qrData, err := auth.BuildQRPayload(
		pairResp.PairingCode,
		x25519kp.PublicKeyBase64(),
		id.DeviceID,
		serverURL,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to build QR payload: %v\n", err)
		os.Exit(1)
	}

	qr, err := qrcode.New(qrData, qrcode.Low)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to generate QR code: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nScan this QR code with PocketMux on your mobile device:")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("Manual pairing code: %s\n\n", pairResp.PairingCode)
	fmt.Println("Waiting for mobile device to complete pairing...")

	// Stop the background agent if running. During pairing, the pair CLI
	// opens its own WebSocket to receive pair_complete. A competing agent
	// WebSocket for the same device ID can intercept the message after DO
	// hibernation, causing the pair CLI to hang. Stopping the agent ensures
	// only one WebSocket exists for this device during pairing.
	if err := agent.StopRunning(paths); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to stop agent for pairing: %v\n", err)
	}

	// Get JWT for WebSocket auth
	jwt, err := auth.ExchangeToken(id, serverURL, httpClient, hmacSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to authenticate: %v\n", err)
		os.Exit(1)
	}

	// Wait for mobile to complete pairing via WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	pairComplete, err := auth.WaitForPairComplete(ctx, serverURL, jwt, hmacSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ pairing failed: %v\n", err)
		os.Exit(1)
	}

	// Compute shared secret via X25519 key exchange
	sharedSecret, err := x25519kp.ComputeSharedSecret(pairComplete.MobileX25519PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ key exchange failed: %v\n", err)
		os.Exit(1)
	}

	// Store paired device
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	mobileName := auth.TruncateMobileName(pairComplete.MobileName)
	err = auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     pairComplete.MobileDeviceID,
		Name:         mobileName,
		SharedSecret: sharedSecret,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to save paired device: %v\n", err)
		os.Exit(1)
	}

	displayName := mobileName
	if displayName == "" {
		displayName = pairComplete.MobileDeviceID
	}
	fmt.Printf("Paired successfully with device '%s'\n", displayName)

	// Restart the background agent (stopped earlier to avoid WebSocket race).
	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)
	if err := agent.EnsureRunning(paths, store, mgr); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to restart agent: %v\n", err)
	}
}

func handleUnpair() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	cfg, _ := config.LoadConfig(paths.ConfigFile)
	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	if err := agent.RunUnpair(paths, store, hmacSecret, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleUninstall(args []string) {
	// Parse flags
	keepConfig := false
	skipConfirm := false
	for _, arg := range args {
		switch arg {
		case "--keep-config":
			keepConfig = true
		case "--yes", "-y":
			skipConfirm = true
		}
	}

	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	// Don't fail if dirs don't exist — they might already be gone
	_ = paths.EnsureDirs()

	cfg, _ := config.LoadConfig(paths.ConfigFile)
	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunUninstall(paths, store, mgr, keepConfig, hmacSecret, skipConfirm, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleStatus() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	cfg, _ := config.LoadConfig(paths.ConfigFile)
	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)
	tmuxClient := tmux.NewClient(cfg.Tmux.SocketName)
	if cfg.Tmux.TmuxPath != "" {
		tmuxClient.TmuxBin = cfg.Tmux.TmuxPath
	}

	params := agent.StatusParams{
		Version:           version,
		PairedDevicesPath: paths.PairedDevices,
		Store:             store,
		PIDFilePath:       agent.PIDFilePath(paths),
		ServiceManager:    mgr,
		Sessions:          tmuxClient,
	}

	if err := agent.RunStatus(params, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

// handleAgent routes "pmux agent <subcommand>" to the appropriate handler.
func handleAgent(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: pmux agent <command>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  run        Run the agent in the foreground")
		fmt.Fprintln(os.Stderr, "  start      Start the agent")
		fmt.Fprintln(os.Stderr, "  stop       Stop the agent")
		fmt.Fprintln(os.Stderr, "  status     Show agent status")
		fmt.Fprintln(os.Stderr, "  install    Install as OS service (launchd/systemd)")
		fmt.Fprintln(os.Stderr, "  uninstall  Remove OS service registration")
		os.Exit(1)
	}

	switch args[0] {
	case "run":
		// "run" is an internal subcommand used by the supervisor to start the agent process.
		// Supports optional --cpuprofile <file> and --memprofile <file> flags.
		var cpuProfile, memProfile string
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--cpuprofile":
				if i+1 < len(args) {
					cpuProfile = args[i+1]
					i++
				}
			case "--memprofile":
				if i+1 < len(args) {
					memProfile = args[i+1]
					i++
				}
			}
		}
		runAgent(cpuProfile, memProfile)
	case "start":
		handleAgentStart()
	case "stop":
		handleAgentStop()
	case "status":
		handleAgentStatus()
	case "install":
		handleAgentInstall()
	case "uninstall":
		handleAgentUninstall()
	default:
		fmt.Fprintf(os.Stderr, "Unknown agent command: %s\n", args[0])
		os.Exit(1)
	}
}

func handleAgentStatus() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunAgentDetail(version, paths, mgr, os.Stdout); err != nil {
		if errors.Is(err, agent.ErrAgentNotRunning) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleAgentStop() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunAgentStop(paths, mgr, os.Stdout); err != nil {
		if errors.Is(err, agent.ErrAgentNotRunning) {
			fmt.Println("Agent is not running")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleAgentStart() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	cfg := loadEffectiveConfig()
	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunAgentStart(paths, store, mgr, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleAgentInstall() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ could not resolve binary path: %v\n", err)
		os.Exit(1)
	}

	mgr := service.NewManager(exe, paths.ConfigDir)
	if err := mgr.Install(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to install service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service installed. Agent is running.")
}

func handleAgentUninstall() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)
	if err := mgr.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to uninstall service: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service uninstalled.")
}


func printHelp() {
	fmt.Println(`pmux — PocketMux terminal access agent

PocketMux commands:
  init              Generate identity and configure agent
  pair              Pair with a mobile device (displays QR code)
  config            Show effective configuration with sources
  status            Show agent, service, and pairing status
  unpair            Remove the paired mobile device
  uninstall [-y]    Remove PocketMux completely (reverses 'init')
  agent run         Run the agent in the foreground
  agent start       Start the agent
  agent stop        Stop the agent
  agent status      Show agent status and recent logs
  agent install     Install as OS service (auto-start on login)
  agent uninstall   Remove OS service registration
  --version         Show version
  --help            Show this help

All other commands are passed through to tmux -L pmux.
Run 'pmux' with no args to start a new session.

Examples:
  pmux                          Start new tmux session
  pmux new-session -s work      Named session
  pmux attach -t work           Attach to session
  pmux ls                       List sessions
  pmux kill-server              Stop tmux server`)
}
