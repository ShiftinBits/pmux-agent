package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"

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

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunInit(paths, cfg, store, mgr, tmuxPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
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

	cfg, _ := config.LoadConfig(paths.ConfigFile)

	store, err := initSecretStore(paths, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to initialize secret store: %v\n", err)
		os.Exit(1)
	}

	exe, _ := os.Executable()
	mgr := service.NewManager(exe, paths.ConfigDir)

	if err := agent.RunPair(paths, cfg, store, mgr, hmacSecret, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
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
