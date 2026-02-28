package main

import (
	"bufio"
	"context"
	"fmt"
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
)

const version = "0.1.0-dev"

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

func main() {
	args := os.Args[1:]

	// Internal: agent background mode (spawned by supervisor)
	// Supports optional --cpuprofile <file> and --memprofile <file> flags.
	if len(args) >= 1 && args[0] == "--agent" {
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
		return
	}

	// Load effective config for socket name and other settings
	cfg := loadEffectiveConfig()
	socketName := cfg.Tmux.SocketName

	// No args: default to new session (or attach if server running)
	if len(args) == 0 {
		ensureAgent()
		if err := proxy.ExecTmux(socketName); err != nil {
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
	case "devices":
		handleDevices()
		return
	case "unpair":
		handleUnpair(args[1:])
		return
	case "host-status":
		handleHostStatus()
		return
	case "host-stop":
		handleHostStop()
		return
	case "--version", "-v":
		fmt.Printf("pmux version %s\n", version)
		return
	case "--help", "-h":
		printHelp()
		return
	}

	// Everything else: ensure agent is running, then passthrough to tmux -L <socket>
	ensureAgent()
	if err := proxy.ExecTmux(socketName, args...); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

// ensureAgent starts the background agent if it's not already running.
func ensureAgent() {
	paths, err := config.DefaultPaths()
	if err != nil {
		return // Non-fatal: agent is optional if not initialized
	}

	if err := agent.EnsureRunning(paths); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to start host: %v\n", err)
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

	agentErr := agent.Run(ctx, paths)

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

	if agentErr != nil && agentErr != context.Canceled {
		os.Exit(1)
	}
}

func handleInit() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	// Check if identity already exists
	if auth.HasIdentity(paths.KeysDir) {
		id, err := auth.LoadIdentity(paths.KeysDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ failed to load existing identity: %v\n", err)
			os.Exit(1)
		}
		cfg, _ := config.LoadConfig(paths.ConfigFile)
		fmt.Printf("Identity already exists.\n")
		fmt.Printf("Device ID: %s\n", id.DeviceID)
		if cfg.Name != "" {
			fmt.Printf("Host name: %s\n", cfg.Name)
		}
		return
	}

	// Create directories and generate identity
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	id, err := auth.GenerateIdentity(paths.KeysDir)
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

	// Write config: start with commented defaults, then prepend the name
	configContent := fmt.Sprintf("name = %q\n\n%s", input, config.CommentedDefaultConfig())
	if err := os.WriteFile(paths.ConfigFile, []byte(configContent), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to save config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nIdentity generated.\n")
	fmt.Printf("Device ID: %s\n", id.DeviceID)
	fmt.Printf("Host name: %s\n", input)
	fmt.Printf("Keys saved to: %s\n", paths.KeysDir)
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

	// Must have identity first
	if !auth.HasIdentity(paths.KeysDir) {
		fmt.Fprintf(os.Stderr, "⚠ no identity found. Run 'pmux init' first.\n")
		os.Exit(1)
	}

	id, err := auth.LoadIdentity(paths.KeysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to load identity: %v\n", err)
		os.Exit(1)
	}

	// Check for existing pairing
	pairedDevicesPath := filepath.Join(paths.ConfigDir, "paired_devices.json")
	existingDevice, err := auth.LoadPairedDevice(pairedDevicesPath)
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

		if err := auth.SavePairedDevices(pairedDevicesPath, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to clear paired devices: %v\n", err)
			os.Exit(1)
		}
	}

	// Load config to get server URL and host name
	cfg, _ := config.LoadConfig(paths.ConfigFile)
	serverURL := cfg.ServerURL()

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
	pairResp, err := auth.InitiatePairing(id, x25519kp.PublicKeyBase64(), serverURL, httpClient, hostName)
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
		fmt.Fprintf(os.Stderr, "warning: failed to stop host for pairing: %v\n", err)
	}

	// Get JWT for WebSocket auth
	jwt, err := auth.ExchangeToken(id, serverURL, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to authenticate: %v\n", err)
		os.Exit(1)
	}

	// Wait for mobile to complete pairing via WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	pairComplete, err := auth.WaitForPairComplete(ctx, serverURL, jwt)
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

	err = auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     pairComplete.MobileDeviceID,
		SharedSecret: sharedSecret,
		PairedAt:     time.Now(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to save paired device: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Paired successfully with device %s\n", pairComplete.MobileDeviceID)
}

func handleUnpair(args []string) {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	if err := agent.RunUnpair(args, paths.PairedDevices, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleDevices() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	if err := agent.RunDevices(paths.PairedDevices, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}
}

func handleHostStatus() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	pidFile := agent.PIDFilePath(paths)

	pid, err := agent.ReadPIDFile(pidFile)
	if err != nil {
		fmt.Println("Host is not running")
		os.Exit(1)
	}

	if !agent.IsProcessRunning(pid) {
		fmt.Println("Host is not running (stale PID file)")
		agent.CleanStalePIDFile(pidFile)
		os.Exit(1)
	}

	fmt.Printf("Host is running (PID %d)\n", pid)

	// Try to get process uptime via ps
	out, err := exec.Command("ps", "-o", "etime=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err == nil {
		uptime := strings.TrimSpace(string(out))
		if uptime != "" {
			fmt.Printf("Uptime: %s\n", uptime)
		}
	}

	// Show last 5 lines of host log
	logFile := filepath.Join(paths.ConfigDir, "host.log")
	lines, err := tailFile(logFile, 5)
	if err == nil && len(lines) > 0 {
		fmt.Println("\nRecent log:")
		for _, line := range lines {
			fmt.Printf("  %s\n", line)
		}
	}
}

func handleHostStop() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ %v\n", err)
		os.Exit(1)
	}

	pidFile := agent.PIDFilePath(paths)

	pid, err := agent.ReadPIDFile(pidFile)
	if err != nil {
		fmt.Println("Host is not running")
		os.Exit(1)
	}

	if !agent.IsProcessRunning(pid) {
		fmt.Println("Host is not running (stale PID file cleaned up)")
		agent.RemovePIDFile(pidFile)
		os.Exit(0)
	}

	// Send SIGTERM for graceful shutdown
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "⚠ failed to send SIGTERM to PID %d: %v\n", pid, err)
		os.Exit(1)
	}

	// Wait up to 5 seconds for process to exit (poll every 200ms)
	const (
		stopTimeout  = 5 * time.Second
		pollInterval = 200 * time.Millisecond
	)

	deadline := time.After(stopTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			// Process didn't exit in time — send SIGKILL
			if err := process.Signal(syscall.SIGKILL); err != nil {
				// Process may have exited between the last check and now
				if !agent.IsProcessRunning(pid) {
					fmt.Println("Host stopped")
					agent.RemovePIDFile(pidFile)
					return
				}
				fmt.Fprintf(os.Stderr, "⚠ failed to send SIGKILL to PID %d: %v\n", pid, err)
				os.Exit(1)
			}
			fmt.Println("Host forcefully killed")
			agent.RemovePIDFile(pidFile)
			return
		case <-ticker.C:
			if !agent.IsProcessRunning(pid) {
				fmt.Println("Host stopped")
				agent.RemovePIDFile(pidFile)
				return
			}
		}
	}
}

// tailFile reads the last n lines from a file.
func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines, scanner.Err()
}

func printHelp() {
	fmt.Println(`pmux — PocketMux terminal access host

PocketMux commands:
  init          Generate identity and register with signaling server
  pair          Pair with a mobile device (displays QR code)
  config        Show effective configuration with sources
  devices       List paired mobile devices
  unpair        Remove a paired mobile device
  host-status   Show host process status and recent logs
  host-stop     Stop the background host process
  --version     Show version
  --help        Show this help

All other commands are passed through to tmux -L pmux.
Run 'pmux' with no args to start a new session.

Examples:
  pmux                          Start new tmux session
  pmux new-session -s work      Named session
  pmux attach -t work           Attach to session
  pmux ls                       List sessions
  pmux kill-server              Stop tmux server + host`)
}
