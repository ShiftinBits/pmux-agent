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
	"strings"
	"syscall"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/proxy"
)

const (
	tmuxSocket = "pmux"
	version    = "0.1.0-dev"
)

func main() {
	args := os.Args[1:]

	// Internal: agent background mode (spawned by supervisor)
	if len(args) == 1 && args[0] == "--agent" {
		runAgent()
		return
	}

	// No args: default to new session (or attach if server running)
	if len(args) == 0 {
		ensureAgent()
		if err := proxy.ExecTmux(tmuxSocket); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
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
	case "devices":
		handleDevices()
		return
	case "unpair":
		handleUnpair(args[1:])
		return
	case "agent-status":
		handleAgentStatus()
		return
	case "agent-stop":
		handleAgentStop()
		return
	case "--version", "-v":
		fmt.Printf("pmux version %s\n", version)
		return
	case "--help", "-h":
		printHelp()
		return
	}

	// Everything else: ensure agent is running, then passthrough to tmux -L pmux
	ensureAgent()
	if err := proxy.ExecTmux(tmuxSocket, args...); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "warning: failed to start agent: %v\n", err)
	}
}

// runAgent runs the background WebRTC agent process.
func runAgent() {
	paths, err := config.DefaultPaths()
	if err != nil {
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Handle SIGTERM and SIGINT for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := agent.Run(ctx, paths); err != nil && err != context.Canceled {
		os.Exit(1)
	}
}

func handleInit() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Check if identity already exists
	if auth.HasIdentity(paths.KeysDir) {
		id, err := auth.LoadIdentity(paths.KeysDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to load existing identity: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Identity already exists.\n")
		fmt.Printf("Device ID: %s\n", id.DeviceID)
		return
	}

	// Create directories and generate identity
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	id, err := auth.GenerateIdentity(paths.KeysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to generate identity: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Identity generated.\n")
	fmt.Printf("Device ID: %s\n", id.DeviceID)
	fmt.Printf("Keys saved to: %s\n", paths.KeysDir)
}

func handlePair() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Must have identity first
	if !auth.HasIdentity(paths.KeysDir) {
		fmt.Fprintf(os.Stderr, "error: no identity found. Run 'pmux init' first.\n")
		os.Exit(1)
	}

	id, err := auth.LoadIdentity(paths.KeysDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load identity: %v\n", err)
		os.Exit(1)
	}

	// TODO: read server URL from config file; fall back to default
	serverURL := config.DefaultServerURL

	// Generate X25519 ephemeral keypair for key exchange
	x25519kp, err := auth.GenerateX25519Keypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to generate X25519 keypair: %v\n", err)
		os.Exit(1)
	}

	// Initiate pairing with signaling server
	fmt.Println("Contacting signaling server...")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	pairResp, err := auth.InitiatePairing(id, x25519kp.PublicKeyBase64(), serverURL, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to initiate pairing: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "error: failed to build QR payload: %v\n", err)
		os.Exit(1)
	}

	qr, err := qrcode.New(qrData, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to generate QR code: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nScan this QR code with PocketMux on your mobile device:")
	fmt.Println()
	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("Manual pairing code: %s\n\n", pairResp.PairingCode)
	fmt.Println("Waiting for mobile device to complete pairing...")

	// Get JWT for WebSocket auth
	jwt, err := auth.ExchangeToken(id, serverURL, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to authenticate: %v\n", err)
		os.Exit(1)
	}

	// Wait for mobile to complete pairing via WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	pairComplete, err := auth.WaitForPairComplete(ctx, serverURL, jwt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: pairing failed: %v\n", err)
		os.Exit(1)
	}

	// Compute shared secret via X25519 key exchange
	sharedSecret, err := x25519kp.ComputeSharedSecret(pairComplete.MobileX25519PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: key exchange failed: %v\n", err)
		os.Exit(1)
	}

	// Store paired device
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	err = auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     pairComplete.MobileDeviceID,
		SharedSecret: sharedSecret,
		PairedAt:     time.Now(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to save paired device: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Paired successfully with device %s\n", pairComplete.MobileDeviceID)
}

func handleUnpair(args []string) {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := agent.RunUnpair(args, paths.PairedDevices, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleDevices() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := agent.RunDevices(paths.PairedDevices, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func handleAgentStatus() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pidFile := agent.PIDFilePath(paths)

	pid, err := agent.ReadPIDFile(pidFile)
	if err != nil {
		fmt.Println("Agent is not running")
		os.Exit(1)
	}

	if !agent.IsProcessRunning(pid) {
		fmt.Println("Agent is not running (stale PID file)")
		agent.CleanStalePIDFile(pidFile)
		os.Exit(1)
	}

	fmt.Printf("Agent is running (PID %d)\n", pid)

	// Try to get process uptime via ps
	out, err := exec.Command("ps", "-o", "etime=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err == nil {
		uptime := strings.TrimSpace(string(out))
		if uptime != "" {
			fmt.Printf("Uptime: %s\n", uptime)
		}
	}

	// Show last 5 lines of agent log
	logFile := filepath.Join(paths.ConfigDir, "agent.log")
	lines, err := tailFile(logFile, 5)
	if err == nil && len(lines) > 0 {
		fmt.Println("\nRecent log:")
		for _, line := range lines {
			fmt.Printf("  %s\n", line)
		}
	}
}

func handleAgentStop() {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	pidFile := agent.PIDFilePath(paths)

	pid, err := agent.ReadPIDFile(pidFile)
	if err != nil {
		fmt.Println("Agent is not running")
		os.Exit(1)
	}

	if !agent.IsProcessRunning(pid) {
		fmt.Println("Agent is not running (stale PID file cleaned up)")
		agent.RemovePIDFile(pidFile)
		os.Exit(0)
	}

	// Send SIGTERM for graceful shutdown
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to find process %d: %v\n", pid, err)
		os.Exit(1)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send SIGTERM to PID %d: %v\n", pid, err)
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
					fmt.Println("Agent stopped")
					agent.RemovePIDFile(pidFile)
					return
				}
				fmt.Fprintf(os.Stderr, "error: failed to send SIGKILL to PID %d: %v\n", pid, err)
				os.Exit(1)
			}
			fmt.Println("Agent forcefully killed")
			agent.RemovePIDFile(pidFile)
			return
		case <-ticker.C:
			if !agent.IsProcessRunning(pid) {
				fmt.Println("Agent stopped")
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
	fmt.Println(`pmux — PocketMux terminal access agent

PocketMux commands:
  init          Generate identity and register with signaling server
  pair          Pair with a mobile device (displays QR code)
  devices       List paired mobile devices
  unpair        Remove a paired mobile device
  agent-status  Show agent process status and recent logs
  agent-stop    Stop the background agent process
  --version     Show version
  --help        Show this help

All other commands are passed through to tmux -L pmux.
Run 'pmux' with no args to start a new session.

Examples:
  pmux                          Start new tmux session
  pmux new-session -s work      Named session
  pmux attach -t work           Attach to session
  pmux ls                       List sessions
  pmux kill-server              Stop tmux server + agent`)
}
