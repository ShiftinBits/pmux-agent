package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

const (
	tmuxSocket = "pmux"
	version    = "0.1.0-dev"
)

func main() {
	args := os.Args[1:]

	// No args: default to new session (or attach if server running)
	if len(args) == 0 {
		execTmux()
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
	case "--version", "-v":
		fmt.Printf("pmux version %s\n", version)
		return
	case "--help", "-h":
		printHelp()
		return
	}

	// Everything else: passthrough to tmux -L pmux
	execTmux(args...)
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
	fmt.Println("pmux pair: not implemented yet (T1.10)")
}

func execTmux(args ...string) {
	tmuxPath, err := exec.LookPath("tmux")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: tmux not found in PATH\n")
		os.Exit(1)
	}

	// Build args: tmux -L pmux [user args...]
	tmuxArgs := []string{"tmux", "-L", tmuxSocket}
	tmuxArgs = append(tmuxArgs, args...)

	// Replace current process with tmux
	if err := syscall.Exec(tmuxPath, tmuxArgs, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to exec tmux: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`pmux — PocketMux terminal access agent

PocketMux commands:
  init          Generate identity and register with signaling server
  pair          Pair with a mobile device (displays QR code)
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
