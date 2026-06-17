package agent

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/firewall"
)

// RunInit generates a new Pocketmux identity and writes the initial config file.
// If an identity already exists, it displays the existing device ID and returns.
// The agent starts automatically on any pmux command via EnsureRunning.
func RunInit(paths config.Paths, cfg config.Config, store auth.SecretStore, tmuxPath string, r io.Reader, w io.Writer) error {
	// Check if identity already exists
	if auth.HasIdentity(paths.KeysDir, store) {
		id, err := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
		if err != nil {
			return fmt.Errorf("failed to load existing identity: %w", err)
		}
		fmt.Fprintf(w, "Identity already exists.\n")
		fmt.Fprintf(w, "Device ID: %s\n", id.DeviceID)
		if cfg.Name != "" {
			fmt.Fprintf(w, "Host name: %s\n", cfg.Name)
		}
		return nil
	}

	id, err := auth.GenerateIdentity(paths.KeysDir, store)
	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}

	// Prompt for host name (default: OS hostname)
	defaultName := config.DefaultHostName()
	fmt.Fprintf(w, "Host name [%s]: ", defaultName)
	reader := bufio.NewReader(r)
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
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Fprintf(w, "\nIdentity generated.\n")
	fmt.Fprintf(w, "Device ID: %s\n", id.DeviceID)
	fmt.Fprintf(w, "Host name: %s\n", input)
	fmt.Fprintf(w, "Keys saved to: %s (backend: %s)\n", paths.KeysDir, store.Backend())

	PrintFirewallNotice(w)
	return nil
}

// PrintFirewallNotice probes the host firewall for the running binary and, if
// it is likely blocking inbound connections, prints the standard warning to w.
func PrintFirewallNotice(w io.Writer) {
	exePath, err := firewall.ExecutablePath()
	if err != nil {
		return
	}
	if st := firewall.NewManager().Probe(exePath); firewall.NeedsAttention(st) {
		fmt.Fprintf(w, "\n%s\n", firewall.Warning)
	}
}
