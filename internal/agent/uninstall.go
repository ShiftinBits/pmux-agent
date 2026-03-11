package agent

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/service"
)

// RunUninstall removes PocketMux completely — the reverse of init.
// It stops the agent, uninstalls the OS service, un-registers from the
// signaling server, and removes local config/keys.
// If keepConfig is true, local config and keys are preserved.
func RunUninstall(paths config.Paths, store auth.SecretStore, mgr service.Manager, keepConfig bool, hmacSecret string, skipConfirm bool, r io.Reader, w io.Writer) error {
	if skipConfirm {
		fmt.Fprintln(w, "Uninstalling PocketMux from this host:")
		fmt.Fprintln(w, "  • Stop the agent process")
		fmt.Fprintln(w, "  • Uninstall the agent service (launchd/systemd)")
		fmt.Fprintln(w, "  • Un-register this host from the signaling server")
		if !keepConfig {
			fmt.Fprintf(w, "  • Delete config and keys (%s)\n", paths.ConfigDir)
		}
		fmt.Fprintln(w)
	} else {
		// Step 1: Interactive confirmation
		fmt.Fprintln(w, "This will remove PocketMux from this host:")
		fmt.Fprintln(w, "  • Stop the agent process")
		fmt.Fprintln(w, "  • Uninstall the agent service (launchd/systemd)")
		fmt.Fprintln(w, "  • Un-register this host from the signaling server")
		if !keepConfig {
			fmt.Fprintf(w, "  • Delete config and keys (%s)\n", paths.ConfigDir)
		}
		fmt.Fprint(w, "\nProceed with uninstall? [y/N] ")

		var response string
		if _, err := fmt.Fscanln(r, &response); err != nil {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Cancelled.")
			return nil
		}
		if strings.ToLower(response) != "y" {
			fmt.Fprintln(w, "Cancelled.")
			return nil
		}

		fmt.Fprintln(w)
	}

	// Step 2: Stop agent process (best-effort)
	if err := StopRunning(paths); err != nil {
		fmt.Fprintf(w, "Warning: could not stop agent: %v\n", err)
	} else {
		fmt.Fprintln(w, "Agent process stopped.")
	}

	// Step 3: Uninstall OS service (best-effort)
	if err := mgr.Uninstall(); err != nil {
		fmt.Fprintf(w, "Warning: could not uninstall service: %v\n", err)
	} else {
		fmt.Fprintln(w, "Agent service uninstalled.")
	}

	// Step 4: Un-register from signaling server (best-effort)
	identity, identErr := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
	if identErr == nil {
		cfg, _ := config.LoadConfig(paths.ConfigFile)
		httpClient := &http.Client{Timeout: 10 * time.Second}
		if err := auth.DeleteDevice(identity, cfg.ServerURL(), httpClient, hmacSecret); err != nil {
			fmt.Fprintf(w, "Warning: could not un-register from server: %v\n", err)
			fmt.Fprintln(w, "  The host may still appear on your mobile device.")
		} else {
			fmt.Fprintln(w, "Host un-registered from signaling server.")
		}
	} else {
		fmt.Fprintln(w, "No identity found, skipping server un-registration.")
	}

	// Step 5: Clean up config and secrets (if not --keep-config)
	if !keepConfig {
		// Delete secrets from store before removing config dir
		// (encrypted-file backend stores inside config dir, but keyring is external)
		if identErr == nil {
			// Clean up shared secret for paired device (if any)
			device, _ := auth.LoadPairedDevice(paths.PairedDevices, store)
			if device != nil {
				_ = store.Delete(auth.SharedSecretKey(device.DeviceID))
			}
			// Clean up private key
			_ = store.Delete(auth.SecretKeyEd25519Private)
		}

		if err := os.RemoveAll(paths.ConfigDir); err != nil {
			return fmt.Errorf("remove config directory: %w", err)
		}
		fmt.Fprintf(w, "Config directory removed (%s).\n", paths.ConfigDir)
	} else {
		fmt.Fprintln(w, "Config and keys preserved (--keep-config).")
	}

	fmt.Fprintln(w, "\nPocketMux uninstalled successfully.")
	return nil
}
