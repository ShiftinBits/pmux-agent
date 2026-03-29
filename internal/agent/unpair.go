package agent

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// RunUnpair removes the paired mobile device after confirmation.
// It notifies the signaling server (best-effort) and signals the running
// agent to close active connections before removing the local pairing.
func RunUnpair(paths config.Paths, store auth.SecretStore, hmacSecret string, r io.Reader, w io.Writer) error {
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		return fmt.Errorf("load paired device: %w", err)
	}

	if device == nil {
		fmt.Fprintln(w, "No device paired.")
		return nil
	}

	name := device.Name
	if name == "" {
		name = "(unnamed)"
	}

	deviceIDShort := device.DeviceID
	if len(deviceIDShort) > 12 {
		deviceIDShort = deviceIDShort[:12] + "..."
	}

	fmt.Fprintf(w, "Unpair device '%s' (%s)?\nThis device will need to scan a new QR code to reconnect. [y/N] ", name, deviceIDShort)
	var response string
	if _, err := fmt.Fscanln(r, &response); err != nil {
		// EOF or read error — treat as cancel
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Cancelled.")
		return nil
	}
	if strings.ToLower(response) != "y" {
		fmt.Fprintln(w, "Cancelled.")
		return nil
	}

	// Notify signaling server (best-effort)
	identity, identErr := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
	if identErr == nil {
		cfg, _ := config.LoadConfig(paths.ConfigFile)
		httpClient := &http.Client{Timeout: 10 * time.Second}
		if err := auth.DeletePairing(identity, cfg.ServerURL(), httpClient, hmacSecret); err != nil {
			fmt.Fprintf(w, "Warning: could not notify server: %v\n", err)
		}
	}

	if err := auth.RemovePairedDevice(paths.PairedDevices, device.DeviceID, store); err != nil {
		return fmt.Errorf("remove device: %w", err)
	}

	// Signal running agent to close connections (best-effort)
	pidFile := PIDFilePath(paths)
	if pid, err := ReadPIDFile(pidFile); err == nil && IsProcessRunning(pid) {
		signalReloadPairing(pid)
	}

	fmt.Fprintf(w, "Device '%s' unpaired successfully.\n", name)
	return nil
}
