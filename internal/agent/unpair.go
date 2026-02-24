package agent

import (
	"fmt"
	"io"
	"strings"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// RunUnpair removes a paired device by device ID prefix.
// Takes io.Reader for input (confirmation prompt) and io.Writer for output.
func RunUnpair(args []string, pairedDevicesPath string, r io.Reader, w io.Writer) error {
	if len(args) == 0 {
		fmt.Fprintln(w, "Usage: pmux unpair <device-id-prefix>")
		return nil
	}

	prefix := args[0]
	devices, err := auth.LoadPairedDevices(pairedDevicesPath)
	if err != nil {
		return fmt.Errorf("load paired devices: %w", err)
	}

	// Find matching devices by prefix
	var matches []auth.PairedDevice
	for _, d := range devices {
		if strings.HasPrefix(d.DeviceID, prefix) {
			matches = append(matches, d)
		}
	}

	if len(matches) == 0 {
		fmt.Fprintf(w, "No device found matching '%s'.\n", prefix)
		return nil
	}

	if len(matches) > 1 {
		fmt.Fprintf(w, "Ambiguous prefix '%s'. Matching devices:\n", prefix)
		for _, d := range matches {
			id := d.DeviceID
			if len(id) > 12 {
				id = id[:12] + "..."
			}
			name := d.Name
			if name == "" {
				name = "(unnamed)"
			}
			fmt.Fprintf(w, "  %s  %s\n", id, name)
		}
		return nil
	}

	device := matches[0]
	name := device.Name
	if name == "" {
		name = "(unnamed)"
	}

	deviceIDShort := device.DeviceID
	if len(deviceIDShort) > 12 {
		deviceIDShort = deviceIDShort[:12] + "..."
	}

	// Confirmation prompt
	fmt.Fprintf(w, "Unpair device '%s' (%s)? [y/N] ", name, deviceIDShort)
	var response string
	fmt.Fscanln(r, &response)
	if strings.ToLower(response) != "y" {
		fmt.Fprintln(w, "Cancelled.")
		return nil
	}

	// Remove from storage
	if err := auth.RemovePairedDevice(pairedDevicesPath, device.DeviceID); err != nil {
		return fmt.Errorf("remove device: %w", err)
	}

	fmt.Fprintf(w, "Device '%s' unpaired successfully.\n", name)
	return nil
}
