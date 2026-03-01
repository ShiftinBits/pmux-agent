package agent

import (
	"fmt"
	"io"
	"strings"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// RunUnpair removes the paired mobile device after confirmation.
//
// TODO: When the agent is running, closing the DataChannel to the unpaired
// device and notifying the signaling server would give immediate feedback.
// For now, the device is only removed from local storage; the agent will
// reject messages from the device on its next connection attempt.
func RunUnpair(pairedDevicesPath string, store auth.SecretStore, r io.Reader, w io.Writer) error {
	device, err := auth.LoadPairedDevice(pairedDevicesPath, store)
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

	if err := auth.RemovePairedDevice(pairedDevicesPath, device.DeviceID, store); err != nil {
		return fmt.Errorf("remove device: %w", err)
	}

	fmt.Fprintf(w, "Device '%s' unpaired successfully.\n", name)
	return nil
}
