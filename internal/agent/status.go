package agent

import (
	"fmt"
	"io"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// RunStatus shows the paired mobile device, or a hint to pair if none.
func RunStatus(pairedDevicesPath string, store auth.SecretStore, w io.Writer) error {
	device, err := auth.LoadPairedDevice(pairedDevicesPath, store)
	if err != nil {
		return fmt.Errorf("load paired device: %w", err)
	}

	if device == nil {
		fmt.Fprintln(w, "No device paired. Run 'pmux pair' to pair a mobile device.")
		return nil
	}

	name := device.Name
	if name == "" {
		name = device.DeviceID
		if len(name) > 12 {
			name = name[:12] + "..."
		}
	}

	deviceIDShort := device.DeviceID
	if len(deviceIDShort) > 12 {
		deviceIDShort = deviceIDShort[:12] + "..."
	}

	lastSeen := "never"
	if device.LastSeen > 0 {
		lastSeen = time.Unix(device.LastSeen, 0).Format("2006-01-02 15:04")
	}

	fmt.Fprintf(w, "Paired device: %s\n", name)
	fmt.Fprintf(w, "  Device ID:  %s\n", deviceIDShort)
	fmt.Fprintf(w, "  Paired:     %s\n", device.PairedAt.Format("2006-01-02"))
	fmt.Fprintf(w, "  Last seen:  %s\n", lastSeen)

	return nil
}
