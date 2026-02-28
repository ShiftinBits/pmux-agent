package agent

import (
	"fmt"
	"io"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// RunDevices lists all paired mobile devices.
func RunDevices(pairedDevicesPath string, store auth.SecretStore, w io.Writer) error {
	devices, err := auth.LoadPairedDevices(pairedDevicesPath, store)
	if err != nil {
		return fmt.Errorf("load paired devices: %w", err)
	}

	if len(devices) == 0 {
		fmt.Fprintln(w, "No paired devices.")
		return nil
	}

	fmt.Fprintf(w, "%-14s  %-20s  %-12s  %-18s\n",
		"DEVICE ID", "NAME", "PAIRED", "LAST SEEN")

	for _, d := range devices {
		deviceIDShort := d.DeviceID
		if len(deviceIDShort) > 12 {
			deviceIDShort = deviceIDShort[:12] + "..."
		}

		name := d.Name
		if name == "" {
			name = "(unnamed)"
		}
		if len(name) > 20 {
			name = name[:17] + "..."
		}

		paired := d.PairedAt.Format("2006-01-02")

		lastSeen := "never"
		if d.LastSeen > 0 {
			lastSeen = time.Unix(d.LastSeen, 0).Format("2006-01-02 15:04")
		}

		fmt.Fprintf(w, "%-14s  %-20s  %-12s  %-18s\n",
			deviceIDShort, name, paired, lastSeen)
	}
	return nil
}
