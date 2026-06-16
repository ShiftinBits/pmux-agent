package agent

import (
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/firewall"
	"github.com/shiftinbits/pmux-agent/internal/service"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

// SessionLister abstracts tmux session listing for testability.
// tmux.Client satisfies this interface.
type SessionLister interface {
	ListSessions() ([]tmux.Session, error)
}

// StatusParams holds all dependencies for the RunStatus command.
type StatusParams struct {
	Version           string
	PairedDevicesPath string
	Store             auth.SecretStore
	PIDFilePath       string
	ServiceManager    service.Manager // nil-safe: treated as "not installed"
	Sessions          SessionLister   // nil-safe: treated as 0 sessions
	// FirewallStatus is the probed host-firewall status; nil omits the line.
	FirewallStatus *firewall.Status
}

// RunStatus shows a comprehensive status overview: agent process, service
// registration, tmux session count, and paired mobile device info.
func RunStatus(params StatusParams, w io.Writer) error {
	// --- Version ---
	if params.Version != "" {
		fmt.Fprintf(w, "Version:  %s\n", params.Version)
	}

	// --- Agent process status ---
	agentLine := "not running"
	if params.PIDFilePath != "" {
		if pid, err := ReadPIDFile(params.PIDFilePath); err == nil {
			if IsProcessRunning(pid) {
				agentLine = fmt.Sprintf("running (PID %d)", pid)
			} else {
				RemovePIDFile(params.PIDFilePath)
			}
		}
	}
	fmt.Fprintf(w, "Agent:    %s\n", agentLine)

	// --- Service status ---
	serviceLine := "not installed"
	if params.ServiceManager != nil && params.ServiceManager.IsInstalled() {
		serviceLine = "installed"
	}
	fmt.Fprintf(w, "Service:  %s\n", serviceLine)

	// --- tmux sessions ---
	sessionLine := "0"
	if params.Sessions != nil {
		sessions, err := params.Sessions.ListSessions()
		if err != nil {
			sessionLine = "unknown"
		} else {
			sessionLine = fmt.Sprintf("%d", len(sessions))
		}
	}
	fmt.Fprintf(w, "Sessions: %s\n", sessionLine)

	// --- Firewall ---
	// Detection-only: surface the standard warning when the firewall is suspected
	// of blocking inbound connections; stay silent otherwise.
	if fw := params.FirewallStatus; fw != nil && firewall.NeedsAttention(*fw) {
		fmt.Fprintf(w, "%s\n", firewall.Warning)
	}

	// --- Blank separator ---
	fmt.Fprintln(w)

	// --- Paired device ---
	device, err := auth.LoadPairedDevice(params.PairedDevicesPath, params.Store)
	if err != nil {
		return fmt.Errorf("load paired device: %w", err)
	}

	if device == nil {
		fmt.Fprintln(w, "No device paired. Run 'pmux pair' to pair a mobile device.")
		return nil
	}

	deviceIDShort := device.DeviceID
	if len(deviceIDShort) > 12 {
		deviceIDShort = deviceIDShort[:12] + "..."
	}

	if device.Name != "" {
		fmt.Fprintf(w, "Paired device: %s\n", device.Name)
		fmt.Fprintf(w, "  Device ID:  %s\n", deviceIDShort)
	} else {
		fmt.Fprintf(w, "Paired device: %s\n", deviceIDShort)
	}
	fmt.Fprintf(w, "  Paired:     %s\n", device.PairedAt.Format("2006-01-02"))

	return nil
}
