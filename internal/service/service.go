// Package service manages the pmux agent as an OS service (launchd on macOS,
// systemd on Linux). The agent IS the service — these are not separate concepts.
package service

import (
	"fmt"
	"runtime"
)

// Status represents the current state of the agent service.
type Status struct {
	Installed bool
	Running   bool
	PID       int
}

// Manager provides cross-platform service lifecycle management.
type Manager interface {
	// Install generates the platform service file, registers it, and starts the agent.
	Install() error
	// Uninstall stops the agent, deregisters, and removes the service file.
	Uninstall() error
	// Start starts the agent via the service manager.
	Start() error
	// Stop stops the agent and tells the service manager not to restart it.
	Stop() error
	// Status returns the current agent service state.
	Status() (Status, error)
	// IsInstalled returns whether the service file exists and is registered.
	IsInstalled() bool
}

// NewManager returns the appropriate Manager for the current platform.
// pmuxPath is the absolute path to the pmux binary (resolved at install time).
// configDir is the path to ~/.config/pmux (for log file paths in service config).
func NewManager(pmuxPath string, configDir string) Manager {
	switch runtime.GOOS {
	case "darwin":
		return newLaunchdManager(pmuxPath, configDir)
	case "linux":
		return newSystemdManager(pmuxPath, configDir)
	default:
		return &unsupportedManager{platform: runtime.GOOS}
	}
}

// unsupportedManager is returned on platforms without service manager support.
type unsupportedManager struct {
	platform string
}

func (u *unsupportedManager) Install() error {
	return fmt.Errorf("service management not supported on %s", u.platform)
}
func (u *unsupportedManager) Uninstall() error {
	return fmt.Errorf("service management not supported on %s", u.platform)
}
func (u *unsupportedManager) Start() error {
	return fmt.Errorf("service management not supported on %s", u.platform)
}
func (u *unsupportedManager) Stop() error {
	return fmt.Errorf("service management not supported on %s", u.platform)
}
func (u *unsupportedManager) Status() (Status, error) {
	return Status{}, fmt.Errorf("service management not supported on %s", u.platform)
}
func (u *unsupportedManager) IsInstalled() bool { return false }
