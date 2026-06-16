//go:build !darwin && !linux && !windows

package firewall

// NewManager returns an unsupported Manager on platforms without firewall support.
func NewManager() Manager { return unsupportedManager{} }
