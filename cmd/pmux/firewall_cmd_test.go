package main

import (
	"testing"

	fw "github.com/shiftinbits/pmux-agent/internal/firewall"
)

// Ensures printFirewallResult renders both states without panicking.
func TestPrintFirewallResult(t *testing.T) {
	printFirewallResult(fw.Status{Supported: true, FirewallEnabled: true, Authorized: true, Path: "/x/pmux"})
	printFirewallResult(fw.Status{Supported: true, FirewallEnabled: true, Authorized: false, Path: "/x/pmux", Detail: "blocked"})
}
