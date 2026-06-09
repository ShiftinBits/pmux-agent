//go:build darwin || linux || windows

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// TestHelperProcess is the subprocess entry point used by the exec stubs.
// It echoes canned output for a given behavior and exits.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("GO_HELPER_BEHAVIOR") {
	case "mac_global_on":
		fmt.Println("Firewall is enabled. (State = 1)")
		os.Exit(0)
	case "mac_global_off":
		fmt.Println("Firewall is disabled. (State = 0)")
		os.Exit(0)
	case "mac_blockall_on":
		fmt.Println("Firewall has block all state set to enabled.")
		os.Exit(0)
	case "mac_blockall_off":
		fmt.Println("Firewall has block all state set to disabled.")
		os.Exit(0)
	case "mac_listapps_allowed":
		fmt.Println("Total number of apps = 2 ")
		fmt.Println("1 : /opt/homebrew/Caskroom/pmux/0.3.2/pmux ")
		fmt.Println("             (Allow incoming connections) ")
		os.Exit(0)
	case "mac_listapps_blocked":
		fmt.Println("Total number of apps = 1 ")
		fmt.Println("1 : /opt/homebrew/Caskroom/pmux/0.3.2/pmux ")
		fmt.Println("             (Block incoming connections) ")
		os.Exit(0)
	case "mac_listapps_absent":
		fmt.Println("Total number of apps = 1 ")
		fmt.Println("1 : /opt/homebrew/bin/other ")
		fmt.Println("             (Allow incoming connections) ")
		os.Exit(0)
	case "win_profile_on":
		fmt.Println("True")
		os.Exit(0)
	case "win_profile_off":
		fmt.Println("False")
		os.Exit(0)
	case "win_rule_present":
		fmt.Println("pmux agent")
		os.Exit(0)
	case "win_rule_absent":
		os.Exit(0) // empty output => not found
	case "linux_ufw_active":
		fmt.Println("Status: active")
		os.Exit(0)
	case "linux_ufw_inactive":
		fmt.Println("Status: inactive")
		os.Exit(0)
	case "linux_ufw_missing":
		fmt.Fprintln(os.Stderr, "ufw: command not found")
		os.Exit(127)
	case "linux_fwd_running":
		fmt.Println("running")
		os.Exit(0)
	case "linux_fwd_absent":
		fmt.Fprintln(os.Stderr, "not running")
		os.Exit(1)
	case "success":
		os.Exit(0)
	case "failure":
		fmt.Fprintln(os.Stderr, "mock command failed")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown GO_HELPER_BEHAVIOR: %q\n", os.Getenv("GO_HELPER_BEHAVIOR"))
		os.Exit(1)
	}
}

// fakeByArg returns a replacement for execCommand that maps each command to a
// behavior key by "name" or "name firstArg", so a single Probe call invoking
// several commands can return distinct canned outputs.
func fakeByArg(mapping map[string]string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		key := name
		if len(args) > 0 {
			key = name + " " + args[0]
		}
		behavior := mapping[key]
		if behavior == "" {
			behavior = mapping[name]
		}
		cs := []string{"-test.run=TestHelperProcess", "--", name}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "GO_HELPER_BEHAVIOR="+behavior)
		return cmd
	}
}
