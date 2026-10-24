package agent

import (
	"errors"
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

var errNoIdentity = errors.New("no identity found; run 'pmux init' first")

// RunAgentStart starts the Pocketmux agent. It checks whether the agent is
// already running, fails with errNoIdentity if no identity exists, and
// otherwise spawns it directly via EnsureRunning.
func RunAgentStart(paths config.Paths, store auth.SecretStore, w io.Writer) error {
	// Check if already running
	pidFile := PIDFilePath(paths)
	if pid, err := ReadPIDFile(pidFile); err == nil && IsProcessRunning(pid) {
		fmt.Fprintf(w, "Agent is already running (PID %d)\n", pid)
		return nil
	}

	if err := checkIdentity(paths, store); err != nil {
		return err
	}

	if err := EnsureRunning(paths, store); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}
	fmt.Fprintln(w, "Agent started")
	return nil
}

// checkIdentity returns errNoIdentity when no identity exists, and the
// underlying error when the secret store fails for any other reason (e.g. a
// locked keychain), so a valid identity is never mistaken for a missing one.
func checkIdentity(paths config.Paths, store auth.SecretStore) error {
	if auth.HasIdentity(paths.KeysDir, store) {
		return nil
	}
	if _, err := store.Get(auth.SecretKeyEd25519Private); err != nil && !errors.Is(err, auth.ErrSecretNotFound) {
		return fmt.Errorf("read identity from secret store: %w", err)
	}
	return errNoIdentity
}
