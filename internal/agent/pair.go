package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// Indirected through package vars so tests can drive a full pairing against a
// fake server: the secret never reaches the server, so a fake mobile can only
// compute pairMac if the test controls it, and restarting the agent would
// spawn the test binary.
var (
	generatePairingSecret = auth.GeneratePairingSecret
	ensureAgentRunning    = EnsureRunning
)

// errPairMACRejected is returned when pair_complete does not carry a valid
// pairMac. Pairing is aborted rather than waiting for another pair_complete:
// one guess per pairing session is what keeps the pairing secret's length
// sufficient.
var errPairMACRejected = errors.New("pairing rejected: mobile could not prove it scanned this code (update the Pocketmux app, or the signaling server tampered with pairing)")

// checkServerTransport refuses a cleartext (http:// or ws://) server URL
// unless the host is loopback or an RFC 1918 private IPv4 address, matching
// the mobile app's validateServerUrl. Pairing data sent in cleartext to a
// public host could be rewritten in transit.
func checkServerTransport(serverURL string) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "ws" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || (ip.To4() != nil && ip.IsPrivate())) {
		return nil
	}
	return fmt.Errorf("refusing to pair over unencrypted %s:// with non-local server %q; use https://", u.Scheme, host)
}

// pairedDeviceLabel names a paired device for the terminal: its name, or else
// a prefix of its device ID.
func pairedDeviceLabel(d *auth.PairedDevice) string {
	if d.Name != "" {
		return d.Name
	}
	if len(d.DeviceID) > 12 {
		return d.DeviceID[:12] + "..."
	}
	return d.DeviceID
}

// RunPair pairs this host with a mobile device via the signaling server.
// It displays a QR code for scanning, waits for the mobile to complete
// the pairing handshake, and stores the resulting shared secret locally.
func RunPair(paths config.Paths, cfg config.Config, store auth.SecretStore, hmacSecret string, r io.Reader, w io.Writer) error {
	// Must have identity first
	if !auth.HasIdentity(paths.KeysDir, store) {
		return fmt.Errorf("no identity found. Run 'pmux init' first")
	}

	id, err := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}

	// serverURL is the bare host URL — used for the transport check below
	// and the QR code payload (the mobile decodes the bare URL and adds its
	// own version prefix). apiBaseURL carries the configured API version
	// suffix and is passed to every HTTP/WS helper.
	serverURL := cfg.ServerURL()
	apiBaseURL := cfg.APIBaseURL()

	// Refuse cleartext transport to a non-local server before touching the
	// existing pairing or contacting the server.
	if err := checkServerTransport(serverURL); err != nil {
		return err
	}

	// Check for existing pairing
	existingDevice, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		return fmt.Errorf("Failed to load paired devices: %w", err)
	}

	if existingDevice != nil {
		pairedDate := existingDevice.PairedAt.Format("2006-01-02")
		fmt.Fprintf(w, "A device is already paired: %s (paired %s). Replace it? [y/N] ", auth.SanitizeDisplayString(pairedDeviceLabel(existingDevice)), pairedDate)

		reader := bufio.NewReader(r)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(w, "Pairing cancelled.")
			return nil
		}
		// With a server that confirms pairing, the old device is replaced
		// only once the new pairing is stored, so a failed or rejected
		// re-pair leaves it in place. A legacy server replaces the old
		// mobile as soon as the new one completes pairing, so from then on
		// the old device is removed here too, whether or not the new
		// pairing is stored.
	}

	// Generate X25519 ephemeral keypair for key exchange
	x25519kp, err := auth.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}

	// The pairing secret goes only into the QR code / manual code, never to
	// the server, and is not persisted.
	pairingSecret, err := generatePairingSecret()
	if err != nil {
		return fmt.Errorf("failed to generate pairing secret: %w", err)
	}

	hostName := cfg.Name
	if hostName == "" {
		hostName = config.DefaultHostName()
	}

	// Initiate pairing with signaling server
	fmt.Fprintln(w, "Contacting signaling server...")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	pairResp, err := auth.InitiatePairing(id, x25519kp.PublicKeyBase64(), apiBaseURL, httpClient, hostName, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to initiate pairing: %w", err)
	}
	// A server that echoes pairConfirm holds the mobile's request, for at
	// most 30s, for our answer to pair_complete. An older server has already
	// committed the pairing by the time pair_complete arrives.
	confirmed := pairResp.PairConfirm
	if !confirmed {
		fmt.Fprintln(w, "warning: the signaling server did not confirm support for host-confirmed pairing, so it will commit the pairing before this host verifies the mobile. Update the server.")
	}

	// Build the QR code now, but show it only once the WebSocket is ready to
	// receive pair_complete. BuildQRPayload uses the bare server URL so the
	// mobile client stores a versionless host address; the mobile app adds
	// its own API version prefix when it opens connections.
	qrData, err := auth.BuildQRPayload(
		pairResp.PairingCode,
		x25519kp.PublicKeyBase64(),
		id.DeviceID,
		serverURL,
		pairingSecret,
	)
	if err != nil {
		return fmt.Errorf("failed to build QR payload: %w", err)
	}

	qr, err := qrcode.New(qrData, qrcode.Low)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Stop the background agent if running. During pairing, the pair CLI
	// opens its own WebSocket to receive pair_complete. A competing agent
	// WebSocket for the same device ID can intercept the message after DO
	// hibernation, causing the pair CLI to hang. Stopping the agent ensures
	// only one WebSocket exists for this device during pairing.
	if err := StopRunning(paths); err != nil {
		fmt.Fprintf(w, "warning: failed to stop agent for pairing: %v\n", err)
	}
	// Restart the agent on every exit from here on, including failed or
	// rejected pairings, so the host never stays unreachable.
	defer func() {
		if err := ensureAgentRunning(paths, store); err != nil {
			fmt.Fprintf(w, "warning: failed to restart agent: %v\n", err)
		}
	}()

	// Get JWT for WebSocket auth
	jwt, err := auth.ExchangeToken(id, apiBaseURL, httpClient, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	sess, err := auth.DialPairSession(ctx, apiBaseURL, jwt, hmacSecret, confirmed)
	if err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}
	// In confirmed mode, Close rejects a pair_complete we didn't accept, so
	// every early return below leaves nothing committed on the server.
	defer func() {
		if err := sess.Close(); err != nil {
			fmt.Fprintf(w, "warning: failed to reject pairing on server: %s\n", auth.SanitizeDisplayString(err.Error()))
		}
	}()

	fmt.Fprintln(w, "\nScan this QR code with Pocketmux on your mobile device:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, qr.ToSmallString(false))
	fmt.Fprintf(w, "Manual pairing code: %s\n\n", auth.SanitizeDisplayString(auth.FormatManualCode(pairResp.PairingCode, pairingSecret)))
	fmt.Fprintln(w, "Waiting for mobile device to complete pairing...")

	// A legacy server committed the pairing, replacing the old mobile and
	// sending it device_unpaired, as soon as the mobile completed pairing,
	// before this host could verify it. From then on the old device is gone
	// server-side, so drop it locally; and if the new device isn't stored,
	// remove the server's pairing so it doesn't point at a mobile we never
	// stored.
	var (
		pairComplete *auth.PairCompleteMessage
		stored       bool
	)
	defer func() {
		if confirmed || pairComplete == nil {
			return
		}
		if !stored {
			if err := auth.DeletePairing(id, apiBaseURL, httpClient, hmacSecret); err != nil {
				fmt.Fprintf(w, "warning: failed to remove the unverified pairing from the server: %s\n", auth.SanitizeDisplayString(err.Error()))
			}
		}
		// A stored re-pair of the same device replaced it rather than
		// unpairing it.
		if existingDevice == nil || (stored && existingDevice.DeviceID == pairComplete.MobileDeviceID) {
			return
		}
		// On success AddPairedDevice already replaced the old device.
		if !stored {
			if err := auth.RemovePairedDevice(paths.PairedDevices, existingDevice.DeviceID, store); err != nil {
				fmt.Fprintf(w, "warning: failed to remove the previous device: %v\n", err)
			}
		}
		fmt.Fprintf(w, "The server unpaired the previous device '%s'.\n", auth.SanitizeDisplayString(pairedDeviceLabel(existingDevice)))
	}()

	// pairComplete is non-nil whenever one was received, even on error.
	pairComplete, err = sess.WaitForPairComplete(ctx)
	if err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}

	// Verify the mobile proved knowledge of the QR-only secret before using
	// its key. On failure, abort instead of waiting for another pair_complete.
	if err := auth.VerifyPairMAC(
		pairingSecret,
		pairComplete.MobileX25519PublicKey,
		pairComplete.MobileDeviceID,
		pairComplete.PairMac,
	); err != nil {
		return fmt.Errorf("%w: %w", errPairMACRejected, err)
	}

	// Compute shared secret via X25519 key exchange
	sharedSecret, err := x25519kp.ComputeSharedSecret(
		pairComplete.MobileX25519PublicKey,
		pairingSecret,
		id.DeviceID,
		pairComplete.MobileDeviceID,
	)
	if err != nil {
		return fmt.Errorf("key exchange failed: %w", err)
	}

	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("%w", err)
	}

	// Persist nothing until the server confirms it committed the pairing.
	// The server holds the mobile's request for at most 30s from when the
	// mobile sent it, so nothing slow may run before Accept.
	if confirmed {
		if err := sess.Accept(auth.PairAcceptTimeout); err != nil {
			return fmt.Errorf("pairing failed: %w", err)
		}
	}

	// ponytail: with a confirming server, a local store failure after the
	// commit leaves a server-only pairing; the error tells the user to pair
	// again, which replaces it. A legacy server's pairing is removed instead.
	mobileName := auth.TruncateMobileName(pairComplete.MobileName)
	err = auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     pairComplete.MobileDeviceID,
		Name:         mobileName,
		SharedSecret: sharedSecret,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		return fmt.Errorf("failed to save paired device (run 'pmux pair' again): %w", err)
	}
	stored = true

	// AddPairedDevice replaced the device list, so only the old device's
	// secret is left. Failing to delete it leaves an unused secret behind
	// rather than failing a pairing the server has committed. A re-pair of
	// the same device already overwrote it.
	if existingDevice != nil && existingDevice.DeviceID != pairComplete.MobileDeviceID {
		if err := store.Delete(auth.SharedSecretKey(existingDevice.DeviceID)); err != nil {
			fmt.Fprintf(w, "warning: failed to delete the previous device's secret: %v\n", err)
		}
	}

	displayName := mobileName
	if displayName == "" {
		displayName = pairComplete.MobileDeviceID
	}
	fmt.Fprintf(w, "Paired successfully with device '%s'\n", auth.SanitizeDisplayString(displayName))

	// If the agent is still running (e.g., a racing pmux command restarted it),
	// signal it to reload the new pairing state.
	pidFile := PIDFilePath(paths)
	if pid, err := ReadPIDFile(pidFile); err == nil && IsProcessRunning(pid) {
		signalReloadPairing(pid)
	}

	return nil
}
