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
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil && ip.IsPrivate() {
		return nil
	}
	return fmt.Errorf("refusing to pair over unencrypted %s:// with non-local server %q; use https://", u.Scheme, host)
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
		name := existingDevice.Name
		if name == "" {
			name = existingDevice.DeviceID[:12] + "..."
		}
		pairedDate := existingDevice.PairedAt.Format("2006-01-02")
		fmt.Fprintf(w, "A device is already paired: %s (paired %s). Replace it? [y/N] ", auth.SanitizeDisplayString(name), pairedDate)

		reader := bufio.NewReader(r)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(w, "Pairing cancelled.")
			return nil
		}

		if err := auth.RemovePairedDevice(paths.PairedDevices, existingDevice.DeviceID, store); err != nil {
			return fmt.Errorf("Failed to remove paired device: %w", err)
		}
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

	// Build and display QR code. BuildQRPayload uses the bare server URL so
	// the mobile client stores a versionless host address; the mobile app
	// adds its own API version prefix when it opens connections.
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

	fmt.Fprintln(w, "\nScan this QR code with Pocketmux on your mobile device:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, qr.ToSmallString(false))
	fmt.Fprintf(w, "Manual pairing code: %s\n\n", auth.SanitizeDisplayString(auth.FormatManualCode(pairResp.PairingCode, pairingSecret)))
	fmt.Fprintln(w, "Waiting for mobile device to complete pairing...")

	// Stop the background agent if running. During pairing, the pair CLI
	// opens its own WebSocket to receive pair_complete. A competing agent
	// WebSocket for the same device ID can intercept the message after DO
	// hibernation, causing the pair CLI to hang. Stopping the agent ensures
	// only one WebSocket exists for this device during pairing.
	if err := StopRunning(paths); err != nil {
		fmt.Fprintf(w, "warning: failed to stop agent for pairing: %v\n", err)
	}

	// Get JWT for WebSocket auth
	jwt, err := auth.ExchangeToken(id, apiBaseURL, httpClient, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// Wait for mobile to complete pairing via WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	pairComplete, err := auth.WaitForPairComplete(ctx, apiBaseURL, jwt, hmacSecret)
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

	// Store paired device
	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("%w", err)
	}

	mobileName := auth.TruncateMobileName(pairComplete.MobileName)
	err = auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     pairComplete.MobileDeviceID,
		Name:         mobileName,
		SharedSecret: sharedSecret,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		return fmt.Errorf("failed to save paired device: %w", err)
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

	// Restart the background agent (stopped earlier to avoid WebSocket race).
	if err := ensureAgentRunning(paths, store); err != nil {
		fmt.Fprintf(w, "warning: failed to restart agent: %v\n", err)
	}

	return nil
}
