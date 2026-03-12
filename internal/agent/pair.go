package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/service"
)

// RunPair pairs this host with a mobile device via the signaling server.
// It displays a QR code for scanning, waits for the mobile to complete
// the pairing handshake, and stores the resulting shared secret locally.
func RunPair(paths config.Paths, cfg config.Config, store auth.SecretStore, mgr service.Manager, hmacSecret string, r io.Reader, w io.Writer) error {
	// Must have identity first
	if !auth.HasIdentity(paths.KeysDir, store) {
		return fmt.Errorf("no identity found. Run 'pmux init' first")
	}

	id, err := auth.LoadIdentity(paths.KeysDir, store, slog.Default())
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
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
		fmt.Fprintf(w, "A device is already paired: %s (paired %s). Replace it? [y/N] ", name, pairedDate)

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

	serverURL := cfg.ServerURL()

	// Warn if using unencrypted HTTP for non-local server
	if strings.HasPrefix(serverURL, "http://") || strings.HasPrefix(serverURL, "ws://") {
		host := strings.TrimPrefix(strings.TrimPrefix(serverURL, "http://"), "ws://")
		host = strings.Split(host, "/")[0] // strip path
		host = strings.Split(host, ":")[0] // strip port
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			fmt.Fprintf(w, "WARNING: Server URL %q uses unencrypted HTTP.\n", serverURL)
			fmt.Fprintf(w, "  Pairing data (public keys, device IDs) will be sent in cleartext.\n")
			fmt.Fprintf(w, "  Use https:// for production servers.\n\n")
		}
	}

	// Generate X25519 ephemeral keypair for key exchange
	x25519kp, err := auth.GenerateX25519Keypair()
	if err != nil {
		return fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}

	hostName := cfg.Name
	if hostName == "" {
		hostName = config.DefaultHostName()
	}

	// Initiate pairing with signaling server
	fmt.Fprintln(w, "Contacting signaling server...")
	httpClient := &http.Client{Timeout: 10 * time.Second}
	pairResp, err := auth.InitiatePairing(id, x25519kp.PublicKeyBase64(), serverURL, httpClient, hostName, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to initiate pairing: %w", err)
	}

	// Build and display QR code
	qrData, err := auth.BuildQRPayload(
		pairResp.PairingCode,
		x25519kp.PublicKeyBase64(),
		id.DeviceID,
		serverURL,
	)
	if err != nil {
		return fmt.Errorf("failed to build QR payload: %w", err)
	}

	qr, err := qrcode.New(qrData, qrcode.Low)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	fmt.Fprintln(w, "\nScan this QR code with PocketMux on your mobile device:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, qr.ToSmallString(false))
	fmt.Fprintf(w, "Manual pairing code: %s\n\n", pairResp.PairingCode)
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
	jwt, err := auth.ExchangeToken(id, serverURL, httpClient, hmacSecret)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// Wait for mobile to complete pairing via WebSocket
	ctx, cancel := context.WithTimeout(context.Background(), auth.PairTimeout)
	defer cancel()

	pairComplete, err := auth.WaitForPairComplete(ctx, serverURL, jwt, hmacSecret)
	if err != nil {
		return fmt.Errorf("pairing failed: %w", err)
	}

	// Compute shared secret via X25519 key exchange
	sharedSecret, err := x25519kp.ComputeSharedSecret(pairComplete.MobileX25519PublicKey)
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
	fmt.Fprintf(w, "Paired successfully with device '%s'\n", displayName)

	// Restart the background agent (stopped earlier to avoid WebSocket race).
	if err := EnsureRunning(paths, store, mgr); err != nil {
		fmt.Fprintf(w, "warning: failed to restart agent: %v\n", err)
	}

	return nil
}
