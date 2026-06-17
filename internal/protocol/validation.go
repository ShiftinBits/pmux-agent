package protocol

import "fmt"

// Field-level validation bounds for incoming protocol messages.
//
// The agent is the security boundary for messages arriving from untrusted
// mobile clients over the WebRTC DataChannel. These constants MUST stay in
// sync with the TypeScript codec in @pocketmux/shared (src/codec.ts) so that
// both ends of the wire enforce identical limits. A change here requires a
// corresponding change there (and vice versa).
//
// MaxMessageSize (the overall envelope limit) is defined in codec.go.
const (
	// MaxStringIDLength bounds session/pane/window IDs and names that are
	// ultimately passed to the tmux CLI as -t arguments.
	MaxStringIDLength = 255
	// MaxErrorCodeLength bounds the code field of an error event.
	MaxErrorCodeLength = 255
	// MaxErrorMessageLength bounds the human-readable message of an error event.
	MaxErrorMessageLength = 4096
	// MaxInputSize bounds a single input message written to the PTY (16 KiB).
	MaxInputSize = 16 * 1024
	// MaxOutputSize bounds a single output message read from the PTY (1 MiB).
	// Equal to MaxMessageSize by design (matches @pocketmux/shared): an output
	// event whose payload exceeds this is rejected by the envelope size check
	// in Decode() before Validate() can run, so OutputEvent.Validate() is
	// defense-in-depth (output events are also dropped by the IsRequest gate).
	MaxOutputSize = 1 << 20
	// MinDimension is the smallest allowed terminal dimension.
	MinDimension = 1
	// MaxDimension is the largest allowed terminal dimension.
	MaxDimension = 500
	// MaxAuthBlobLength bounds the base64-encoded auth nonce/mac strings. Both
	// are 32 bytes (HMAC-SHA256) → ~44 base64 chars; 128 gives headroom.
	// Matches MAX_AUTH_BLOB_LENGTH in @pocketmux/shared (src/codec.ts).
	MaxAuthBlobLength = 128
)

// Validatable is implemented by message types that carry fields requiring
// bounds checks. Decode() invokes Validate() after unmarshaling so that
// out-of-bounds messages are rejected before their contents reach tmux or the
// PTY. Field-less message types (e.g. list_sessions, ping) intentionally do
// not implement this interface, mirroring the no-op cases in the TypeScript
// validateFields() switch.
type Validatable interface {
	Validate() error
}

// validateStringLen reports an error if v exceeds max bytes.
//
// Length is measured in bytes (Go's len), not UTF-16 code units as in the
// TypeScript codec. For tmux IDs and names (effectively ASCII) the two are
// identical; for multibyte input the byte count is a stricter-or-equal bound,
// which is the security-relevant limit on the argument handed to the tmux CLI.
func validateStringLen(typ, field, v string, max int) error {
	if len(v) > max {
		return fmt.Errorf("%s: %q exceeds maximum length of %d", typ, field, max)
	}
	return nil
}

// validateDimension reports an error if v falls outside [MinDimension, MaxDimension].
func validateDimension(typ, field string, v int) error {
	if v < MinDimension || v > MaxDimension {
		return fmt.Errorf("%s: %q must be between %d and %d", typ, field, MinDimension, MaxDimension)
	}
	return nil
}

// validateByteSize reports an error if n exceeds max bytes.
func validateByteSize(typ, field string, n, max int) error {
	if n > max {
		return fmt.Errorf("%s: %q exceeds maximum size of %d bytes", typ, field, max)
	}
	return nil
}

// --- Mobile → Host (Requests): the primary security boundary ---
//
// The optional reattach/compression fields on attach (and compression on
// attached) are not range-checked: msgpack decodes them into statically typed
// Go fields (bool/string), which is the equivalent of the TypeScript typeof
// guards. A msgpack integer 0/1 would coerce to bool where TS rejects it, but
// that is a benign well-formedness divergence, not a security gap.

// Validate enforces bounds on an attach request.
func (m *AttachRequest) Validate() error {
	if err := validateStringLen("attach", "paneId", m.PaneID, MaxStringIDLength); err != nil {
		return err
	}
	if err := validateDimension("attach", "cols", m.Cols); err != nil {
		return err
	}
	return validateDimension("attach", "rows", m.Rows)
}

// Validate enforces bounds on an input request.
func (m *InputRequest) Validate() error {
	return validateByteSize("input", "data", len(m.Data), MaxInputSize)
}

// Validate enforces bounds on an auth-response request.
func (m *AuthResponseRequest) Validate() error {
	return validateStringLen("auth_response", "mac", m.Mac, MaxAuthBlobLength)
}

// Validate enforces bounds on a resize request.
func (m *ResizeRequest) Validate() error {
	if err := validateDimension("resize", "cols", m.Cols); err != nil {
		return err
	}
	return validateDimension("resize", "rows", m.Rows)
}

// Validate enforces bounds on a kill-session request.
func (m *KillSessionRequest) Validate() error {
	return validateStringLen("kill_session", "session", m.Session, MaxStringIDLength)
}

// --- Host → Mobile (Events) ---
//
// Events carry bounded fields and are validated to match the TypeScript
// validateFields() contract. The sessions and session_created events are
// intentionally omitted: TypeScript only asserts that their payloads are an
// array / object respectively (no length or nested-string bounds), and Go's
// static typing already guarantees those shapes ([]TmuxSession / TmuxSession).
// Adding bounds here would diverge from the shared contract rather than mirror
// it.

// Validate enforces bounds on an output event.
func (m *OutputEvent) Validate() error {
	return validateByteSize("output", "data", len(m.Data), MaxOutputSize)
}

// Validate enforces bounds on an attached event.
func (m *AttachedEvent) Validate() error {
	return validateStringLen("attached", "paneId", m.PaneID, MaxStringIDLength)
}

// Validate enforces bounds on a session-ended event.
func (m *SessionEndedEvent) Validate() error {
	return validateStringLen("session_ended", "session", m.Session, MaxStringIDLength)
}

// Validate enforces bounds on a pane-closed event.
func (m *PaneClosedEvent) Validate() error {
	return validateStringLen("pane_closed", "paneId", m.PaneID, MaxStringIDLength)
}

// Validate enforces bounds on an error event.
func (m *ErrorEvent) Validate() error {
	if err := validateStringLen("error", "code", m.Code, MaxErrorCodeLength); err != nil {
		return err
	}
	return validateStringLen("error", "message", m.Message, MaxErrorMessageLength)
}

// Validate enforces bounds on a pong event.
func (m *PongEvent) Validate() error {
	if m.Latency < 0 {
		return fmt.Errorf("pong: %q must be >= 0", "latency")
	}
	return nil
}
