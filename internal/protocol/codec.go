package protocol

import (
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// MaxMessageSize is the maximum size in bytes for an incoming protocol message.
// Terminal I/O data is typically < 4KB. This limit provides defense-in-depth
// against malicious or malformed messages causing memory exhaustion.
// The WebRTC DataChannel has its own limits, but validating here catches issues
// regardless of transport.
const MaxMessageSize = 1 << 20 // 1 MiB

// messageEnvelope is used to extract the type field for dispatching.
type messageEnvelope struct {
	Type string `msgpack:"type"`
}

// Encode serializes a protocol message to MessagePack binary.
func Encode(msg Message) ([]byte, error) {
	data, err := msgpack.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", msg.MessageType(), err)
	}
	return data, nil
}

// Decode deserializes MessagePack binary to a protocol message.
// It inspects the "type" field first, then decodes into the correct Go struct.
// Returns an error if the message exceeds MaxMessageSize.
func Decode(data []byte) (Message, error) {
	if len(data) > MaxMessageSize {
		return nil, fmt.Errorf("decode: message size %d exceeds maximum %d", len(data), MaxMessageSize)
	}

	var env messageEnvelope
	if err := msgpack.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}

	if env.Type == "" {
		return nil, fmt.Errorf("decode: missing or empty \"type\" field")
	}

	var msg Message
	switch env.Type {
	// Requests (Mobile → Host)
	case "list_sessions":
		msg = &ListSessionsRequest{}
	case "attach":
		msg = &AttachRequest{}
	case "detach":
		msg = &DetachRequest{}
	case "input":
		msg = &InputRequest{}
	case "resize":
		msg = &ResizeRequest{}
	case "kill_session":
		msg = &KillSessionRequest{}
	case "ping":
		msg = &PingRequest{}
	case "create_session":
		msg = &CreateSessionRequest{}

	// Events (Host → Mobile)
	case "sessions":
		msg = &SessionsEvent{}
	case "output":
		msg = &OutputEvent{}
	case "attached":
		msg = &AttachedEvent{}
	case "detached":
		msg = &DetachedEvent{}
	case "session_ended":
		msg = &SessionEndedEvent{}
	case "pane_closed":
		msg = &PaneClosedEvent{}
	case "session_created":
		msg = &SessionCreatedEvent{}
	case "error":
		msg = &ErrorEvent{}
	case "pong":
		msg = &PongEvent{}

	default:
		return nil, fmt.Errorf("decode: unknown message type %q", env.Type)
	}

	if err := msgpack.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("decode %s: %w", env.Type, err)
	}

	return msg, nil
}

// IsRequest returns true if the message is a Mobile → Host request.
func IsRequest(msg Message) bool {
	switch msg.(type) {
	case *ListSessionsRequest, *AttachRequest, *DetachRequest,
		*InputRequest, *ResizeRequest,
		*KillSessionRequest, *CreateSessionRequest, *PingRequest:
		return true
	}
	return false
}

// IsEvent returns true if the message is a Host → Mobile event.
func IsEvent(msg Message) bool {
	switch msg.(type) {
	case *SessionsEvent, *OutputEvent, *AttachedEvent, *DetachedEvent,
		*SessionEndedEvent, *PaneClosedEvent, *SessionCreatedEvent, *ErrorEvent, *PongEvent:
		return true
	}
	return false
}
