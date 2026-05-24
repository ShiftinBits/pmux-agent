package protocol

import (
	"strings"
	"testing"
)

func TestAttachRequestValidate(t *testing.T) {
	maxID := strings.Repeat("a", MaxStringIDLength)
	tooLongID := strings.Repeat("a", MaxStringIDLength+1)
	tests := []struct {
		name    string
		msg     *AttachRequest
		wantErr bool
	}{
		{"valid min dimensions", &AttachRequest{PaneID: "%1", Cols: MinDimension, Rows: MinDimension}, false},
		{"valid max dimensions", &AttachRequest{PaneID: "%1", Cols: MaxDimension, Rows: MaxDimension}, false},
		{"valid max paneId", &AttachRequest{PaneID: maxID, Cols: 80, Rows: 24}, false},
		{"cols below min", &AttachRequest{PaneID: "%1", Cols: MinDimension - 1, Rows: 24}, true},
		{"cols above max", &AttachRequest{PaneID: "%1", Cols: MaxDimension + 1, Rows: 24}, true},
		{"rows below min", &AttachRequest{PaneID: "%1", Cols: 80, Rows: MinDimension - 1}, true},
		{"rows above max", &AttachRequest{PaneID: "%1", Cols: 80, Rows: MaxDimension + 1}, true},
		{"paneId too long", &AttachRequest{PaneID: tooLongID, Cols: 80, Rows: 24}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.msg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInputRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"empty", 0, false},
		{"at max", MaxInputSize, false},
		{"over max", MaxInputSize + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &InputRequest{Type: "input", Data: make([]byte, tt.size)}
			if err := msg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResizeRequestValidate(t *testing.T) {
	tests := []struct {
		name    string
		msg     *ResizeRequest
		wantErr bool
	}{
		{"valid min", &ResizeRequest{Cols: MinDimension, Rows: MinDimension}, false},
		{"valid max", &ResizeRequest{Cols: MaxDimension, Rows: MaxDimension}, false},
		{"cols below min", &ResizeRequest{Cols: MinDimension - 1, Rows: 24}, true},
		{"cols above max", &ResizeRequest{Cols: MaxDimension + 1, Rows: 24}, true},
		{"rows below min", &ResizeRequest{Cols: 80, Rows: MinDimension - 1}, true},
		{"rows above max", &ResizeRequest{Cols: 80, Rows: MaxDimension + 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.msg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKillSessionRequestValidate(t *testing.T) {
	if err := (&KillSessionRequest{Session: strings.Repeat("s", MaxStringIDLength)}).Validate(); err != nil {
		t.Errorf("max-length session should be valid, got %v", err)
	}
	if err := (&KillSessionRequest{Session: strings.Repeat("s", MaxStringIDLength+1)}).Validate(); err == nil {
		t.Error("over-length session should be rejected")
	}
}

func TestOutputEventValidate(t *testing.T) {
	if err := (&OutputEvent{Data: make([]byte, MaxOutputSize)}).Validate(); err != nil {
		t.Errorf("max-size output should be valid, got %v", err)
	}
	if err := (&OutputEvent{Data: make([]byte, MaxOutputSize+1)}).Validate(); err == nil {
		t.Error("over-size output should be rejected")
	}
}

func TestStringIDEventValidate(t *testing.T) {
	maxID := strings.Repeat("x", MaxStringIDLength)
	tooLong := strings.Repeat("x", MaxStringIDLength+1)
	tests := []struct {
		name    string
		msg     Validatable
		wantErr bool
	}{
		{"attached valid", &AttachedEvent{PaneID: maxID}, false},
		{"attached too long", &AttachedEvent{PaneID: tooLong}, true},
		{"session_ended valid", &SessionEndedEvent{Session: maxID}, false},
		{"session_ended too long", &SessionEndedEvent{Session: tooLong}, true},
		{"pane_closed valid", &PaneClosedEvent{PaneID: maxID}, false},
		{"pane_closed too long", &PaneClosedEvent{PaneID: tooLong}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.msg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrorEventValidate(t *testing.T) {
	maxCode := strings.Repeat("c", MaxErrorCodeLength)
	maxMsg := strings.Repeat("m", MaxErrorMessageLength)
	tests := []struct {
		name    string
		msg     *ErrorEvent
		wantErr bool
	}{
		{"valid at limits", &ErrorEvent{Code: maxCode, Message: maxMsg}, false},
		{"code too long", &ErrorEvent{Code: maxCode + "c", Message: "ok"}, true},
		{"message too long", &ErrorEvent{Code: "OK", Message: maxMsg + "m"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.msg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPongEventValidate(t *testing.T) {
	tests := []struct {
		name    string
		latency int
		wantErr bool
	}{
		{"zero", 0, false},
		{"positive", 42, false},
		{"negative", -1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := (&PongEvent{Latency: tt.latency}).Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDecodeRejectsOutOfBounds covers the ticket's threat model end-to-end:
// a malicious client crafts a structurally valid message with out-of-bounds
// fields. Encode() does not validate, so these messages are well-formed on the
// wire; Decode() must reject them before the values reach tmux or the PTY.
func TestDecodeRejectsOutOfBounds(t *testing.T) {
	tests := []struct {
		name    string
		msg     Message
		wantSub string
	}{
		{
			name:    "oversized dimensions",
			msg:     &AttachRequest{Type: "attach", PaneID: "%1", Cols: 99999, Rows: 99999},
			wantSub: `"cols"`,
		},
		{
			name:    "oversized input",
			msg:     &InputRequest{Type: "input", Data: make([]byte, MaxInputSize+1)},
			wantSub: `"data"`,
		},
		{
			name:    "oversized resize",
			msg:     &ResizeRequest{Type: "resize", Cols: 99999, Rows: 99999},
			wantSub: `"cols"`,
		},
		{
			name:    "over-long session name",
			msg:     &KillSessionRequest{Type: "kill_session", Session: strings.Repeat("s", MaxStringIDLength+1)},
			wantSub: `"session"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := Encode(tt.msg)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			_, err = Decode(data)
			if err == nil {
				t.Fatalf("Decode() accepted out-of-bounds message %T", tt.msg)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("Decode() error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

// TestDecodeAcceptsValid confirms in-bounds messages still decode, and that a
// field-less message type (no Validatable) is unaffected by the new check.
func TestDecodeAcceptsValid(t *testing.T) {
	valid := []Message{
		&AttachRequest{Type: "attach", PaneID: "%3", Cols: 120, Rows: 40},
		&InputRequest{Type: "input", Data: []byte("ls -la\n")},
		&ResizeRequest{Type: "resize", Cols: 200, Rows: 50},
		&KillSessionRequest{Type: "kill_session", Session: "$2"},
		&ListSessionsRequest{Type: "list_sessions"},
	}
	for _, msg := range valid {
		data, err := Encode(msg)
		if err != nil {
			t.Fatalf("Encode(%T) error = %v", msg, err)
		}
		if _, err := Decode(data); err != nil {
			t.Errorf("Decode(%T) rejected a valid message: %v", msg, err)
		}
	}
}
