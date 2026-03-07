package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// --- Round-trip tests for every HostRequest type ---

func TestRoundTripListSessions(t *testing.T) {
	msg := &ListSessionsRequest{Type: "list_sessions"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*ListSessionsRequest)
	if !ok {
		t.Fatalf("expected *ListSessionsRequest, got %T", decoded)
	}
	if got.Type != "list_sessions" {
		t.Errorf("type = %q, want %q", got.Type, "list_sessions")
	}
}

func TestRoundTripAttach(t *testing.T) {
	msg := &AttachRequest{Type: "attach", PaneID: "%3", Cols: 120, Rows: 40}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*AttachRequest)
	if !ok {
		t.Fatalf("expected *AttachRequest, got %T", decoded)
	}
	if got.PaneID != "%3" || got.Cols != 120 || got.Rows != 40 {
		t.Errorf("got %+v, want paneId=%%3 cols=120 rows=40", got)
	}
}

func TestRoundTripAttachReattach(t *testing.T) {
	msg := &AttachRequest{Type: "attach", PaneID: "%3", Cols: 120, Rows: 40, Reattach: true}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*AttachRequest)
	if !ok {
		t.Fatalf("expected *AttachRequest, got %T", decoded)
	}
	if got.PaneID != "%3" || got.Cols != 120 || got.Rows != 40 {
		t.Errorf("got %+v, want paneId=%%3 cols=120 rows=40", got)
	}
	if !got.Reattach {
		t.Error("expected Reattach=true, got false")
	}
}

func TestRoundTripDetach(t *testing.T) {
	msg := &DetachRequest{Type: "detach"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := decoded.(*DetachRequest); !ok {
		t.Fatalf("expected *DetachRequest, got %T", decoded)
	}
}

func TestRoundTripInput(t *testing.T) {
	inputData := []byte{0x1b, 0x5b, 0x41, 0x0a, 0xff, 0x00}
	msg := &InputRequest{Type: "input", Data: inputData}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*InputRequest)
	if !ok {
		t.Fatalf("expected *InputRequest, got %T", decoded)
	}
	if len(got.Data) != len(inputData) {
		t.Fatalf("data length = %d, want %d", len(got.Data), len(inputData))
	}
	for i, b := range got.Data {
		if b != inputData[i] {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, b, inputData[i])
		}
	}
}

func TestRoundTripResize(t *testing.T) {
	msg := &ResizeRequest{Type: "resize", Cols: 200, Rows: 50}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*ResizeRequest)
	if !ok {
		t.Fatalf("expected *ResizeRequest, got %T", decoded)
	}
	if got.Cols != 200 || got.Rows != 50 {
		t.Errorf("got cols=%d rows=%d, want 200,50", got.Cols, got.Rows)
	}
}

func TestRoundTripKillSession(t *testing.T) {
	msg := &KillSessionRequest{Type: "kill_session", Session: "$2"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*KillSessionRequest)
	if !ok {
		t.Fatalf("expected *KillSessionRequest, got %T", decoded)
	}
	if got.Session != "$2" {
		t.Errorf("session = %q, want %q", got.Session, "$2")
	}
}

func TestRoundTripPing(t *testing.T) {
	msg := &PingRequest{Type: "ping"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := decoded.(*PingRequest); !ok {
		t.Fatalf("expected *PingRequest, got %T", decoded)
	}
}

// --- Round-trip tests for every HostEvent type ---

func TestRoundTripSessions(t *testing.T) {
	msg := &SessionsEvent{
		Type: "sessions",
		Sessions: []TmuxSession{
			{
				ID:      "$1",
				Name:    "dev",
				CreatedAt: 1708700000,
				Windows: []TmuxWindow{
					{
						ID:     "@1",
						Name:   "main",
						Index:  0,
						Active: true,
						Panes: []TmuxPane{
							{
								ID:             "%1",
								Index:          0,
								Active:         true,
								Size:           PaneSize{Cols: 80, Rows: 24},
								Title:          "bash",
								CurrentCommand: "zsh",
							},
						},
					},
				},
				LastActivityAt: 1708700100,
				Attached:     false,
			},
		},
	}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*SessionsEvent)
	if !ok {
		t.Fatalf("expected *SessionsEvent, got %T", decoded)
	}
	if len(got.Sessions) != 1 {
		t.Fatalf("sessions count = %d, want 1", len(got.Sessions))
	}
	s := got.Sessions[0]
	if s.ID != "$1" || s.Name != "dev" || s.CreatedAt != 1708700000 {
		t.Errorf("session = %+v", s)
	}
	if len(s.Windows) != 1 {
		t.Fatalf("windows count = %d, want 1", len(s.Windows))
	}
	w := s.Windows[0]
	if w.ID != "@1" || w.Name != "main" || !w.Active {
		t.Errorf("window = %+v", w)
	}
	if len(w.Panes) != 1 {
		t.Fatalf("panes count = %d, want 1", len(w.Panes))
	}
	p := w.Panes[0]
	if p.ID != "%1" || p.Size.Cols != 80 || p.Size.Rows != 24 || p.CurrentCommand != "zsh" {
		t.Errorf("pane = %+v", p)
	}
}

func TestRoundTripSessionsEmpty(t *testing.T) {
	msg := &SessionsEvent{Type: "sessions", Sessions: []TmuxSession{}}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*SessionsEvent)
	if !ok {
		t.Fatalf("expected *SessionsEvent, got %T", decoded)
	}
	if len(got.Sessions) != 0 {
		t.Errorf("sessions count = %d, want 0", len(got.Sessions))
	}
}

func TestRoundTripOutput(t *testing.T) {
	outputData := []byte{0x1b, 0x5b, 0x33, 0x32, 0x6d, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	msg := &OutputEvent{Type: "output", Data: outputData}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*OutputEvent)
	if !ok {
		t.Fatalf("expected *OutputEvent, got %T", decoded)
	}
	if len(got.Data) != len(outputData) {
		t.Fatalf("data length = %d, want %d", len(got.Data), len(outputData))
	}
	for i, b := range got.Data {
		if b != outputData[i] {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, b, outputData[i])
		}
	}
}

func TestRoundTripAttached(t *testing.T) {
	msg := &AttachedEvent{Type: "attached", PaneID: "%5"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*AttachedEvent)
	if !ok {
		t.Fatalf("expected *AttachedEvent, got %T", decoded)
	}
	if got.PaneID != "%5" {
		t.Errorf("paneId = %q, want %%5", got.PaneID)
	}
}

func TestRoundTripDetached(t *testing.T) {
	msg := &DetachedEvent{Type: "detached"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := decoded.(*DetachedEvent); !ok {
		t.Fatalf("expected *DetachedEvent, got %T", decoded)
	}
}

func TestRoundTripSessionEnded(t *testing.T) {
	msg := &SessionEndedEvent{Type: "session_ended", Session: "$3"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*SessionEndedEvent)
	if !ok {
		t.Fatalf("expected *SessionEndedEvent, got %T", decoded)
	}
	if got.Session != "$3" {
		t.Errorf("session = %q, want %q", got.Session, "$3")
	}
}

func TestRoundTripPaneClosed(t *testing.T) {
	msg := &PaneClosedEvent{Type: "pane_closed", PaneID: "%7"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*PaneClosedEvent)
	if !ok {
		t.Fatalf("expected *PaneClosedEvent, got %T", decoded)
	}
	if got.PaneID != "%7" {
		t.Errorf("paneId = %q, want %%7", got.PaneID)
	}
}

func TestRoundTripError(t *testing.T) {
	msg := &ErrorEvent{Type: "error", Code: "PANE_NOT_FOUND", Message: "Pane %99 does not exist"}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*ErrorEvent)
	if !ok {
		t.Fatalf("expected *ErrorEvent, got %T", decoded)
	}
	if got.Code != "PANE_NOT_FOUND" || got.Message != "Pane %99 does not exist" {
		t.Errorf("got %+v", got)
	}
}

func TestRoundTripPong(t *testing.T) {
	msg := &PongEvent{Type: "pong", Latency: 42}
	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := decoded.(*PongEvent)
	if !ok {
		t.Fatalf("expected *PongEvent, got %T", decoded)
	}
	if got.Latency != 42 {
		t.Errorf("latency = %d, want 42", got.Latency)
	}
}

// --- Binary data integrity ---

func TestBinaryIntegrity256(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	msg := &InputRequest{Type: "input", Data: data}
	encoded, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := decoded.(*InputRequest)
	if len(got.Data) != 256 {
		t.Fatalf("data length = %d, want 256", len(got.Data))
	}
	for i, b := range got.Data {
		if b != byte(i) {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, b, byte(i))
		}
	}
}

func TestBinaryIntegrity1024(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	msg := &OutputEvent{Type: "output", Data: data}
	encoded, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := decoded.(*OutputEvent)
	if len(got.Data) != 1024 {
		t.Fatalf("data length = %d, want 1024", len(got.Data))
	}
}

func TestBinaryEmptyData(t *testing.T) {
	msg := &InputRequest{Type: "input", Data: []byte{}}
	encoded, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := decoded.(*InputRequest)
	if len(got.Data) != 0 {
		t.Errorf("data length = %d, want 0", len(got.Data))
	}
}

// --- Type guards ---

func TestIsRequest(t *testing.T) {
	requests := []Message{
		&ListSessionsRequest{Type: "list_sessions"},
		&AttachRequest{Type: "attach"},
		&DetachRequest{Type: "detach"},
		&InputRequest{Type: "input"},
		&ResizeRequest{Type: "resize"},
		&KillSessionRequest{Type: "kill_session"},
		&PingRequest{Type: "ping"},
	}
	for _, msg := range requests {
		if !IsRequest(msg) {
			t.Errorf("IsRequest(%T) = false, want true", msg)
		}
		if IsEvent(msg) {
			t.Errorf("IsEvent(%T) = true, want false", msg)
		}
	}
}

func TestIsEvent(t *testing.T) {
	events := []Message{
		&SessionsEvent{Type: "sessions"},
		&OutputEvent{Type: "output"},
		&AttachedEvent{Type: "attached"},
		&DetachedEvent{Type: "detached"},
		&SessionEndedEvent{Type: "session_ended"},
		&PaneClosedEvent{Type: "pane_closed"},
		&ErrorEvent{Type: "error"},
		&PongEvent{Type: "pong"},
	}
	for _, msg := range events {
		if !IsEvent(msg) {
			t.Errorf("IsEvent(%T) = false, want true", msg)
		}
		if IsRequest(msg) {
			t.Errorf("IsRequest(%T) = true, want false", msg)
		}
	}
}

// --- Error handling ---

func TestDecodeEmptyData(t *testing.T) {
	_, err := Decode([]byte{})
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestDecodeMalformedData(t *testing.T) {
	_, err := Decode([]byte{0xff, 0xfe, 0xfd})
	if err == nil {
		t.Error("expected error for malformed data")
	}
}

func TestDecodeUnknownType(t *testing.T) {
	// Manually encode a map with an unknown type using msgpack
	unknown := struct {
		Type string `msgpack:"type"`
	}{Type: "unknown_msg"}
	data, err := msgpack.Marshal(&unknown)
	if err != nil {
		t.Fatalf("marshal unknown: %v", err)
	}
	_, err = Decode(data)
	if err == nil {
		t.Error("expected error for unknown type")
	}
	if !strings.Contains(err.Error(), "unknown message type") {
		t.Errorf("error = %q, want containing 'unknown message type'", err.Error())
	}
}

// --- Cross-language fixture tests ---

// fixturesDir returns the path to the TypeScript-generated fixture files.
func fixturesDir() string {
	// Navigate from packages/agent/internal/protocol/ to packages/shared/src/__tests__/fixtures/
	return filepath.Join("..", "..", "..", "shared", "src", "__tests__", "fixtures")
}

// fixtureJSON represents the JSON companion file for a fixture.
// The "data" field for binary messages is an array of integers.
type fixtureJSON struct {
	Type           string        `json:"type"`
	PaneID         string        `json:"paneId,omitempty"`
	Cols           *int          `json:"cols,omitempty"`
	Rows           *int          `json:"rows,omitempty"`
	Reattach       *bool         `json:"reattach,omitempty"`
	Data           []int         `json:"data,omitempty"`
	Name           *string       `json:"name,omitempty"`
	Command        *string       `json:"command,omitempty"`
	Session        string        `json:"session,omitempty"`
	Sessions       []interface{} `json:"sessions,omitempty"`
	Code           string        `json:"code,omitempty"`
	Message        string        `json:"message,omitempty"`
	Latency        *int          `json:"latency,omitempty"`
}

func TestCrossLanguageFixtures(t *testing.T) {
	dir := fixturesDir()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixtures dir not found (standalone checkout?): %s", dir)
		}
		t.Fatalf("read fixtures dir %s: %v", dir, err)
	}

	msgpackFiles := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".msgpack") {
			continue
		}
		msgpackFiles++
		name := strings.TrimSuffix(entry.Name(), ".msgpack")

		t.Run(name, func(t *testing.T) {
			// Load the msgpack fixture
			msgpackData, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("read msgpack: %v", err)
			}

			// Load the JSON companion
			jsonData, err := os.ReadFile(filepath.Join(dir, name+".json"))
			if err != nil {
				t.Fatalf("read json: %v", err)
			}

			var expected fixtureJSON
			if err := json.Unmarshal(jsonData, &expected); err != nil {
				t.Fatalf("parse json: %v", err)
			}

			// Decode the msgpack fixture using our Go codec
			msg, err := Decode(msgpackData)
			if err != nil {
				t.Fatalf("decode msgpack fixture: %v", err)
			}

			// Verify the type matches
			if msg.MessageType() != expected.Type {
				t.Errorf("type = %q, want %q", msg.MessageType(), expected.Type)
			}

			// Verify specific fields based on type
			verifyFixtureFields(t, msg, expected)
		})
	}

	if msgpackFiles == 0 {
		t.Fatal("no .msgpack fixture files found — run 'pnpm fixtures' in packages/shared")
	}

	t.Logf("verified %d cross-language fixtures", msgpackFiles)
}

func verifyFixtureFields(t *testing.T, msg Message, expected fixtureJSON) {
	t.Helper()

	switch m := msg.(type) {
	case *AttachRequest:
		if m.PaneID != expected.PaneID {
			t.Errorf("paneId = %q, want %q", m.PaneID, expected.PaneID)
		}
		if expected.Cols != nil && m.Cols != *expected.Cols {
			t.Errorf("cols = %d, want %d", m.Cols, *expected.Cols)
		}
		if expected.Rows != nil && m.Rows != *expected.Rows {
			t.Errorf("rows = %d, want %d", m.Rows, *expected.Rows)
		}
		if expected.Reattach != nil && m.Reattach != *expected.Reattach {
			t.Errorf("reattach = %v, want %v", m.Reattach, *expected.Reattach)
		}

	case *InputRequest:
		verifyBinaryData(t, m.Data, expected.Data)

	case *ResizeRequest:
		if expected.Cols != nil && m.Cols != *expected.Cols {
			t.Errorf("cols = %d, want %d", m.Cols, *expected.Cols)
		}
		if expected.Rows != nil && m.Rows != *expected.Rows {
			t.Errorf("rows = %d, want %d", m.Rows, *expected.Rows)
		}

	case *KillSessionRequest:
		if m.Session != expected.Session {
			t.Errorf("session = %q, want %q", m.Session, expected.Session)
		}

	case *SessionsEvent:
		// For sessions, verify the structure was decoded (detailed check below)
		if expected.Sessions != nil && len(m.Sessions) != len(expected.Sessions) {
			t.Errorf("sessions count = %d, want %d", len(m.Sessions), len(expected.Sessions))
		}

	case *OutputEvent:
		verifyBinaryData(t, m.Data, expected.Data)

	case *AttachedEvent:
		if m.PaneID != expected.PaneID {
			t.Errorf("paneId = %q, want %q", m.PaneID, expected.PaneID)
		}

	case *SessionEndedEvent:
		if m.Session != expected.Session {
			t.Errorf("session = %q, want %q", m.Session, expected.Session)
		}

	case *PaneClosedEvent:
		if m.PaneID != expected.PaneID {
			t.Errorf("paneId = %q, want %q", m.PaneID, expected.PaneID)
		}

	case *ErrorEvent:
		if m.Code != expected.Code {
			t.Errorf("code = %q, want %q", m.Code, expected.Code)
		}
		if m.Message != expected.Message {
			t.Errorf("message = %q, want %q", m.Message, expected.Message)
		}

	case *PongEvent:
		if expected.Latency != nil && m.Latency != *expected.Latency {
			t.Errorf("latency = %d, want %d", m.Latency, *expected.Latency)
		}
	}
}

// TestGoEncodedSessionsHasMapKeys verifies that Go-encoded SessionsEvent
// uses msgpack map encoding with the field names that the TypeScript
// @msgpack/msgpack decoder expects. This is the Go→TypeScript direction
// which is NOT covered by the cross-language fixture tests (those test TS→Go).
func TestGoEncodedSessionsHasMapKeys(t *testing.T) {
	msg := &SessionsEvent{
		Type: "sessions",
		Sessions: []TmuxSession{
			{
				ID:      "$0",
				Name:    "work",
				CreatedAt: 1708700000,
				Windows: []TmuxWindow{
					{
						ID:     "@0",
						Name:   "editor",
						Index:  0,
						Active: true,
						Panes: []TmuxPane{
							{
								ID:             "%0",
								Index:          0,
								Active:         true,
								Size:           PaneSize{Cols: 80, Rows: 24},
								Title:          "vim",
								CurrentCommand: "vim",
							},
						},
					},
				},
				LastActivityAt: 1708700100,
				Attached:     false,
			},
			{
				ID:      "$1",
				Name:    "shell",
				CreatedAt: 1708700200,
				Windows: []TmuxWindow{
					{
						ID:     "@1",
						Name:   "main",
						Index:  0,
						Active: true,
						Panes: []TmuxPane{
							{
								ID:             "%1",
								Index:          0,
								Active:         true,
								Size:           PaneSize{Cols: 120, Rows: 40},
								Title:          "zsh",
								CurrentCommand: "zsh",
							},
						},
					},
				},
				LastActivityAt: 1708700300,
				Attached:     true,
			},
		},
	}

	data, err := Encode(msg)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Decode using raw msgpack into a generic map to verify field names
	var raw map[string]interface{}
	if err := msgpack.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to raw map: %v", err)
	}

	// Verify top-level fields
	if raw["type"] != "sessions" {
		t.Errorf("type = %v, want 'sessions'", raw["type"])
	}

	sessions, ok := raw["sessions"].([]interface{})
	if !ok {
		t.Fatalf("sessions field is %T, want []interface{}", raw["sessions"])
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions count = %d, want 2", len(sessions))
	}

	// Verify first session has correct field names (camelCase matching TS)
	s0, ok := sessions[0].(map[string]interface{})
	if !ok {
		t.Fatalf("session[0] is %T, want map[string]interface{}", sessions[0])
	}

	expectedSessionKeys := []string{"id", "name", "createdAt", "windows", "lastActivityAt", "attached"}
	for _, key := range expectedSessionKeys {
		if _, exists := s0[key]; !exists {
			t.Errorf("session[0] missing key %q (keys: %v)", key, mapKeys(s0))
		}
	}

	// Verify windows → panes nesting
	windows, ok := s0["windows"].([]interface{})
	if !ok || len(windows) == 0 {
		t.Fatalf("session[0].windows is %T (len %v)", s0["windows"], len(windows))
	}
	w0, ok := windows[0].(map[string]interface{})
	if !ok {
		t.Fatalf("window[0] is %T, want map[string]interface{}", windows[0])
	}

	expectedWindowKeys := []string{"id", "name", "index", "active", "panes"}
	for _, key := range expectedWindowKeys {
		if _, exists := w0[key]; !exists {
			t.Errorf("window[0] missing key %q (keys: %v)", key, mapKeys(w0))
		}
	}

	panes, ok := w0["panes"].([]interface{})
	if !ok || len(panes) == 0 {
		t.Fatalf("window[0].panes is %T (len %v)", w0["panes"], len(panes))
	}
	p0, ok := panes[0].(map[string]interface{})
	if !ok {
		t.Fatalf("pane[0] is %T, want map[string]interface{}", panes[0])
	}

	expectedPaneKeys := []string{"id", "index", "active", "size", "title", "currentCommand"}
	for _, key := range expectedPaneKeys {
		if _, exists := p0[key]; !exists {
			t.Errorf("pane[0] missing key %q (keys: %v)", key, mapKeys(p0))
		}
	}

	// Verify size sub-object
	size, ok := p0["size"].(map[string]interface{})
	if !ok {
		t.Fatalf("pane[0].size is %T, want map[string]interface{}", p0["size"])
	}
	if _, exists := size["cols"]; !exists {
		t.Errorf("size missing 'cols' key")
	}
	if _, exists := size["rows"]; !exists {
		t.Errorf("size missing 'rows' key")
	}

	t.Logf("Go-encoded SessionsEvent uses correct map keys for TypeScript compatibility")
}

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func verifyBinaryData(t *testing.T, got []byte, expected []int) {
	t.Helper()
	if len(got) != len(expected) {
		t.Errorf("data length = %d, want %d", len(got), len(expected))
		return
	}
	for i, b := range got {
		if int(b) != expected[i] {
			t.Errorf("data[%d] = 0x%02x, want 0x%02x", i, b, expected[i])
		}
	}
}
