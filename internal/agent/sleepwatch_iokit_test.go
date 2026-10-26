package agent

import (
	"io"
	"log/slog"
	"slices"
	"testing"
)

func TestHandlePowerMessage(t *testing.T) {
	const arg uintptr = 0x1234

	tests := []struct {
		name    string
		msgType uint32
		want    []string
	}{
		{"can system sleep is allowed, never vetoed", kIOMessageCanSystemSleep, []string{"allow"}},
		{"will sleep runs onSleep before allowing", kIOMessageSystemWillSleep, []string{"sleep", "allow"}},
		{"has powered on resumes", kIOMessageSystemHasPoweredOn, []string{"resume"}},
		{"will power on is ignored", kIOMessageSystemWillPowerOn, nil},
		{"will not sleep is ignored", kIOMessageSystemWillNotSleep, nil},
		{"unrelated message is ignored", 0xE0000340, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			onSleep := func() { got = append(got, "sleep") }
			onResume := func() { got = append(got, "resume") }
			allow := func(a uintptr) {
				if a != arg {
					t.Errorf("allow called with %#x, want %#x", a, arg)
				}
				got = append(got, "allow")
			}

			handlePowerMessage(tt.msgType, arg, onSleep, onResume, allow, slog.New(slog.NewTextHandler(io.Discard, nil)))

			if !slices.Equal(got, tt.want) {
				t.Errorf("calls = %v, want %v", got, tt.want)
			}
		})
	}
}
