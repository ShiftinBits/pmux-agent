package agent

import (
	"slices"
	"testing"
)

func TestCaffeinateArgs(t *testing.T) {
	// -i prevents idle system sleep; -w ties the helper's lifetime to the
	// agent PID so it self-exits if the agent dies without a clean shutdown.
	got := caffeinateArgs(4242)
	want := []string{"-i", "-w", "4242"}
	if !slices.Equal(got, want) {
		t.Errorf("caffeinateArgs(4242) = %v, want %v", got, want)
	}
}

func TestIsWSL(t *testing.T) {
	tests := []struct {
		name        string
		procVersion string
		want        bool
	}{
		{
			name:        "WSL2 kernel",
			procVersion: "Linux version 5.15.90.1-microsoft-standard-WSL2 (oe-user@oe-host) ...",
			want:        true,
		},
		{
			name:        "WSL1 Microsoft marker",
			procVersion: "Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com) ...",
			want:        true,
		},
		{
			name:        "bare metal Linux",
			procVersion: "Linux version 6.8.0-45-generic (buildd@lcy02) ...",
			want:        false,
		},
		{
			name:        "empty (unreadable /proc/version)",
			procVersion: "",
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWSL(tt.procVersion); got != tt.want {
				t.Errorf("isWSL(%q) = %v, want %v", tt.procVersion, got, tt.want)
			}
		})
	}
}
