package update

import "testing"

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"equal", "1.0.0", "1.0.0", 0},
		{"a greater major", "2.0.0", "1.0.0", 1},
		{"b greater major", "1.0.0", "2.0.0", -1},
		{"a greater minor", "1.2.0", "1.1.0", 1},
		{"b greater minor", "1.1.0", "1.2.0", -1},
		{"a greater patch", "1.0.2", "1.0.1", 1},
		{"b greater patch", "1.0.1", "1.0.2", -1},
		{"v prefix a", "v1.2.3", "1.2.3", 0},
		{"v prefix b", "1.2.3", "v1.2.3", 0},
		{"v prefix both", "v1.2.3", "v1.2.3", 0},
		{"pre-release stripped", "1.0.0-rc1", "1.0.0", 0},
		{"missing patch", "1.0", "1.0.0", 0},
		{"missing minor+patch", "1", "1.0.0", 0},
		{"empty string", "", "1.0.0", -1},
		{"both empty", "", "", 0},
		{"malformed", "abc", "1.0.0", -1},
		{"large version", "10.20.300", "10.20.299", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareVersions(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
