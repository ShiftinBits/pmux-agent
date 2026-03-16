package update

import "testing"

func TestDetect_DevBuild(t *testing.T) {
	got := Detect("dev")
	if got != MethodDev {
		t.Errorf("Detect(\"dev\") = %q, want %q", got, MethodDev)
	}
}

func TestDetect_EmptyBuildMethod(t *testing.T) {
	// With empty buildMethod on a dev machine, should fall through to
	// runtime detection. The exact result depends on the system but
	// should not be "dev".
	got := Detect("")
	if got == MethodDev {
		t.Error("Detect(\"\") should not return MethodDev")
	}
}

func TestInstallMethod_String(t *testing.T) {
	tests := []struct {
		method InstallMethod
		want   string
	}{
		{MethodDev, "development build"},
		{MethodSnap, "Snap Store"},
		{MethodDeb, "Debian package (dpkg)"},
		{MethodRPM, "RPM package"},
		{MethodHomebrew, "Homebrew"},
		{MethodGitHub, "GitHub Releases (direct binary)"},
	}
	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			if got := tt.method.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInstallMethod_HasUpdatePath(t *testing.T) {
	tests := []struct {
		method InstallMethod
		want   bool
	}{
		{MethodDev, false},
		{MethodSnap, true},
		{MethodDeb, true},
		{MethodRPM, true},
		{MethodHomebrew, true},
		{MethodGitHub, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.method), func(t *testing.T) {
			if got := tt.method.HasUpdatePath(); got != tt.want {
				t.Errorf("HasUpdatePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetect_SnapPath(t *testing.T) {
	// Override executablePath to simulate a snap-installed binary.
	original := executablePath
	executablePath = func() (string, error) {
		return "/snap/pmux/42/bin/pmux", nil
	}
	defer func() { executablePath = original }()

	got := Detect("")
	if got != MethodSnap {
		t.Errorf("Detect() with snap path = %q, want %q", got, MethodSnap)
	}
}

func TestDetect_HomebrewPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"Cellar", "/usr/local/Cellar/pmux/1.0.0/bin/pmux"},
		{"opt/homebrew", "/opt/homebrew/Cellar/pmux/1.0.0/bin/pmux"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := executablePath
			executablePath = func() (string, error) {
				return tt.path, nil
			}
			defer func() { executablePath = original }()

			got := Detect("")
			if got != MethodHomebrew {
				t.Errorf("Detect() with path %q = %q, want %q", tt.path, got, MethodHomebrew)
			}
		})
	}
}
