package update

import (
	"strconv"
	"strings"
)

// CompareVersions compares two semver strings.
// Strips leading "v" prefix and compares MAJOR.MINOR.PATCH numerically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Malformed versions are treated as 0.0.0.
func CompareVersions(a, b string) int {
	aParts := parseVersion(a)
	bParts := parseVersion(b)

	for i := range 3 {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

// parseVersion splits a version string into [major, minor, patch].
func parseVersion(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)

	var result [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		// Strip any pre-release suffix (e.g., "1.0.0-rc1" → "1.0.0")
		clean := strings.SplitN(parts[i], "-", 2)[0]
		n, err := strconv.Atoi(clean)
		if err == nil && n >= 0 {
			result[i] = n
		}
	}
	return result
}
