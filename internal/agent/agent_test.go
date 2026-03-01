package agent

import (
	"sync"
)

// mockServerChecker is a thread-safe mock for serverChecker.
type mockServerChecker struct {
	mu      sync.Mutex
	running bool
}

func (m *mockServerChecker) IsServerRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *mockServerChecker) setRunning(running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = running
}

