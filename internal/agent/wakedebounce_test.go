package agent

import (
	"math/rand"
	"sync"
	"testing"
	"time"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func newTestDebouncer(delay time.Duration) (*wakeDebouncer, *eventLog) {
	log := &eventLog{}
	return newWakeDebouncer(delay, func() { log.add("sleep") }, func() { log.add("resume") }), log
}

func TestWakeDebounce(t *testing.T) {
	const delay = 20 * time.Millisecond

	tests := []struct {
		name string
		run  func(d *wakeDebouncer)
		want []string
	}{
		{"single wake resumes once", func(d *wakeDebouncer) { d.wake() }, []string{"resume"}},
		{"repeated wakes collapse", func(d *wakeDebouncer) {
			d.wake()
			d.wake()
			d.wake()
		}, []string{"resume"}},
		{"sleep within delay cancels resume", func(d *wakeDebouncer) {
			d.wake()
			d.sleep()
		}, []string{"sleep"}},
		{"stop within delay cancels resume", func(d *wakeDebouncer) {
			d.wake()
			d.stop()
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, log := newTestDebouncer(delay)
			tt.run(d)
			time.Sleep(delay * 5)
			got := log.snapshot()
			if len(got) != len(tt.want) {
				t.Fatalf("events = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("events = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestWakeDebounce_NoResumeAfterFinalSleep(t *testing.T) {
	const delay = time.Millisecond
	d, log := newTestDebouncer(delay)
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 300; i++ {
		d.wake()
		time.Sleep(time.Duration(rng.Intn(2000)) * time.Microsecond)
		d.sleep()
	}
	time.Sleep(delay * 20)

	got := log.snapshot()
	if len(got) == 0 || got[len(got)-1] != "sleep" {
		t.Fatalf("last event must be sleep, got tail %v", got[max(0, len(got)-3):])
	}
}
