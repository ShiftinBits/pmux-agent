package agent

import (
	"sync"
	"time"
)

// wakeResumeDelay is how long the host must stay awake after a wake
// notification before the agent resumes signaling.
const wakeResumeDelay = 10 * time.Second

// wakeDebouncer turns raw sleep/wake notifications into Suspend/Resume calls.
//
// DarkWake (maintenance wakes) is short and ends in another WillSleep, which
// cancels the pending Resume, so the agent stays suspended with no reconnect
// churn and no false host_online. A full wake resumes after the delay. Every
// wake ends in a Resume unless the host sleeps again first, so the agent
// cannot stay suspended forever.
//
// onResume runs while holding mu so a Resume can never land after a Suspend:
// sleep() bumps gen under mu before calling onSleep, so a timer callback either
// finished its Resume before that bump or sees a stale gen and does nothing.
// This is safe because Resume is non-blocking.
type wakeDebouncer struct {
	onSleep, onResume func()
	delay             time.Duration

	mu    sync.Mutex
	gen   uint64
	timer *time.Timer
}

func newWakeDebouncer(delay time.Duration, onSleep, onResume func()) *wakeDebouncer {
	return &wakeDebouncer{delay: delay, onSleep: onSleep, onResume: onResume}
}

// wake arms (or re-arms) the delayed Resume.
func (d *wakeDebouncer) wake() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancelLocked()
	gen := d.gen
	d.timer = time.AfterFunc(d.delay, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen != gen {
			return
		}
		d.onResume()
	})
}

// sleep cancels any pending Resume and runs onSleep synchronously, returning
// only after it finishes. mu is not held across onSleep.
func (d *wakeDebouncer) sleep() {
	d.mu.Lock()
	d.cancelLocked()
	d.mu.Unlock()
	d.onSleep()
}

// stop cancels any pending Resume so none fires after the watcher exits.
func (d *wakeDebouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cancelLocked()
}

func (d *wakeDebouncer) cancelLocked() {
	d.gen++
	if d.timer != nil {
		d.timer.Stop()
	}
}
