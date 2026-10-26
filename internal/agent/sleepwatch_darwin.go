package agent

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	iokitPath          = "/System/Library/Frameworks/IOKit.framework/IOKit"
	coreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

	// IOKit system power messages: iokit_common_msg(x) = 0xE0000000 | x
	// (IOKit/IOMessage.h).
	kIOMessageCanSystemSleep     = 0xE0000270
	kIOMessageSystemWillSleep    = 0xE0000280
	kIOMessageSystemHasPoweredOn = 0xE0000300

	// runLoopStopRetry is how often shutdown re-issues CFRunLoopStop until the
	// run loop has exited. A stop sent before CFRunLoopRun starts is discarded,
	// so a single call could leave the run loop blocked forever.
	runLoopStopRetry = 50 * time.Millisecond
)

// iokitPower holds the IOKit and CoreFoundation functions the sleep watcher
// calls, bound at runtime through purego. Signatures mirror the C prototypes in
// IOKit/pwr_mgt/IOPMLib.h, IOKit/IOKitLib.h and CoreFoundation/CFRunLoop.h:
// io_connect_t and io_object_t are mach ports (uint32), IONotificationPortRef,
// CFRunLoopRef, CFRunLoopSourceRef and CFRunLoopMode are pointers (uintptr).
type iokitPower struct {
	registerForSystemPower     func(refcon uintptr, port *uintptr, callback uintptr, notifier *uint32) uint32
	allowPowerChange           func(kernelPort uint32, notificationID uintptr) int32
	deregisterForSystemPower   func(notifier *uint32) int32
	serviceClose               func(connect uint32) int32
	notificationPortRunLoopSrc func(port uintptr) uintptr
	notificationPortDestroy    func(port uintptr)
	runLoopGetCurrent          func() uintptr
	runLoopAddSource           func(rl, source, mode uintptr)
	runLoopRun                 func()
	runLoopStop                func(rl uintptr)

	// defaultMode is the value of the kCFRunLoopDefaultMode data symbol.
	defaultMode uintptr
}

// loadIOKitPower opens IOKit and CoreFoundation and binds the functions the
// sleep watcher needs.
func loadIOKitPower() (*iokitPower, error) {
	iokit, err := purego.Dlopen(iokitPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("open IOKit: %w", err)
	}
	cf, err := purego.Dlopen(coreFoundationPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("open CoreFoundation: %w", err)
	}

	p := &iokitPower{}
	bindings := []struct {
		fptr any
		lib  uintptr
		name string
	}{
		{&p.registerForSystemPower, iokit, "IORegisterForSystemPower"},
		{&p.allowPowerChange, iokit, "IOAllowPowerChange"},
		{&p.deregisterForSystemPower, iokit, "IODeregisterForSystemPower"},
		{&p.serviceClose, iokit, "IOServiceClose"},
		{&p.notificationPortRunLoopSrc, iokit, "IONotificationPortGetRunLoopSource"},
		{&p.notificationPortDestroy, iokit, "IONotificationPortDestroy"},
		{&p.runLoopGetCurrent, cf, "CFRunLoopGetCurrent"},
		{&p.runLoopAddSource, cf, "CFRunLoopAddSource"},
		{&p.runLoopRun, cf, "CFRunLoopRun"},
		{&p.runLoopStop, cf, "CFRunLoopStop"},
	}
	for _, b := range bindings {
		// Dlsym + RegisterFunc rather than RegisterLibFunc, which panics on a
		// missing symbol instead of returning an error.
		sym, err := purego.Dlsym(b.lib, b.name)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", b.name, err)
		}
		purego.RegisterFunc(b.fptr, sym)
	}

	// kCFRunLoopDefaultMode is a data symbol: Dlsym returns the address of the
	// CFStringRef variable, so dereference it to get the mode itself. The
	// pointer-to-pointer conversion keeps go vet's unsafeptr check satisfied.
	modeSym, err := purego.Dlsym(cf, "kCFRunLoopDefaultMode")
	if err != nil {
		return nil, fmt.Errorf("resolve kCFRunLoopDefaultMode: %w", err)
	}
	p.defaultMode = **(**uintptr)(unsafe.Pointer(&modeSym))
	if p.defaultMode == 0 {
		return nil, fmt.Errorf("kCFRunLoopDefaultMode is nil")
	}
	return p, nil
}

// startSleepWatcher registers for IOKit system power notifications so the agent
// can notify the signaling server right before the host sleeps (onSleep) and
// refresh presence after it wakes (onResume).
//
// IOKit flow: IORegisterForSystemPower connects to the root power domain and
// creates a notification port whose run-loop source is added to a dedicated,
// OS-thread-locked run loop (CFRunLoopRun). The kernel then delivers power
// messages to the callback on that thread:
//   - kIOMessageCanSystemSleep: an idle sleep is proposed. Acknowledged at once
//     with IOAllowPowerChange; the agent never vetoes sleep.
//   - kIOMessageSystemWillSleep: sleep is committed. onSleep runs (bounded by
//     Suspend's write deadline), then IOAllowPowerChange lets sleep proceed.
//   - kIOMessageSystemHasPoweredOn: the host woke; onResume is scheduled.
//
// IOAllowPowerChange is required for both CanSystemSleep and WillSleep: an
// unacknowledged message makes the kernel wait up to 30s before sleeping
// anyway. Holding the WillSleep acknowledgement until onSleep returns is what
// lets the offline notice flush before the process freezes.
//
// Wakes go through wakeDebouncer: a DarkWake (Power Nap / maintenance wake)
// powers on briefly and sleeps again before the resume delay elapses, so the
// pending Resume is cancelled and the agent stays suspended with no reconnect
// churn. Accepted limitation: a pmux command run during a DarkWake sends
// SIGUSR1, which resumes signaling immediately.
//
// keepAwake is ignored, unlike on Linux. keep_awake on macOS is a caffeinate -i
// idle-sleep assertion; lid close, low battery and forced sleeps still happen
// and still deliver these notifications, so the watcher runs regardless.
//
// The build stays pure Go (CGO_ENABLED=0): frameworks are loaded with purego
// (Dlopen/Dlsym/RegisterFunc) and the callback is a purego.NewCallback, so no
// cgo is involved.
//
// Best-effort: if the frameworks can't be loaded or registration fails, it logs
// and returns, and the server's idle timeout remains the backstop. It returns
// immediately; the run loop stops when ctx is cancelled.
func startSleepWatcher(ctx context.Context, logger *slog.Logger, _ bool, onSleep, onResume func()) {
	api, err := loadIOKitPower()
	if err != nil {
		logger.Warn("sleep watcher: cannot load IOKit power notifications; "+
			"relying on the server idle timeout for offline detection", "error", err)
		return
	}

	d := newWakeDebouncer(wakeResumeDelay, onSleep, onResume)

	// ready carries the run loop ref once the watcher is running, or 0 if
	// registration failed. Buffered so the run-loop goroutine never blocks on it.
	ready := make(chan uintptr, 1)

	// mu guards exited so CFRunLoopStop is never called on a run loop whose
	// thread has already been released.
	var (
		mu     sync.Mutex
		exited bool
	)

	go func() {
		// The run loop, its source and the callback are bound to this OS thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// root is written before the run loop starts and only read by the
		// callback, which runs on this same thread inside CFRunLoopRun.
		var root uint32
		allow := func(messageArgument uintptr) {
			if ret := api.allowPowerChange(root, messageArgument); ret != 0 {
				logger.Warn("sleep watcher: IOAllowPowerChange failed", "ioReturn", fmt.Sprintf("%#x", uint32(ret)))
			}
		}
		callback := purego.NewCallback(func(_, _ uintptr, messageType uint32, messageArgument uintptr) uintptr {
			switch messageType {
			case kIOMessageCanSystemSleep:
				allow(messageArgument)
			case kIOMessageSystemWillSleep:
				logger.Info("host is about to sleep, marking offline")
				d.sleep()
				allow(messageArgument)
			case kIOMessageSystemHasPoweredOn:
				logger.Info("host powered on, refreshing presence after resume delay", "delay", wakeResumeDelay)
				d.wake()
			}
			return 0
		})

		var (
			port     uintptr
			notifier uint32
		)
		root = api.registerForSystemPower(0, &port, callback, &notifier)
		if root == 0 {
			logger.Warn("sleep watcher: IORegisterForSystemPower failed; " +
				"relying on the server idle timeout for offline detection")
			ready <- 0
			return
		}

		rl := api.runLoopGetCurrent()
		api.runLoopAddSource(rl, api.notificationPortRunLoopSrc(port), api.defaultMode)
		ready <- rl
		logger.Info("sleep watcher started: will notify the signaling server before the host sleeps")

		api.runLoopRun()

		mu.Lock()
		exited = true
		mu.Unlock()

		// The callback only runs inside CFRunLoopRun, so once it has returned no
		// wake can re-arm the debouncer; cancel any pending Resume.
		d.stop()
		api.deregisterForSystemPower(&notifier)
		api.serviceClose(root)
		api.notificationPortDestroy(port)
		logger.Info("sleep watcher stopped")
	}()

	go func() {
		<-ctx.Done()
		d.stop()
		rl := <-ready
		if rl == 0 {
			return
		}
		for {
			mu.Lock()
			if exited {
				mu.Unlock()
				return
			}
			api.runLoopStop(rl)
			mu.Unlock()
			time.Sleep(runLoopStopRetry)
		}
	}()
}
