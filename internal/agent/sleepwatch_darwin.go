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
// messages to the callback on that thread, which hands them to
// handlePowerMessage: CanSystemSleep is acknowledged at once, WillSleep runs
// onSleep (bounded by Suspend's write deadline) before acknowledging, and
// HasPoweredOn runs onResume.
//
// DarkWakes (Power Nap / maintenance wakes) need no special handling: the
// kernel only sends IORegisterForSystemPower (app power-state interest) clients
// WillSleep on the transition out of full wake and HasPoweredOn on the
// transition into full wake, so a DarkWake between two sleeps is never seen and
// onResume only runs when the host is really back.
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
			handlePowerMessage(messageType, messageArgument, onSleep, onResume, allow, logger)
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

		api.deregisterForSystemPower(&notifier)
		api.serviceClose(root)
		api.notificationPortDestroy(port)
		logger.Info("sleep watcher stopped")
	}()

	go func() {
		<-ctx.Done()
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
