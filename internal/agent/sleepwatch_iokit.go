package agent

import "log/slog"

// IOKit system power messages: iokit_common_msg(x) = 0xE0000000 | x
// (IOKit/IOMessage.h). Kept in an untagged file so the dispatch logic below is
// compiled and tested on every platform, not just darwin.
const (
	kIOMessageCanSystemSleep     = 0xE0000270
	kIOMessageSystemWillSleep    = 0xE0000280
	kIOMessageSystemWillNotSleep = 0xE0000290
	kIOMessageSystemHasPoweredOn = 0xE0000300
	kIOMessageSystemWillPowerOn  = 0xE0000320
)

// handlePowerMessage dispatches one IORegisterForSystemPower message:
//   - kIOMessageCanSystemSleep: an idle sleep is proposed. Acknowledged at once
//     with allow; the agent never vetoes sleep.
//   - kIOMessageSystemWillSleep: sleep is committed. onSleep runs to completion
//     first, then allow lets sleep proceed, so the offline notice flushes before
//     the process freezes.
//   - kIOMessageSystemHasPoweredOn: the host woke; onResume refreshes presence.
//
// Every other message (WillPowerOn, WillNotSleep, ...) needs no action or
// acknowledgement and is ignored.
//
// allow wraps IOAllowPowerChange with the message argument. It is required for
// both CanSystemSleep and WillSleep: an unacknowledged message makes the kernel
// wait up to 30s before sleeping anyway.
func handlePowerMessage(msgType uint32, arg uintptr, onSleep, onResume func(), allow func(uintptr), logger *slog.Logger) {
	switch msgType {
	case kIOMessageCanSystemSleep:
		allow(arg)
	case kIOMessageSystemWillSleep:
		logger.Info("host is about to sleep, marking offline")
		onSleep()
		allow(arg)
	case kIOMessageSystemHasPoweredOn:
		logger.Info("host resumed from sleep, refreshing presence")
		onResume()
	}
}
