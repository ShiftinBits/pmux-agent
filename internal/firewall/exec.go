package firewall

import "os/exec"

// execCommand is the function used to create exec.Cmd objects.
// Overridden in tests to avoid running real system commands.
var execCommand = exec.Command
