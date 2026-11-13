package gateway

import (
	"os"
	"syscall"
	"testing"
)

// TestMain exits with the raw exit syscall. Under -race, os.Exit runs the race
// runtime's finalizer, which leaves through C exit() and so runs OpenVPN 3
// Core's C++ static destructors; in CI those have both crashed and hung after
// every test had passed. Ordinary Go binaries never run them, because Go exits
// via exit_group. Races are still caught: testing fails any test during which
// the detector reported one.
func TestMain(m *testing.M) {
	code := m.Run()
	_ = os.Stdout.Sync()
	syscall.Exit(code)
}
