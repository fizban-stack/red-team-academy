//go:build !windows

package main

// applyEvasionPatches is a no-op on non-Windows platforms.
// ETW and AMSI are Windows-specific telemetry mechanisms.
// On Linux/macOS the implant relies on encrypted comms and
// jittered sleep for stealth.
func applyEvasionPatches() {
	// No-op: ETW and AMSI don't exist on Linux/macOS
}
