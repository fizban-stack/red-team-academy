//go:build !windows

package main

// PPID spoofing and process masquerading are Windows-specific.
// On Linux/macOS these are no-ops.

func execCmdWithPPIDSpoof(command string) []byte { return execCmd(command) }
func masqueradeProcess()                         {}
