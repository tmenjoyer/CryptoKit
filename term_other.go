//go:build !windows

package main

import (
	"os"
	"os/exec"
)

// disableEcho turns off terminal echo (via stty) and returns a function restoring it.
func disableEcho() func() {
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	if err := off.Run(); err != nil {
		return func() {} // not a TTY or stty unavailable
	}
	return func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
	}
}
