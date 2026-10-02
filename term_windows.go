//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

const enableEchoInput = 0x0004

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsole = kernel32.NewProc("GetConsoleMode")
	procSetConsole = kernel32.NewProc("SetConsoleMode")
)

// disableEcho turns off console echo and returns a function restoring it.
func disableEcho() func() {
	h := uintptr(syscall.Stdin)
	var mode uint32
	r, _, _ := procGetConsole.Call(h, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return func() {} // not a console (piped input)
	}
	procSetConsole.Call(h, uintptr(mode&^enableEchoInput))
	return func() { procSetConsole.Call(h, uintptr(mode)) }
}
