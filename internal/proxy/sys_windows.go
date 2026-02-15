//go:build windows

package proxy

import "syscall"

// GetSysProcAttr returns platform-specific SysProcAttr for detaching daemon processes.
func GetSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// Windows doesn't have Setsid.
		// Command start already detaches on Windows.
	}
}
