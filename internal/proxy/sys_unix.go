//go:build !windows

package proxy

import "syscall"

// GetSysProcAttr returns platform-specific SysProcAttr for detaching daemon processes.
func GetSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
