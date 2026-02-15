//go:build windows

package main

import "syscall"

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// Windows doesn't have Setsid. 
		// Command start already detaches on windows.
	}
}
