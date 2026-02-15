package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Version info set by ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// ProxyState is written to the state file for daemon status reporting.
type ProxyState struct {
	PID       int       `json:"pid"`
	Port      int       `json:"port"`
	ExitNode  string    `json:"exit_node"`
	StartTime time.Time `json:"start_time"`
	Version   string    `json:"version"`
}

// GetConfigDir returns the app-specific config directory, creating it if needed.
func GetConfigDir(appName string) (string, error) {
	ucd, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	ensureDir := filepath.Join(ucd, appName)
	if err := os.MkdirAll(ensureDir, 0700); err != nil {
		return "", err
	}
	return ensureDir, nil
}

// GetPidFilePath returns the path to the PID file for the given app.
func GetPidFilePath(appName string) (string, error) {
	dir, err := GetConfigDir(appName)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "proxy.pid"), nil
}

// GetStateFilePath returns the path to the state file for the given app.
func GetStateFilePath(appName string) (string, error) {
	dir, err := GetConfigDir(appName)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "proxy.state"), nil
}

// WriteStateFile writes the proxy state to disk.
func WriteStateFile(appName string, state ProxyState) error {
	stateFile, err := GetStateFilePath(appName)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, b, 0644)
}

// UpdateStateExitNode updates the exit node in the state file.
func UpdateStateExitNode(appName string, exitNodeIP string) {
	stateFile, err := GetStateFilePath(appName)
	if err != nil {
		return
	}
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		return
	}
	var state ProxyState
	if err := json.Unmarshal(raw, &state); err != nil {
		return
	}
	state.ExitNode = exitNodeIP
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(stateFile, b, 0644)
}

// PrintVersion prints version info to stdout.
func PrintVersion(productName string) {
	fmt.Printf("%s %s\n", productName, Version)
	fmt.Printf("Commit: %s\n", Commit)
	fmt.Printf("Date: %s\n", Date)
}
