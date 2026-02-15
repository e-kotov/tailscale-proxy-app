package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/hostinfo"

	"tailscale-proxy/internal/proxy"
)

const (
	appName     = "tailscale-proxy-cli"
	productName = "Tailscale Proxy CLI (Community)"
	initID      = "12345678-0000-0000-0000-1234567890cd"
)

var (
	// CLI Flags
	versionFlag   = flag.Bool("version", false, "display version information")
	proxyFlag     = flag.Bool("proxy", false, "run in CLI proxy mode")
	verboseFlag   = flag.Bool("verbose", false, "log to stderr in proxy mode")
	exitNodeFlag  = flag.String("exit-node", "", "exit node name or IP to use")
	portFlag      = flag.Int("port", 57320, "local port to listen on")
	logFileFlag   = flag.String("log-file", "", "path to log file")
	quietFlag     = flag.Bool("quiet", false, "silence all non-error output")
	daemonFlag    = flag.Bool("daemon", false, "run in background")
	stopFlag      = flag.Bool("stop", false, "stop the running daemon")
	statusFlag    = flag.Bool("status", false, "check if the daemon is running")
	hostnameFlag  = flag.String("hostname", "tailscale-proxy", "hostname to use for the tailscale node")
	pprofPortFlag = flag.Int("pprof-port", 0, "port for pprof debugging server (0 to disable)")
	authKeyFlag   = flag.String("auth-key", "", "tailscale auth key to use for login")
	logoutFlag    = flag.Bool("logout", false, "logout and remove state data")
	installFlag   = flag.String("install", "", "register the browser extension; string is 'C' (Chrome) or 'F' (Firefox) followed by extension ID")
	uninstallFlag = flag.Bool("uninstall", false, "unregister the browser extension")
)

func main() {
	flag.Parse()

	if *versionFlag {
		proxy.PrintVersion(productName)
		return
	}

	if *stopFlag {
		stopDaemon()
		return
	}

	if *statusFlag {
		statusDaemon()
		return
	}

	if *logoutFlag {
		logout()
		return
	}

	if *daemonFlag {
		startDaemon()
	}

	// Start pprof server for debugging memory leaks
	if *pprofPortFlag > 0 {
		go func() {
			addr := fmt.Sprintf("localhost:%d", *pprofPortFlag)
			log.Printf("Starting pprof server on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("pprof server error: %v", err)
			}
		}()
	}

	if *installFlag != "" {
		if err := install(*installFlag); err != nil {
			log.Fatalf("installation error: %v", err)
		}
		return
	}
	if *uninstallFlag {
		if err := uninstall(); err != nil {
			log.Fatalf("uninstallation error: %v", err)
		}
		return
	}

	// Default behavior: Start Proxy mode
	runProxyMode(*portFlag, *logFileFlag, *quietFlag)
}

func startDaemon() {
	pidFile, err := proxy.GetPidFilePath(appName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting PID file path: %v\n", err)
		os.Exit(1)
	}

	// Check if already running
	if raw, err := os.ReadFile(pidFile); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		if proc, err := os.FindProcess(pid); err == nil {
			if err := proc.Signal(syscall.Signal(0)); err == nil {
				fmt.Printf("Daemon already running (PID: %d)\n", pid)
				os.Exit(0)
			}
		}
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting executable path: %v\n", err)
		os.Exit(1)
	}

	// Filter out --daemon from args to prevent infinite loop
	args := []string{}
	for _, arg := range os.Args[1:] {
		if arg == "--daemon" || arg == "-daemon" {
			continue
		}
		args = append(args, arg)
	}

	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = proxy.GetSysProcAttr()
	if *logFileFlag == "" {
		cmd.Stdout = nil
		cmd.Stderr = nil
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write PID file: %v\n", err)
	}

	fmt.Printf("Started in background (PID: %d)\n", cmd.Process.Pid)
	os.Exit(0)
}

func stopDaemon() {
	pidFile, err := proxy.GetPidFilePath(appName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not running (PID file not found).")
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error reading PID file: %v\n", err)
		os.Exit(1)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid PID file content\n")
		os.Exit(1)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("Process not found.")
		os.Remove(pidFile)
		os.Exit(0)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to stop process (PID %d): %v\n", pid, err)
		os.Exit(1)
	}

	for i := 0; i < 10; i++ {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	os.Remove(pidFile)
	fmt.Printf("Stopped (PID: %d)\n", pid)
	os.Exit(0)
}

func statusDaemon() {
	pidFile, err := proxy.GetPidFilePath(appName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	stateFile, _ := proxy.GetStateFilePath(appName)

	if rawState, err := os.ReadFile(stateFile); err == nil {
		var state proxy.ProxyState
		if err := json.Unmarshal(rawState, &state); err == nil {
			if proc, err := os.FindProcess(state.PID); err == nil {
				if err := proc.Signal(syscall.Signal(0)); err == nil {
					fmt.Printf("Status:       Running\n")
					fmt.Printf("PID:          %d\n", state.PID)
					fmt.Printf("Port:         %d\n", state.Port)
					if state.ExitNode != "" {
						fmt.Printf("Exit Node:    %s\n", state.ExitNode)
					} else {
						fmt.Printf("Exit Node:    <none> (Local Traffic)\n")
					}
					fmt.Printf("Started:      %s\n", state.StartTime.Format(time.RFC822))
					fmt.Printf("Version:      %s\n", state.Version)
					os.Exit(0)
				}
			}
		}
	}

	raw, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Println("Status:       Not Running")
		os.Exit(1)
	}

	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	proc, err := os.FindProcess(pid)
	if err == nil {
		if err := proc.Signal(syscall.Signal(0)); err == nil {
			fmt.Printf("Status:       Running (PID: %d)\n", pid)
			fmt.Println("Details:      State file missing or unreadable.")
			os.Exit(0)
		}
	}

	fmt.Println("Status:       Not Running (Stale PID found)")
	os.Exit(1)
}

func logout() {
	pidFile, _ := proxy.GetPidFilePath(appName)

	// Try to stop the daemon first
	if raw, err := os.ReadFile(pidFile); err == nil {
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		if proc, err := os.FindProcess(pid); err == nil {
			proc.Signal(syscall.SIGTERM)
			time.Sleep(1 * time.Second)
		}
		os.Remove(pidFile)
	}

	// Remove state directory
	ucd, _ := os.UserConfigDir()
	tsDir := filepath.Join(ucd, appName, initID)

	fmt.Printf("Removing state directory: %s\n", tsDir)
	if err := os.RemoveAll(tsDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing state dir: %v\n", err)
		os.Exit(1)
	}

	stateFile, _ := proxy.GetStateFilePath(appName)
	os.Remove(stateFile)
	os.Remove(pidFile)

	fmt.Println("Logged out successfully (state cleared).")
	os.Exit(0)
}

// Browser extension registration

func getTargetDir(browserByte string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	var dir string
	switch runtime.GOOS {
	case "linux":
		if browserByte == "C" {
			dir = filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")
		} else if browserByte == "F" {
			dir = filepath.Join(home, ".mozilla", "native-messaging-hosts")
		}
	case "darwin":
		if browserByte == "C" {
			dir = filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts")
		} else if browserByte == "F" {
			dir = filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts")
		}
	default:
		return "", fmt.Errorf("TODO: implement support for installing on %q", runtime.GOOS)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	return dir, nil
}

func uninstall() error {
	for _, browserByte := range []string{"C", "F"} {
		targetDir, err := getTargetDir(browserByte)
		if err != nil {
			return err
		}
		targetBin := filepath.Join(targetDir, "ts-browser-ext")
		targetJSON := filepath.Join(targetDir, "com.tailscale.browserext.chrome.json")
		if browserByte == "F" {
			targetJSON = filepath.Join(targetDir, "com.tailscale.browserext.firefox.json")
		}
		if err := os.Remove(targetBin); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(targetJSON); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func install(installArg string) error {
	browserByte, extension := installArg[0:1], installArg[1:]
	switch browserByte {
	case "C":
		extensionRE := regexp.MustCompile(`^[a-z0-9]{32}$`)
		if !extensionRE.MatchString(extension) {
			return fmt.Errorf("invalid extension ID %q", extension)
		}
	case "F":
	default:
		return fmt.Errorf("unknown browser prefix byte %q", browserByte)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	targetDir, err := getTargetDir(browserByte)
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	targetBin := filepath.Join(targetDir, "ts-browser-ext")
	if err := os.WriteFile(targetBin, binary, 0755); err != nil {
		return err
	}
	log.SetFlags(0)
	log.Printf("copied binary to %v", targetBin)

	var targetJSON string
	var jsonConf []byte

	switch browserByte {
	case "C":
		targetJSON = filepath.Join(targetDir, "com.tailscale.browserext.chrome.json")
		jsonConf = fmt.Appendf(nil, `{
		"name": "com.tailscale.browserext.chrome",
		"description": "Tailscale Browser Extension",
		"path": "%s",
		"type": "stdio",
		"allowed_origins": [
			"chrome-extension://%s/"
		]
	  }`, targetBin, extension)
	case "F":
		targetJSON = filepath.Join(targetDir, "com.tailscale.browserext.firefox.json")
		jsonConf = fmt.Appendf(nil, `{
		"name": "com.tailscale.browserext.firefox",
		"description": "Tailscale Browser Extension",
		"path": "%s",
		"type": "stdio",
		"allowed_extensions": [
			"browser-ext@tailscale.com"
		]
	  }`, targetBin)
	default:
		return fmt.Errorf("unknown browser prefix byte %q", browserByte)
	}
	if err := os.WriteFile(targetJSON, jsonConf, 0644); err != nil {
		return err
	}
	log.Printf("wrote registration to %v", targetJSON)
	return nil
}

// Proxy mode

func runProxyMode(port int, logFile string, quiet bool) {
	cliToHostR, cliToHostW := io.Pipe()
	hostToCliR, hostToCliW := io.Pipe()

	if quiet {
		log.SetOutput(io.Discard)
	} else if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		log.SetOutput(f)
	} else {
		log.SetOutput(os.Stderr)
	}
	log.SetFlags(log.Ltime | log.Lshortfile)

	go func() {
		hostinfo.SetApp("tailscale-proxy-cli")
		h := proxy.NewHost(cliToHostR, hostToCliW)
		h.CustomPort = port
		h.Verbose = *verboseFlag
		h.HostName = *hostnameFlag
		h.StateDirName = appName

		h.Logf = func(f string, a ...any) {
			if *verboseFlag || logFile != "" {
				log.Printf("[BACKEND] "+f, a...)
			}
		}

		ln := h.GetProxyListener()
		actualPort := ln.Addr().(*net.TCPAddr).Port
		if *verboseFlag {
			log.Printf("Proxy listening on localhost:%v", actualPort)
		}

		// Write State File
		state := proxy.ProxyState{
			PID:       os.Getpid(),
			Port:      actualPort,
			StartTime: time.Now(),
			Version:   proxy.Version,
		}
		if prefs, err := h.LoadPrefs(); err == nil {
			state.ExitNode = prefs.ExitNodeIP
		}
		proxy.WriteStateFile(appName, state)

		h.Send(&proxy.Reply{ProcRunning: &proxy.ProcRunningResult{
			Port: actualPort,
			Pid:  os.Getpid(),
		}})

		if err := h.ReadMessages(); err != nil {
			if *verboseFlag {
				log.Printf("host loop ended: %v", err)
			}
		}
	}()

	// Helper to send commands
	sendCmd := func(cmd proxy.Request) {
		b, _ := json.Marshal(cmd)
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(b)))
		cliToHostW.Write(lenBuf)
		cliToHostW.Write(b)
	}

	// Read Loop
	go func() {
		br := bufio.NewReader(hostToCliR)
		var lenBuf [4]byte
		for {
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
				return
			}
			msgSize := binary.LittleEndian.Uint32(lenBuf[:])
			msgb := make([]byte, msgSize)
			if _, err := io.ReadFull(br, msgb); err != nil {
				return
			}

			var msg proxy.Reply
			if err := json.Unmarshal(msgb, &msg); err != nil {
				continue
			}

			if msg.Init != nil && msg.Init.Error != "" {
				fmt.Fprintf(os.Stderr, "Error initializing: %s\n", msg.Init.Error)
				os.Exit(1)
			}

			if msg.ProcRunning != nil {
				log.Printf("Listening for HTTP/SOCKS5 on 127.0.0.1:%d", msg.ProcRunning.Port)
			}

			if msg.Status != nil {
				if msg.Status.NeedsLogin && msg.Status.BrowseToURL != "" {
					fmt.Printf("\nAuth Required! Please visit:\n\n%s\n\n", msg.Status.BrowseToURL)
				}
				if msg.Status.Running {
					if *verboseFlag {
						log.Printf("Status: Running")
					}
				}
			}

			if msg.ExitNodes != nil {
				target := *exitNodeFlag
				if target != "" {
					if len(msg.ExitNodes.Nodes) == 0 {
						continue
					}

					var ip string
					for _, n := range msg.ExitNodes.Nodes {
						if n.Name == target || n.IP == target {
							ip = n.IP
							break
						}
					}
					if ip != "" {
						fmt.Printf("Setting exit node to %s (%s)...\n", target, ip)
						sendCmd(proxy.Request{Cmd: proxy.CmdSetExitNode, ExitNodeIP: ip})
						*exitNodeFlag = ""
					} else {
						fmt.Fprintf(os.Stderr, "Exit node %q not found. Available nodes:\n", target)
						for _, n := range msg.ExitNodes.Nodes {
							fmt.Fprintf(os.Stderr, "  - %s (%s)\n", n.Name, n.IP)
						}
						*exitNodeFlag = ""
					}
				}
			}
		}
	}()

	// Init sequence
	go func() {
		sendCmd(proxy.Request{
			Cmd:     proxy.CmdInit,
			InitID:  initID,
			AuthKey: *authKeyFlag,
		})
		time.Sleep(500 * time.Millisecond)
		sendCmd(proxy.Request{Cmd: proxy.CmdUp})
		sendCmd(proxy.Request{Cmd: proxy.CmdGetStatus})

		if *exitNodeFlag != "" {
			for i := 0; i < 15; i++ {
				if *exitNodeFlag == "" {
					break
				}
				sendCmd(proxy.Request{Cmd: proxy.CmdGetExitNodes})
				time.Sleep(1 * time.Second)
			}
			if *exitNodeFlag != "" {
				fmt.Fprintf(os.Stderr, "Timed out waiting for exit node %q\n", *exitNodeFlag)
			}
		}
	}()

	// Wait for signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	fmt.Println("\nStopping...")
}
