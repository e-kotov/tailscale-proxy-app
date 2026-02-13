package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	// Syslog removal for Windows compatibility
	// if w, err := syslog.Dial("tcp", "localhost:5555", syslog.LOG_INFO, "browser"); err == nil { ... }
	// We rely on standard logging or GUI logging now.
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

var (
	installFlag   = flag.String("install", "", "register the browser extension; string is 'C' (Chrome) or 'F' (Firefox) followed by extension ID")
	uninstallFlag = flag.Bool("uninstall", false, "unregister the browser extension")
	guiFlag       = flag.Bool("gui", false, "run in GUI mode")
	proxyFlag     = flag.Bool("proxy", false, "run in CLI proxy mode")
	verboseFlag   = flag.Bool("verbose", false, "log to stderr in proxy mode")
	exitNodeFlag  = flag.String("exit-node", "", "exit node name or IP to use in CLI proxy mode")
)

func main() {
	flag.Parse()
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

	if *guiFlag || os.Getenv("TS_GUI_MODE") == "1" {
		runGuiMode()
		return
	}

	if *proxyFlag {
		runProxyMode()
		return
	}

	if flag.NArg() == 0 {
		fmt.Printf(`ts-browser-ext is the backend for the Tailscale browser extension,
running as a child process HTTP/SOCKS5 under your browser.

To register it once, run:

     $ ts-browser-ext --install=chrome
     $ ts-browser-ext --gui

`)
		return
	}

	hostinfo.SetApp("ts-browser-ext")

	h := newHost(os.Stdin, os.Stdout)
	
	// Syslog dial removed (Windows incompatible)
	/*
	if w, err := syslog.Dial("tcp", "localhost:5555", syslog.LOG_INFO, "browser"); err == nil {
		log.Printf("syslog dialed")
		h.logf = func(f string, a ...any) {
			fmt.Fprintf(w, f, a...)
		}
		log.SetOutput(w)
	} else {
		log.Printf("syslog: %v", err)
	}
	*/

	ln := h.getProxyListener()
	port := ln.Addr().(*net.TCPAddr).Port
	h.logf("Proxy listening on localhost:%v", port)

	h.send(&reply{ProcRunning: &procRunningResult{
		Port: port,
		Pid:  os.Getpid(),
	}})
	h.logf("Starting readMessages loop")
	err := h.readMessages()
	h.logf("readMessage loop ended: %v", err)
}

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

type host struct {
	br   *bufio.Reader
	w    io.Writer
	logf logger.Logf

	wmu sync.Mutex // guards writing to w

	lenBuf [4]byte // owned by readMessages

	mu              sync.Mutex
	watchDead       bool
	lastNetmap      *netmap.NetworkMap
	lastState       ipn.State
	lastBrowseToURL string
	ctx             context.Context // for IPN bus; canceled by cancelCtx
	cancelCtx       context.CancelFunc
	ts              *tsnet.Server
	ws              *web.Server
	ln              net.Listener
	wantUp          bool
	// ...
}

func newHost(r io.Reader, w io.Writer) *host {
	h := &host{
		br:   bufio.NewReaderSize(r, 1<<20),
		w:    w,
		logf: log.Printf,
	}
	h.ts = &tsnet.Server{
		RunWebClient: true,

		// late-binding, so caller can adjust h.logf.
		Logf: func(f string, a ...any) {
			h.logf(f, a...)
		},
	}
	return h
}

const maxMsgSize = 1 << 20

func (h *host) readMessages() error {
	for {
		msg, err := h.readMessage()
		if err != nil {
			return err
		}
		if err := h.handleMessage(msg); err != nil {
			h.logf("error handling message %v: %v", msg, err)
			return err
		}
	}
}

func (h *host) handleMessage(msg *request) error {
	switch msg.Cmd {
	case CmdInit:
		return h.handleInit(msg)
	case CmdGetStatus:
		h.sendStatus()
	case CmdUp:
		return h.handleUp()
	case CmdDown:
		return h.handleDown()
	case CmdGetExitNodes:
		h.handleGetExitNodes()
	case CmdSetExitNode:
		h.handleSetExitNode(msg.ExitNodeIP)
	case CmdSetPort:
		if err := h.restartListener(msg.Port); err != nil {
			h.logf("failed to set port: %v", err)
			// Ideally send error back, but for now just log
		}
	default:
		h.logf("unknown command %q", msg.Cmd)
	}
	return nil
}

func (h *host) handleUp() error {
	return h.setWantRunning(true)
}

func (h *host) handleDown() error {
	return h.setWantRunning(false)
}

func (h *host) handleGetExitNodes() {
	result := &exitNodesResult{}

	h.mu.Lock()
	if h.ts.Sys() == nil {
		h.mu.Unlock()
		result.Error = "not initialized"
		h.send(&reply{ExitNodes: result})
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc, err := h.ts.LocalClient()
	if err != nil {
		result.Error = err.Error()
		h.send(&reply{ExitNodes: result})
		return
	}

	st, err := lc.Status(ctx)
	if err != nil {
		result.Error = err.Error()
		h.send(&reply{ExitNodes: result})
		return
	}

	// Logging peer count
	h.logf("Status check: %d peers found", len(st.Peer))

	// Collect exit nodes from peers
	for _, peer := range st.Peer {
		if peer.ExitNodeOption {
			ip := ""
			if len(peer.TailscaleIPs) > 0 {
				ip = peer.TailscaleIPs[0].String()
			}
			if ip != "" {
				// Use DNSName (short version) for display, matching the settings UI
				// DNSName is like "machine.tailnet.ts.net", we want just "machine"
				name := peer.HostName
				if peer.DNSName != "" {
					name = strings.TrimSuffix(peer.DNSName, ".")
					if idx := strings.Index(name, "."); idx > 0 {
						name = name[:idx]
					}
				}
				result.Nodes = append(result.Nodes, exitNode{
					Name: name,
					IP:   ip,
				})
				// Use ExitNode bool to detect if this peer is the current exit node
				// This avoids IPv4/IPv6 format mismatches when comparing IPs
				if peer.ExitNode {
					result.CurrentNode = ip
				}
			}
		}
	}
	
	h.logf("Found %d exit nodes", len(result.Nodes))
	h.send(&reply{ExitNodes: result})
}

func (h *host) handleSetExitNode(exitNodeIP string) {
	result := &exitNodeSetResult{}

	h.mu.Lock()
	if h.ts.Sys() == nil {
		h.mu.Unlock()
		result.Error = "not initialized"
		h.send(&reply{ExitNodeSet: result})
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc, err := h.ts.LocalClient()
	if err != nil {
		result.Error = err.Error()
		h.send(&reply{ExitNodeSet: result})
		return
	}

	var exitIP netip.Addr
	if exitNodeIP != "" {
		exitIP, err = netip.ParseAddr(exitNodeIP)
		if err != nil {
			result.Error = fmt.Sprintf("invalid exit node IP: %v", err)
			h.send(&reply{ExitNodeSet: result})
			return
		}
	}

	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
		ExitNodeIDSet: true, // Also clear/set ID to ensure IP takes precedence or both are cleared
		Prefs: ipn.Prefs{
			ExitNodeIP: exitIP,
			ExitNodeID: "", // Always clear ID when setting by IP (or clearing both)
		},
	}); err != nil {
		result.Error = fmt.Sprintf("failed to set exit node: %v", err)
		h.send(&reply{ExitNodeSet: result})
		return
	}

	result.Success = true
	h.send(&reply{ExitNodeSet: result})
	h.sendStatus() // Send updated status
}

func (h *host) setWantRunning(want bool) error {
	defer h.sendStatus()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ts.Sys() == nil {
		return fmt.Errorf("not init")
	}
	h.wantUp = want
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc, err := h.ts.LocalClient()
	if err != nil {
		return err
	}
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		WantRunningSet: true,
		Prefs: ipn.Prefs{
			WantRunning: want,
		},
	}); err != nil {
		return fmt.Errorf("EditPrefs to wantRunning=%v: %w", want, err)
	}
	return nil
}

func (h *host) handleInit(msg *request) (ret error) {
	defer func() {
		var errMsg string
		if ret != nil {
			errMsg = ret.Error()
		}
		h.send(&reply{
			Init: &initResult{Error: errMsg},
		})
	}()
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.cancelCtx != nil {
		h.cancelCtx()
	}
	h.ctx, h.cancelCtx = context.WithCancel(context.Background())

	id := msg.InitID
	if len(id) == 0 {
		return fmt.Errorf("missing initID")
	}
	if len(id) > 60 {
		return fmt.Errorf("initID too long")
	}
	for i := range len(id) {
		b := id[i]
		if b == '-' || (b >= 'a' && b <= 'f') || (b >= '0' && b <= '9') {
			continue
		}
		return errors.New("invalid initID character")
	}

	if h.ts.Sys() != nil {
		return fmt.Errorf("already running")
	}
	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("getting current user: %w", err)
	}
	h.ts.Hostname = u.Username + "-browser-ext"

	confDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("getting user config dir: %w", err)
	}
	h.ts.Dir = filepath.Join(confDir, "tailscale-browser-ext", id)

	h.logf("Starting...")
	if err := h.ts.Start(); err != nil {
		return fmt.Errorf("starting tsnet.Server: %w", err)
	}
	h.logf("Started")

	lc, err := h.ts.LocalClient()
	if err != nil {
		return fmt.Errorf("getting local client: %w", err)
	}

	wc, err := lc.WatchIPNBus(h.ctx, ipn.NotifyInitialState|ipn.NotifyRateLimit)
	if err != nil {
		return fmt.Errorf("watching IPN bus: %w", err)
	}
	go h.watchIPNBus(wc)

	h.ws, err = web.NewServer(web.ServerOpts{
		Mode:        web.LoginServerMode, // TODO: manage?
		LocalClient: lc,
	})
	if err != nil {
		return fmt.Errorf("NewServer: %w", err)
	}

	return nil
}

func (h *host) watchIPNBus(wc *tailscale.IPNBusWatcher) {
	h.mu.Lock()
	h.watchDead = false
	h.mu.Unlock()

	for h.updateFromWatcher(wc) {
		// Keep going.
	}
}

func (h *host) updateFromWatcher(wc *tailscale.IPNBusWatcher) bool {
	n, err := wc.Next()

	defer h.sendStatus()

	h.mu.Lock()
	defer h.mu.Unlock()

	if err != nil {
		log.Printf("watchIPNBus: %v", err)
		h.watchDead = true
		return false
	}

	if n.NetMap != nil {
		h.lastNetmap = n.NetMap
	}
	if n.State != nil {
		h.lastState = *n.State
	}

	if n.BrowseToURL != nil {
		h.lastBrowseToURL = *n.BrowseToURL
		// TODO: pop a browser for Tailscale SSH check mode etc, even
		// if already logged in.
	}
	return true
}

func (h *host) send(msg *reply) error {
	msgb, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encoding of message: %w", err)
	}
	h.logf("sent reply: %s", msgb)
	if len(msgb) > maxMsgSize {
		return fmt.Errorf("message too big (%v)", len(msgb))
	}
	binary.LittleEndian.PutUint32(h.lenBuf[:], uint32(len(msgb)))
	h.wmu.Lock()
	defer h.wmu.Unlock()
	if _, err := h.w.Write(h.lenBuf[:]); err != nil {
		return err
	}
	if _, err := h.w.Write(msgb); err != nil {
		return err
	}
	return nil
}

func (h *host) getProxyListener() net.Listener {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.getProxyListenerLocked()
}

func (h *host) getProxyListenerLocked() net.Listener {
	if h.ln != nil {
		return h.ln
	}
	var err error
	h.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err) // TODO: be more graceful
	}
	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(h.ln)

	hs := &http.Server{Handler: h.httpProxyHandler()}
	go func() {
		if err := hs.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP proxy exited: %v", err)
		}
	}()
	ss := &socks5.Server{
		Logf:   logger.WithPrefix(h.logf, "socks5: "),
		Dialer: h.userDial,
	}
	go func() {
		if err := ss.Serve(socksListener); err != nil {
			// SOCKS5 server might not export a specific "Closed" error, but we log it anyway
			// Use string check if necessary or just log.
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS5 server exited: %v", err)
			}
		}
	}()
	return h.ln
}

func (h *host) restartListener(port int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ln != nil {
		h.ln.Close()
		h.ln = nil
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	h.ln = ln

	// Broadcast new port
	// We can't reuse getProxyListenerLocked logic directly because it spawns listeners 
	// but doesn't handle the "restart" part cleanly with existing goroutines.
	// Actually, getProxyListenerLocked spawns NEW serving goroutines for the NEW listener.
	// The OLD goroutines will exit because we closed the OLD listener.
	// So we can just call getProxyListenerLocked? 
	// Wait, getProxyListenerLocked checks if h.ln != nil. 
	// We already set h.ln = ln. So calling it would just return ln.
	// But we need to SPAWN the servers.
	
	// Let's refactor: getProxyListenerLocked should take the listener and spawn servers?
	// Or just duplicate the spawn logic here for now to be safe.
	
	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(h.ln)
	hs := &http.Server{Handler: h.httpProxyHandler()}
	go func() {
		if err := hs.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP proxy exited: %v", err)
		}
	}()
	ss := &socks5.Server{
		Logf:   logger.WithPrefix(h.logf, "socks5: "),
		Dialer: h.userDial,
	}
	go func() {
		if err := ss.Serve(socksListener); err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS5 server exited: %v", err)
			}
		}
	}()
	
	h.logf("Restarted proxy on port %d", port)
	
	// We need to send the new port to the GUI
	// We can reuse ProcRunning message? Yes.
	go func() {
		h.send(&reply{ProcRunning: &procRunningResult{
			Port: ln.Addr().(*net.TCPAddr).Port,
			Pid:  os.Getpid(),
		}})
	}()

	return nil
}

func (h *host) userDial(ctx context.Context, netw, addr string) (net.Conn, error) {
	h.mu.Lock()
	sys := h.ts.Sys()
	h.mu.Unlock()

	if sys == nil {
		h.logf("userDial to %v/%v without a tsnet.Server started", netw, addr)
		return nil, fmt.Errorf("no tsnet.Server")
	}

	return sys.Dialer.Get().UserDial(ctx, netw, addr)
}

func (h *host) sendStatus() {
	st := &status{}
	h.mu.Lock()
	st.Running = h.lastState == ipn.Running
	if nm := h.lastNetmap; nm != nil {
		st.Tailnet = nm.Domain
	}
	if h.lastState == ipn.NeedsLogin {
		st.NeedsLogin = true
		st.BrowseToURL = h.lastBrowseToURL
	} else if !st.Running {
		st.Error = "State: " + h.lastState.String()
	}
	if h.watchDead {
		st.Error = "WatchIPNBus stopped"
	}
	h.mu.Unlock()

	if err := h.send(&reply{Status: st}); err != nil {
		h.logf("failed to send status: %v", err)
	}
}

type Cmd string

const (
	CmdInit         Cmd = "init"
	CmdUp           Cmd = "up"
	CmdDown         Cmd = "down"
	CmdGetStatus    Cmd = "get-status"
	CmdGetExitNodes Cmd = "get-exit-nodes"
	CmdSetExitNode  Cmd = "set-exit-node"
	CmdSetPort      Cmd = "set-port"
)

// request is a message from the browser extension.
type request struct {
	// Cmd is the request type.
	Cmd Cmd `json:"cmd"`

	// Port is used for CmdSetPort
	Port int `json:"port,omitempty"`

	// InitID is the unique ID made by the extension (in its local storage) to
	// distinguish between different browser profiles using the same extension.
	// A given Go process will correspond to a single browser profile.
	// This lets us store tsnet state in different directories.
	// This string, coming from JavaScript, should not be trusted. It must be
	// UUID-ish: hex and hyphens only, and too long.
	InitID string `json:"initID,omitempty"`

	// ExitNodeIP is the IP address of the exit node to use.
	// Empty string means no exit node (direct connection).
	ExitNodeIP string `json:"exitNodeIP,omitempty"`
}

// reply is a message to the browser extension.
type reply struct {
	// ProcRunning is set on the first message when the Go process starts up.
	// It's the message that makes the browser recognize that the native
	// messaging port is up.
	ProcRunning *procRunningResult `json:"procRunning,omitempty"`

	// Status is sent in response to a [CmdGetStatus] [request.Cmd].
	Status *status `json:"status,omitempty"`

	Init *initResult `json:"init,omitempty"`

	// ExitNodes is sent in response to a [CmdGetExitNodes] [request.Cmd].
	ExitNodes *exitNodesResult `json:"exitNodes,omitempty"`

	// ExitNodeSet is sent in response to a [CmdSetExitNode] [request.Cmd].
	ExitNodeSet *exitNodeSetResult `json:"exitNodeSet,omitempty"`
}

// exitNode represents an available exit node.
type exitNode struct {
	Name string `json:"name"` // Hostname of the exit node
	IP   string `json:"ip"`   // IP address to use when setting
}

// exitNodesResult is the response to a get-exit-nodes command.
type exitNodesResult struct {
	Nodes       []exitNode `json:"nodes"`
	CurrentNode string     `json:"currentNode"` // IP of currently selected exit node, empty if none
	Error       string     `json:"error,omitempty"`
}

// exitNodeSetResult is the response to a set-exit-node command.
type exitNodeSetResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type procRunningResult struct {
	Port  int    `json:"port"` // HTTP+SOCKS5 localhost proxy port
	Pid   int    `json:"pid"`
	Error string `json:"error"`
}

type initResult struct {
	Error string `json:"error"` // empty for none
}

type status struct {
	Running bool   `json:"running"`
	Tailnet string `json:"tailnet"`
	Error   string `json:"error,omitempty"`

	NeedsLogin  bool   `json:"needsLogin,omitempty"` // true if the user needs to log in
	BrowseToURL string `json:"browseToURL"`
}

func (h *host) readMessage() (*request, error) {
	if _, err := io.ReadFull(h.br, h.lenBuf[:]); err != nil {
		return nil, err
	}
	msgSize := binary.LittleEndian.Uint32(h.lenBuf[:])
	if msgSize > maxMsgSize {
		return nil, fmt.Errorf("message size too big (%v)", msgSize)
	}
	msgb := make([]byte, msgSize)
	if n, err := io.ReadFull(h.br, msgb); err != nil {
		return nil, fmt.Errorf("read %v of %v bytes in message with error %v", n, msgSize, err)
	}
	msg := new(request)
	if err := json.Unmarshal(msgb, msg); err != nil {
		return nil, fmt.Errorf("invalid JSON decoding of message: %w", err)
	}
	h.logf("got command %q: %s", msg.Cmd, msgb)
	return msg, nil
}

// httpProxyHandler returns an HTTP proxy http.Handler using the
// provided backend dialer.
func (h *host) httpProxyHandler() http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {}, // no change
		Transport: &http.Transport{
			DialContext: h.userDial,
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "100.100.100.100" {
			h.ws.ServeHTTP(w, csrf.PlaintextHTTPRequest(r))
			return
		}

		if r.Method != "CONNECT" {
			backURL := r.RequestURI
			if strings.HasPrefix(backURL, "/") || backURL == "*" {
				http.Error(w, "bogus RequestURI; must be absolute URL or CONNECT", 400)
				return
			}
			rp.ServeHTTP(w, r)
			return
		}

		// CONNECT support:

		dst := r.RequestURI
		c, err := h.userDial(r.Context(), "tcp", dst)
		if err != nil {
			w.Header().Set("Tailscale-Connect-Error", err.Error())
			http.Error(w, err.Error(), 500)
			return
		}
		defer c.Close()

		cc, ccbuf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer cc.Close()

		io.WriteString(cc, "HTTP/1.1 200 OK\r\n\r\n")

		var clientSrc io.Reader = ccbuf
		if ccbuf.Reader.Buffered() == 0 {
			// In the common case (with no
			// buffered data), read directly from
			// the underlying client connection to
			// save some memory, letting the
			// bufio.Reader/Writer get GC'ed.
			clientSrc = cc
		}

		errc := make(chan error, 1)
		go func() {
			_, err := io.Copy(cc, c)
			errc <- err
		}()
		go func() {
			_, err := io.Copy(c, clientSrc)
			errc <- err
		}()
		<-errc
	})
}

func runGuiMode() {
	a := app.New()
	w := a.NewWindow("Tailscale Proxy")

	// Host <-> GUI communication pipes
	guiToHostR, guiToHostW := io.Pipe()
	hostToGuiR, hostToGuiW := io.Pipe()

	// Command Channel to prevent UI blocking
	cmdChan := make(chan request, 16)

	// Command Sender/Writer Routine
	go func() {
		for cmd := range cmdChan {
			b, err := json.Marshal(cmd)
			if err != nil {
				log.Printf("JSON marshal error: %v", err)
				continue
			}
			lenBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBuf, uint32(len(b)))
			
			// Write header then body. Since this is the single writer, it's safe.
			if _, err := guiToHostW.Write(lenBuf); err != nil {
				log.Printf("Pipe write error: %v", err)
				break // Pipe likely closed
			}
			if _, err := guiToHostW.Write(b); err != nil {
				log.Printf("Pipe write error: %v", err)
				break
			}
		}
	}()

	// Helper to send commands (non-blocking)
	sendCmd := func(cmd request) {
		select {
		case cmdChan <- cmd:
		default:
			log.Println("Command channel full, dropping command to avoid hang")
		}
	}

	// Data Bindings
	statusData := binding.NewString()
	statusData.Set("Status: Initializing...")
	statusLabel := widget.NewLabelWithData(statusData)

	// Rich Logs
	richLogs := widget.NewRichText()
	richLogs.Scroll = container.ScrollBoth
	richLogs.Wrapping = fyne.TextWrapBreak
	
	
	// Scroll container for logs
	logScroll := container.NewScroll(richLogs)

	// Log channel for thread-safe updates
	logChan := make(chan *widget.TextSegment, 64)

	// Logger helper (non-blocking, sends to channel)
	addLog := func(msg string) {
		seg := &widget.TextSegment{Text: msg + "\n", Style: widget.RichTextStyleInline}
		
		lower := strings.ToLower(msg)
		isError := (strings.Contains(lower, "error") || strings.Contains(lower, "fail")) && !strings.Contains(lower, `"error":""`)
		
		if isError {
			seg.Style.ColorName = theme.ColorNameError
			seg.Style.TextStyle.Bold = true
		} else if strings.Contains(lower, "listening") || strings.Contains(lower, "restarted") || strings.Contains(lower, "connected") {
			seg.Style.ColorName = theme.ColorNameSuccess
			seg.Style.TextStyle.Bold = true
		} else {
			seg.Style.ColorName = theme.ColorNameForeground
		}
		
		select {
		case logChan <- seg:
		default:
			// Channel full, drop oldest log to make room
		}
	}

	// Log flusher goroutine - drains logChan and updates UI periodically
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			// Drain all pending segments
			var newSegs []*widget.TextSegment
			for {
				select {
				case seg := <-logChan:
					newSegs = append(newSegs, seg)
				default:
					goto done
				}
			}
		done:
			if len(newSegs) == 0 {
				continue
			}
			for _, seg := range newSegs {
				richLogs.Segments = append(richLogs.Segments, seg)
			}
			if len(richLogs.Segments) > 200 {
				richLogs.Segments = richLogs.Segments[len(richLogs.Segments)-150:]
			}
			richLogs.Refresh()
		}
	}()

	// Start the backend
	go func() {
		hostinfo.SetApp("ts-browser-ext-gui")
		h := newHost(guiToHostR, hostToGuiW)
		
		h.logf = func(f string, a ...any) {
			msg := fmt.Sprintf(f, a...)
			log.Println(msg)
			addLog(msg)
		}

		ln := h.getProxyListener()
		port := ln.Addr().(*net.TCPAddr).Port
		addLog(fmt.Sprintf("Proxy listening on localhost:%v", port))
		h.send(&reply{ProcRunning: &procRunningResult{
			Port: port,
			Pid:  os.Getpid(),
		}})

		if err := h.readMessages(); err != nil {
			log.Printf("host readMessages error: %v", err)
			addLog(fmt.Sprintf("Host Error: %v", err))
		}
	}()

	// UI State
	var exitNodes []exitNode
	var loginURL string

	// widgets
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("0")
	portEntry.SetText("0")
	
	setPortBtn := widget.NewButton("Set Port", func() {
		pStr := portEntry.Text
		p, err := strconv.Atoi(pStr)
		if err != nil {
			statusData.Set("Error: Invalid port number")
			return
		}
		addLog(fmt.Sprintf("Requesting port change to %d...", p))
		sendCmd(request{Cmd: CmdSetPort, Port: p})
	})
	
	portContainer := container.NewBorder(nil, nil, widget.NewLabel("Proxy Port:"), setPortBtn, portEntry)

	loginBtn := widget.NewButton("Log in to Tailscale", func() {
		if loginURL != "" {
			u, _ := url.Parse(loginURL)
			if u != nil {
				a.OpenURL(u)
			}
		}
	})
	loginBtn.Hide()

	exitNodeSelect := widget.NewSelect([]string{"Loading nodes..."}, func(selected string) {
		if selected == "Loading nodes..." {
			return
		}
		if selected == "None (Direct)" {
			sendCmd(request{Cmd: CmdSetExitNode, ExitNodeIP: ""})
			return
		}
		for _, node := range exitNodes {
			if node.Name == selected {
				sendCmd(request{Cmd: CmdSetExitNode, ExitNodeIP: node.IP})
				return
			}
		}
	})
	exitNodeSelect.PlaceHolder = "Loading nodes..."

	var connectBtn *widget.Button
	connectBtn = widget.NewButton("Connect to Tailscale", func() {
		if connectBtn.Text == "Connect to Tailscale" {
			sendCmd(request{Cmd: CmdUp})
			connectBtn.SetText("Connecting...")
			connectBtn.Disable()
		} else {
			sendCmd(request{Cmd: CmdDown})
			connectBtn.SetText("Disconnecting...")
			connectBtn.Disable()
		}
	})
	connectBtn.Importance = widget.HighImportance

	// Handle incoming messages
	go func() {
		br := bufio.NewReader(hostToGuiR)
		var lenBuf [4]byte
		for {
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
				break
			}
			msgSize := binary.LittleEndian.Uint32(lenBuf[:])
			msgb := make([]byte, msgSize)
			if _, err := io.ReadFull(br, msgb); err != nil {
				break
			}
			var msg reply
			if err := json.Unmarshal(msgb, &msg); err != nil {
				continue
			}

			if msg.Init != nil && msg.Init.Error != "" {
				statusData.Set("Error: " + msg.Init.Error)
				addLog("[ERROR] Init failed: " + msg.Init.Error)
			}
			if msg.ProcRunning != nil {
				portEntry.SetText(strconv.Itoa(msg.ProcRunning.Port))
			}
			if msg.Status != nil {
				statusText := fmt.Sprintf("Status: Running=%v", msg.Status.Running)
				if msg.Status.Running {
					statusText = "Status: Connected"
				} else {
					statusText = "Status: Disconnected"
				}
				
				if msg.Status.NeedsLogin {
					statusText = "Status: Login Required"
					loginURL = msg.Status.BrowseToURL
					loginBtn.Show()
				} else {
					loginBtn.Hide()
				}
				statusData.Set(statusText)
				if msg.Status.Running {
					connectBtn.SetText("Disconnect")
					connectBtn.Importance = widget.DangerImportance
				} else {
					connectBtn.SetText("Connect to Tailscale")
					connectBtn.Importance = widget.HighImportance
				}
				connectBtn.Enable()
			}
			if msg.ExitNodes != nil {
				var options []string
				options = append(options, "None (Direct)")
				exitNodes = msg.ExitNodes.Nodes
				for _, n := range exitNodes {
					options = append(options, n.Name)
				}
				exitNodeSelect.Options = options
				exitNodeSelect.Refresh()

				if msg.ExitNodes.CurrentNode != "" {
					found := false
					for _, n := range exitNodes {
						if n.IP == msg.ExitNodes.CurrentNode {
							exitNodeSelect.SetSelected(n.Name)
							statusData.Set(fmt.Sprintf("Status: Connected via %s", n.Name))
							found = true
							break
						}
					}
					if !found {
						exitNodeSelect.SetSelected("None (Direct)")
						statusData.Set("Status: Connected (Direct)")
					}
				} else {
					exitNodeSelect.SetSelected("None (Direct)")
					statusData.Set("Status: Connected (Direct)")
				}
			}
		}
	}()

	// Init sequence
	go func() {
		time.Sleep(500 * time.Millisecond)
		addLog("Sending Init command...")
		sendCmd(request{Cmd: CmdInit, InitID: "12345678-1234-1234-1234-1234567890ab"})
		time.Sleep(1 * time.Second)
		sendCmd(request{Cmd: CmdGetExitNodes})
		time.Sleep(2 * time.Second)
		sendCmd(request{Cmd: CmdGetExitNodes})
		time.Sleep(2 * time.Second)
		sendCmd(request{Cmd: CmdGetExitNodes})
	}()

	// Periodic refresh
	go func() {
		for range time.Tick(10 * time.Second) {
			sendCmd(request{Cmd: CmdGetExitNodes})
			sendCmd(request{Cmd: CmdGetStatus})
		}
	}()

	refreshBtn := widget.NewButton("Refresh Exit Nodes", func() {
		addLog("Refreshing exit nodes...")
		sendCmd(request{Cmd: CmdGetExitNodes})
	})

	controls := container.NewVBox(
		statusLabel,
		loginBtn,
		portContainer,
		connectBtn,
		widget.NewLabel("Exit Node:"),
		exitNodeSelect,
		refreshBtn,
		widget.NewLabel("Logs:"),
	)

	w.SetContent(container.NewBorder(
		controls, // Top
		nil,      // Bottom
		nil,      // Left
		nil,      // Right
		logScroll, // Center (expands)
	))

	w.Resize(fyne.NewSize(400, 600))
	w.ShowAndRun()
}

func runProxyMode() {
	// Pipes for communication
	cliToHostR, cliToHostW := io.Pipe()
	hostToCliR, hostToCliW := io.Pipe()

	// Logger setup
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ltime | log.Lshortfile)

	// Start Host
	go func() {
		hostinfo.SetApp("ts-browser-ext-cli")
		h := newHost(cliToHostR, hostToCliW)
		h.logf = func(f string, a ...any) {
			if *verboseFlag {
				log.Printf("[BACKEND] "+f, a...)
			}
		}

		// Start Proxy Listener
		ln := h.getProxyListener()
		port := ln.Addr().(*net.TCPAddr).Port
		if *verboseFlag {
			log.Printf("Proxy listening on localhost:%v", port)
		}
		h.send(&reply{ProcRunning: &procRunningResult{
			Port: port,
			Pid:  os.Getpid(),
		}})

		if err := h.readMessages(); err != nil {
			if *verboseFlag {
				log.Printf("host loop ended: %v", err)
			}
		}
	}()

	// Helper to send commands
	sendCmd := func(cmd request) {
		b, _ := json.Marshal(cmd)
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(b)))
		guiToHostW := cliToHostW // naming reuse
		guiToHostW.Write(lenBuf)
		guiToHostW.Write(b)
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

			var msg reply
			if err := json.Unmarshal(msgb, &msg); err != nil {
				continue
			}

			if msg.Init != nil && msg.Init.Error != "" {
				fmt.Fprintf(os.Stderr, "Error initializing: %s\n", msg.Init.Error)
				os.Exit(1)
			}

			if msg.ProcRunning != nil {
				// Log to stderr to ensure visibility alongside other logs
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
					var ip string
					for _, n := range msg.ExitNodes.Nodes {
						if n.Name == target || n.IP == target {
							ip = n.IP
							break
						}
					}
					if ip != "" {
						fmt.Printf("Setting exit node to %s (%s)...\n", target, ip)
						sendCmd(request{Cmd: CmdSetExitNode, ExitNodeIP: ip})
						// Clear flag to avoid repeated setting
						*exitNodeFlag = "" 
					} else {
						fmt.Fprintf(os.Stderr, "Exit node %q not found. Available nodes:\n", target)
						for _, n := range msg.ExitNodes.Nodes {
							fmt.Fprintf(os.Stderr, "  - %s (%s)\n", n.Name, n.IP)
						}
					}
				}
			}
		}
	}()

	// Init sequence
	go func() {
		time.Sleep(200 * time.Millisecond)
		// Use a fixed ID for CLI persistence, must be hex-like UUID
		sendCmd(request{Cmd: CmdInit, InitID: "12345678-0000-0000-0000-1234567890cd"})
		time.Sleep(500 * time.Millisecond)
		// Enable proxy immediately
		sendCmd(request{Cmd: CmdUp})
		// Get output nodes to set if needed
		if *exitNodeFlag != "" {
			sendCmd(request{Cmd: CmdGetExitNodes})
		}
		// Get status to check login
		sendCmd(request{Cmd: CmdGetStatus})
	}()

	// Wait for signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	fmt.Println("\nStopping...")
}
