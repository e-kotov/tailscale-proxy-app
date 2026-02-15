package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof" // Register pprof handlers
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/csrf"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/web"
	"tailscale.com/ipn"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

// Cmd represents a command from the client (browser extension, GUI, or CLI).
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

// Request is a message from the client.
type Request struct {
	Cmd        Cmd    `json:"cmd"`
	Port       int    `json:"port,omitempty"`
	InitID     string `json:"initID,omitempty"`
	AuthKey    string `json:"authKey,omitempty"`
	ExitNodeIP string `json:"exitNodeIP,omitempty"`
}

// Reply is a message to the client.
type Reply struct {
	ProcRunning *ProcRunningResult `json:"procRunning,omitempty"`
	Status      *Status            `json:"status,omitempty"`
	Init        *InitResult        `json:"init,omitempty"`
	ExitNodes   *ExitNodesResult   `json:"exitNodes,omitempty"`
	ExitNodeSet *ExitNodeSetResult `json:"exitNodeSet,omitempty"`
}

// ExitNode represents an available exit node.
type ExitNode struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// ExitNodesResult is the response to a get-exit-nodes command.
type ExitNodesResult struct {
	Nodes          []ExitNode `json:"nodes"`
	CurrentNode    string     `json:"currentNode"`
	SavedDefaultIP string     `json:"savedDefaultIP"`
	Error          string     `json:"error,omitempty"`
}

// ExitNodeSetResult is the response to a set-exit-node command.
type ExitNodeSetResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// ProcRunningResult is sent when the proxy process starts.
type ProcRunningResult struct {
	Port  int    `json:"port"`
	Pid   int    `json:"pid"`
	Error string `json:"error"`
}

// InitResult is the response to an init command.
type InitResult struct {
	Error string `json:"error"`
}

// Status represents the current state of the proxy.
type Status struct {
	Running     bool   `json:"running"`
	State       string `json:"state"`
	Tailnet     string `json:"tailnet"`
	Error       string `json:"error,omitempty"`
	NeedsLogin  bool   `json:"needsLogin,omitempty"`
	BrowseToURL string `json:"browseToURL"`
}

// Preferences stores user preferences like exit node selection.
type Preferences struct {
	ExitNodeIP string `json:"exitNodeIP"`
}

const MaxMsgSize = 1 << 20

// Host manages the Tailscale proxy backend.
type Host struct {
	br   *bufio.Reader
	w    io.Writer
	Logf logger.Logf

	wmu sync.Mutex // guards writing to w

	lenBuf [4]byte // owned by ReadMessages

	mu              sync.Mutex
	watchDead       bool
	lastNetmap      *netmap.NetworkMap
	lastState       ipn.State
	lastBrowseToURL string
	ctx             context.Context
	cancelCtx       context.CancelFunc
	ts              *tsnet.Server
	ws              *web.Server
	ln              net.Listener
	wantUp          bool
	CustomPort      int
	dialer          func(ctx context.Context, network, addr string) (net.Conn, error)

	// Configuration set by the caller (CLI or GUI).
	Verbose      bool
	HostName     string
	StateDirName string // e.g. "tailscale-proxy-cli" or "tailscale-proxy-app"
}

// NewHost creates a new Host with the given reader/writer for message passing.
func NewHost(r io.Reader, w io.Writer) *Host {
	h := &Host{
		br:   bufio.NewReaderSize(r, 1<<20),
		w:    w,
		Logf: log.Printf,
	}
	h.ts = &tsnet.Server{
		RunWebClient: true,
		Logf: func(f string, a ...any) {
			h.Logf(f, a...)
		},
	}
	h.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		h.mu.Lock()
		sys := h.ts.Sys()
		h.mu.Unlock()
		if sys == nil {
			return nil, fmt.Errorf("no tsnet.Server")
		}
		return sys.Dialer.Get().UserDial(ctx, network, addr)
	}
	return h
}

// ReadMessages reads and handles messages in a loop until an error occurs.
func (h *Host) ReadMessages() error {
	for {
		msg, err := h.readMessage()
		if err != nil {
			return err
		}
		if err := h.HandleMessage(msg); err != nil {
			h.Logf("error handling message %v: %v", msg, err)
			return err
		}
	}
}

// HandleMessage dispatches a request to the appropriate handler.
func (h *Host) HandleMessage(msg *Request) error {
	switch msg.Cmd {
	case CmdInit:
		return h.handleInit(msg)
	case CmdGetStatus:
		h.SendStatus()
	case CmdUp:
		return h.handleUp()
	case CmdDown:
		return h.handleDown()
	case CmdGetExitNodes:
		h.handleGetExitNodes()
	case CmdSetExitNode:
		h.handleSetExitNode(msg.ExitNodeIP)
	case CmdSetPort:
		if err := h.RestartListener(msg.Port); err != nil {
			h.Logf("failed to set port: %v", err)
		}
	default:
		h.Logf("unknown command %q", msg.Cmd)
	}
	return nil
}

func (h *Host) handleUp() error {
	return h.setWantRunning(true)
}

func (h *Host) handleDown() error {
	return h.setWantRunning(false)
}

func (h *Host) handleGetExitNodes() {
	result := &ExitNodesResult{}

	h.mu.Lock()
	if h.ts.Sys() == nil {
		h.mu.Unlock()
		result.Error = "not initialized"
		h.Send(&Reply{ExitNodes: result})
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc, err := h.ts.LocalClient()
	if err != nil {
		result.Error = err.Error()
		h.Send(&Reply{ExitNodes: result})
		return
	}

	st, err := lc.Status(ctx)
	if err != nil {
		result.Error = err.Error()
		h.Send(&Reply{ExitNodes: result})
		return
	}

	h.Logf("Status check: %d peers found", len(st.Peer))

	for _, peer := range st.Peer {
		if peer.ExitNodeOption {
			ip := ""
			if len(peer.TailscaleIPs) > 0 {
				ip = peer.TailscaleIPs[0].String()
			}
			if ip != "" {
				name := peer.HostName
				if peer.DNSName != "" {
					name = strings.TrimSuffix(peer.DNSName, ".")
					if idx := strings.Index(name, "."); idx > 0 {
						name = name[:idx]
					}
				}
				result.Nodes = append(result.Nodes, ExitNode{
					Name: name,
					IP:   ip,
				})
				if peer.ExitNode {
					result.CurrentNode = ip
				}
			}
		}
	}

	h.Logf("Found %d exit nodes", len(result.Nodes))

	if prefs, err := h.loadPrefs(); err == nil {
		result.SavedDefaultIP = prefs.ExitNodeIP
	}

	h.Send(&Reply{ExitNodes: result})
}

func (h *Host) handleSetExitNode(exitNodeIP string) {
	result := &ExitNodeSetResult{}

	h.mu.Lock()
	if h.ts.Sys() == nil {
		h.mu.Unlock()
		result.Error = "not initialized"
		h.Send(&Reply{ExitNodeSet: result})
		return
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc, err := h.ts.LocalClient()
	if err != nil {
		result.Error = err.Error()
		h.Send(&Reply{ExitNodeSet: result})
		return
	}

	var exitIP netip.Addr
	if exitNodeIP != "" {
		exitIP, err = netip.ParseAddr(exitNodeIP)
		if err != nil {
			result.Error = fmt.Sprintf("invalid exit node IP: %v", err)
			h.Send(&Reply{ExitNodeSet: result})
			return
		}
	}

	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
		ExitNodeIDSet: true,
		Prefs: ipn.Prefs{
			ExitNodeIP: exitIP,
			ExitNodeID: "",
		},
	}); err != nil {
		result.Error = fmt.Sprintf("failed to set exit node: %v", err)
		h.Send(&Reply{ExitNodeSet: result})
		return
	}

	if err := h.savePrefs(&Preferences{ExitNodeIP: exitNodeIP}); err != nil {
		h.Logf("failed to save prefs: %v", err)
	}

	// Update State File
	UpdateStateExitNode(h.StateDirName, exitNodeIP)

	result.Success = true
	h.Send(&Reply{ExitNodeSet: result})
	h.SendStatus()
	h.handleGetExitNodes()
}

func (h *Host) setWantRunning(want bool) error {
	defer h.SendStatus()
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

func (h *Host) handleInit(msg *Request) (ret error) {
	defer func() {
		var errMsg string
		if ret != nil {
			errMsg = ret.Error()
		}
		h.Send(&Reply{
			Init: &InitResult{Error: errMsg},
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
	h.ts.Hostname = h.HostName
	if msg.AuthKey != "" {
		h.ts.AuthKey = msg.AuthKey
	}

	confDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("getting user config dir: %w", err)
	}
	h.ts.Dir = filepath.Join(confDir, h.StateDirName, id)

	h.Logf("Starting...")
	if err := h.ts.Start(); err != nil {
		return fmt.Errorf("starting tsnet.Server: %w", err)
	}
	h.Logf("Started")

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
		Mode:        web.LoginServerMode,
		LocalClient: lc,
	})
	if err != nil {
		return fmt.Errorf("NewServer: %w", err)
	}

	// Restore preferences
	if prefs, err := h.loadPrefs(); err == nil && prefs.ExitNodeIP != "" {
		h.Logf("Restoring exit node: %s", prefs.ExitNodeIP)
		ip, err := netip.ParseAddr(prefs.ExitNodeIP)
		if err == nil {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{
					ExitNodeIPSet: true,
					ExitNodeIDSet: true,
					Prefs: ipn.Prefs{
						ExitNodeIP: ip,
						ExitNodeID: "",
					},
				}); err != nil {
					h.Logf("failed to restore exit node: %v", err)
				}
			}()
		}
	}

	return nil
}

func (h *Host) watchIPNBus(wc *tailscale.IPNBusWatcher) {
	h.mu.Lock()
	h.watchDead = false
	h.mu.Unlock()

	for h.updateFromWatcher(wc) {
	}
}

func (h *Host) updateFromWatcher(wc *tailscale.IPNBusWatcher) bool {
	n, err := wc.Next()

	defer h.SendStatus()

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
	}
	return true
}

func (h *Host) getPrefsPath() string {
	return filepath.Join(h.ts.Dir, "params.json")
}

func (h *Host) loadPrefs() (*Preferences, error) {
	p := new(Preferences)
	b, err := os.ReadFile(h.getPrefsPath())
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPrefs returns the current preferences (exported for CLI/GUI use).
func (h *Host) LoadPrefs() (*Preferences, error) {
	return h.loadPrefs()
}

func (h *Host) savePrefs(p *Preferences) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(h.getPrefsPath(), b, 0644)
}

// Send sends a reply message to the client.
func (h *Host) Send(msg *Reply) error {
	msgb, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encoding of message: %w", err)
	}
	h.Logf("sent reply: %s", msgb)
	if len(msgb) > MaxMsgSize {
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

// GetProxyListener returns or creates the proxy listener.
func (h *Host) GetProxyListener() net.Listener {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.getProxyListenerLocked()
}

func (h *Host) getProxyListenerLocked() net.Listener {
	if h.ln != nil {
		return h.ln
	}
	var err error
	port := 57320
	if h.CustomPort != 0 {
		port = h.CustomPort
	}
	h.ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		h.Logf("Port %d unavailable (%v), falling back to random port", port, err)
		h.ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
	}
	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(h.ln)

	hs := &http.Server{Handler: h.HttpProxyHandler()}
	if !h.Verbose {
		hs.ErrorLog = log.New(io.Discard, "", 0)
	}
	go func() {
		if err := hs.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP proxy exited: %v", err)
		}
	}()
	ss := &socks5.Server{
		Logf: func(f string, v ...interface{}) {
			if h.Verbose {
				h.Logf("socks5: "+f, v...)
			}
		},
		Dialer: h.userDial,
	}
	go func() {
		if err := ss.Serve(socksListener); err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS5 server exited: %v", err)
			}
		}
	}()
	return h.ln
}

// RestartListener closes the current listener and starts a new one on the given port.
func (h *Host) RestartListener(port int) error {
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

	socksListener, httpListener := proxymux.SplitSOCKSAndHTTP(h.ln)
	hs := &http.Server{Handler: h.HttpProxyHandler()}
	if !h.Verbose {
		hs.ErrorLog = log.New(io.Discard, "", 0)
	}
	go func() {
		if err := hs.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP proxy exited: %v", err)
		}
	}()
	ss := &socks5.Server{
		Logf: func(f string, v ...interface{}) {
			if h.Verbose {
				h.Logf("socks5: "+f, v...)
			}
		},
		Dialer: h.userDial,
	}
	go func() {
		if err := ss.Serve(socksListener); err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS5 server exited: %v", err)
			}
		}
	}()

	h.Logf("Restarted proxy on port %d", port)

	go func() {
		h.Send(&Reply{ProcRunning: &ProcRunningResult{
			Port: ln.Addr().(*net.TCPAddr).Port,
			Pid:  os.Getpid(),
		}})
	}()

	return nil
}

func (h *Host) userDial(ctx context.Context, netw, addr string) (net.Conn, error) {
	if h.dialer != nil {
		return h.dialer(ctx, netw, addr)
	}
	return nil, fmt.Errorf("no dialer configured")
}

// SendStatus sends the current status to the client.
func (h *Host) SendStatus() {
	st := &Status{}
	h.mu.Lock()
	st.Running = h.lastState == ipn.Running
	st.State = h.lastState.String()
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

	if err := h.Send(&Reply{Status: st}); err != nil {
		h.Logf("failed to send status: %v", err)
	}
}

func (h *Host) readMessage() (*Request, error) {
	if _, err := io.ReadFull(h.br, h.lenBuf[:]); err != nil {
		return nil, err
	}
	msgSize := binary.LittleEndian.Uint32(h.lenBuf[:])
	if msgSize > MaxMsgSize {
		return nil, fmt.Errorf("message size too big (%v)", msgSize)
	}
	msgb := make([]byte, msgSize)
	if n, err := io.ReadFull(h.br, msgb); err != nil {
		return nil, fmt.Errorf("read %v of %v bytes in message with error %v", n, msgSize, err)
	}
	msg := new(Request)
	if err := json.Unmarshal(msgb, msg); err != nil {
		return nil, fmt.Errorf("invalid JSON decoding of message: %w", err)
	}
	h.Logf("got command %q: %s", msg.Cmd, msgb)
	return msg, nil
}

// HttpProxyHandler returns an HTTP proxy http.Handler using the
// provided backend dialer.
func (h *Host) HttpProxyHandler() http.Handler {
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {},
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
