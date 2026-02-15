package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// TestProxyHandler verifies that the proxy handler correctly forwards requests
// using the injected dialer, without needing a real Tailscale connection.
func TestProxyHandler(t *testing.T) {
	// 1. Start a dummy target server (what we want to reach through the proxy)
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from Target")
	})
	targetServer := httptest.NewServer(targetHandler)
	defer targetServer.Close()

	// 2. Create the host with a mock dialer
	// The mock dialer always connects to our local targetServer, ignoring the requested address.
	h := &host{
		logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}
	h.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// In a real proxy, we'd dial 'addr'. Here we hijack it to our test server.
		// We use targetServer.Listener.Addr().Network() to match the test server's listener type (tcp)
		return net.Dial(targetServer.Listener.Addr().Network(), targetServer.Listener.Addr().String())
	}
	
	// Initialize other required fields for httpProxyHandler if any
	// h.httpProxyHandler() uses h.userDial which uses h.dialer. 
	// It constructs httputil.ReverseProxy.

	// 3. Start the Proxy Server
	proxyHandler := h.httpProxyHandler()
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// 4. Send a request THROUGH the proxy
	// We want to fetch "http://example.com/" (or anything), and expect the proxy
	// to route it via our dialer to the targetServer, which returns "Hello from Target".
	
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyServer.URL)
		},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("Failed to issue request through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "Hello from Target" {
		t.Errorf("Expected 'Hello from Target', got %q", string(body))
	}
}

// TestCLICommands verifies the CLI command loop logic (readMessages/handleMessage)
// by simulating stdin/stdout with pipes.
func TestCLICommands(t *testing.T) {
	// 1. Setup Pipes
	// CLI writes to cliW -> host reads from hostR
	hostR, cliW := io.Pipe()
	// Host writes to hostW -> CLI reads from cliR
	cliR, hostW := io.Pipe()

	// 2. Initialize Host
	h := newHost(hostR, hostW)
	// Silence logs for test cleaniness (or capture them if needed)
	h.logf = func(f string, a ...any) { t.Logf(f, a...) }

	// 3. Start the read loop in a goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Initialize the host state that handleSetExitNode might expect?
		// handleMessage calls specific handlers. 
		// CmdSetPort acts on h.customPort.
		if err := h.readMessages(); err != nil && err != io.EOF {
			t.Logf("readMessages ended: %v", err)
		}
	}()

	// 4. Send a Command: CmdSetPort
	// We use the same encoding logic as the CLI
	cmd := request{Cmd: CmdSetPort, Port: 12345}
	b, _ := json.Marshal(cmd)
	// Write length prefix (uint32 little endian)
	// NOTE: We need binary package, it's imported above? No, need to add import "encoding/binary"
	// Wait, I forgot "encoding/binary" and "net/url" in the import list above. 
	// I will fix imports in the actual file write.
	
	// Helper to write message
	writeMsg := func(w io.Writer, b []byte) {
		lenBuf := []byte{0, 0, 0, 0}
		// manual little endian just for test or use library
		length := uint32(len(b))
		lenBuf[0] = byte(length)
		lenBuf[1] = byte(length >> 8)
		lenBuf[2] = byte(length >> 16)
		lenBuf[3] = byte(length >> 24)
		w.Write(lenBuf)
		w.Write(b)
	}

	writeMsg(cliW, b)

	// 5. Read Response
	// The host might send multiple responses depending on logic (sendStatus etc).
	// But CmdSetPort triggers h.send(&reply{ProcRunning: ...}) via h.handleInit? 
	// Wait, CmdSetPort implementation:
	/*
	case CmdSetPort:
		h.mu.Lock()
		h.customPort = msg.Port
		h.mu.Unlock()
		// It creates a new listener! This might fail in test if we don't mock getProxyListener?
		// getProxyListenerLocked calls net.Listen. 
		// This tries to bind to 127.0.0.1:12345. 
		// This makes the test slightly integration-y but acceptable for unit test if port is free.
		// If it binds, it then sends ProcRunning.
	*/
	
	// Ideally we mock getProxyListener too, but that's a method. 
	// We can't mock methods easily without interface.
	// For now, let's try a simpler command or rely on binding working (it's localhost).
	// Or use CmdGetExitNodes?
	
	// Let's test CmdGetStatus instead. It doesn't strictly depend on side effects.
	cmdStatus := request{Cmd: CmdGetStatus}
	b2, _ := json.Marshal(cmdStatus)
	writeMsg(cliW, b2)

	// 6. Read Responses until we get Status
	// CmdSetPort might send ProcRunning.
	// CmdGetStatus sends Status.
	
	timeout := time.After(2 * time.Second)
	var statusReply *status
	
	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for Status reply")
		default:
			// Read a message
			// We need to use the same logic as client
			lenBuf := make([]byte, 4)
			_, err := io.ReadFull(cliR, lenBuf)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			l := uint32(lenBuf[0]) | uint32(lenBuf[1])<<8 | uint32(lenBuf[2])<<16 | uint32(lenBuf[3])<<24
			
			msgBuf := make([]byte, l)
			io.ReadFull(cliR, msgBuf)
			
			var rep reply
			if err := json.Unmarshal(msgBuf, &rep); err != nil {
				t.Logf("JSON error: %v", err)
				continue
			}
			
			if rep.Status != nil {
				statusReply = rep.Status
				goto Done
			}
		}
	}
Done:

	if statusReply == nil {
		t.Fatal("Did not get Status reply")
	}
	
	if statusReply.Running {
		t.Error("Expected not running")
	}

	// Cleanup
	cliW.Close() // Sends EOF to host
	cliR.Close()
	wg.Wait()
}
