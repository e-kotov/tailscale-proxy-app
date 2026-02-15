package proxy

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
	// 1. Start a dummy target server
	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from Target")
	})
	targetServer := httptest.NewServer(targetHandler)
	defer targetServer.Close()

	// 2. Create the host with a mock dialer
	h := &Host{
		Logf: func(format string, args ...any) {
			t.Logf(format, args...)
		},
	}
	h.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(targetServer.Listener.Addr().Network(), targetServer.Listener.Addr().String())
	}

	// 3. Start the Proxy Server
	proxyHandler := h.HttpProxyHandler()
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()

	// 4. Send a request THROUGH the proxy
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

// TestCLICommands verifies the command loop logic (ReadMessages/HandleMessage)
// by simulating stdin/stdout with pipes.
func TestCLICommands(t *testing.T) {
	hostR, cliW := io.Pipe()
	cliR, hostW := io.Pipe()

	h := NewHost(hostR, hostW)
	h.Logf = func(f string, a ...any) { t.Logf(f, a...) }

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := h.ReadMessages(); err != nil && err != io.EOF {
			t.Logf("ReadMessages ended: %v", err)
		}
	}()

	// Helper to write message
	writeMsg := func(w io.Writer, b []byte) {
		lenBuf := []byte{0, 0, 0, 0}
		length := uint32(len(b))
		lenBuf[0] = byte(length)
		lenBuf[1] = byte(length >> 8)
		lenBuf[2] = byte(length >> 16)
		lenBuf[3] = byte(length >> 24)
		w.Write(lenBuf)
		w.Write(b)
	}

	// Send CmdSetPort
	cmd := Request{Cmd: CmdSetPort, Port: 12345}
	b, _ := json.Marshal(cmd)
	writeMsg(cliW, b)

	// Send CmdGetStatus
	cmdStatus := Request{Cmd: CmdGetStatus}
	b2, _ := json.Marshal(cmdStatus)
	writeMsg(cliW, b2)

	// Read Responses until we get Status
	timeout := time.After(2 * time.Second)
	var statusReply *Status

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for Status reply")
		default:
			lenBuf := make([]byte, 4)
			_, err := io.ReadFull(cliR, lenBuf)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			l := uint32(lenBuf[0]) | uint32(lenBuf[1])<<8 | uint32(lenBuf[2])<<16 | uint32(lenBuf[3])<<24

			msgBuf := make([]byte, l)
			io.ReadFull(cliR, msgBuf)

			var rep Reply
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

	cliW.Close()
	cliR.Close()
	wg.Wait()
}
