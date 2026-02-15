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
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tailscale.com/hostinfo"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"tailscale-proxy/internal/proxy"
)

const (
	appName     = "tailscale-proxy-app"
	productName = "Proxy App for Tailscale (Community)"
	initID      = "12345678-1234-1234-1234-1234567890ab"
)

var (
	versionFlag  = flag.Bool("version", false, "display version information")
	verboseFlag  = flag.Bool("verbose", false, "enable verbose logging")
	hostnameFlag = flag.String("hostname", "tailscale-proxy-app", "hostname to use for the tailscale node")
)

func main() {
	flag.Parse()

	if *versionFlag {
		proxy.PrintVersion(productName)
		return
	}

	runGuiMode()
}

func runGuiMode() {
	a := app.New()
	w := a.NewWindow(fmt.Sprintf("%s %s", productName, proxy.Version))

	// Host <-> GUI communication pipes
	guiToHostR, guiToHostW := io.Pipe()
	hostToGuiR, hostToGuiW := io.Pipe()

	// Command Channel to prevent UI blocking
	cmdChan := make(chan proxy.Request, 16)

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

			if _, err := guiToHostW.Write(lenBuf); err != nil {
				log.Printf("Pipe write error: %v", err)
				break
			}
			if _, err := guiToHostW.Write(b); err != nil {
				log.Printf("Pipe write error: %v", err)
				break
			}
		}
	}()

	guiVerbose := *verboseFlag

	sendCmd := func(cmd proxy.Request) {
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
	richLogs.Wrapping = fyne.TextWrapBreak

	// Scroll container for logs
	logScroll := container.NewScroll(richLogs)

	// Log channel for thread-safe updates
	logChan := make(chan *widget.TextSegment, 64)

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
		}
	}

	clearLogs := func() {
		richLogs.Segments = nil
		richLogs.Refresh()
		addLog("Logs cleared.")
	}

	autoScroll := true

	// Log flusher goroutine
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
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
			if autoScroll {
				logScroll.Refresh()
				logScroll.ScrollToBottom()
			}
		}
	}()

	// Start the backend
	go func() {
		hostinfo.SetApp("tailscale-proxy-app")
		h := proxy.NewHost(guiToHostR, hostToGuiW)
		h.Verbose = guiVerbose
		h.HostName = *hostnameFlag
		h.StateDirName = appName

		h.Logf = func(f string, a ...any) {
			msg := fmt.Sprintf(f, a...)
			log.Println(msg)

			if !guiVerbose {
				cleanMsg := regexp.MustCompile(`\x1b\[[0-9;]*m`).ReplaceAllString(msg, "")
				lower := strings.ToLower(cleanMsg)

				if strings.HasPrefix(cleanMsg, "[") {
					return
				}

				noise := []string{
					"magicsock:", "wg:", "control:", "dns:", "wrapper:",
					"netmap", "monitor:", "link change:", "health(",
					"endpoints:", "derp", "program starting", "sent reply",
					"got command", "starting...", "link state", "onportupdate",
				}
				for _, p := range noise {
					if strings.Contains(lower, p) {
						return
					}
				}
			}
			addLog(msg)
		}

		ln := h.GetProxyListener()
		port := ln.Addr().(*net.TCPAddr).Port
		addLog(fmt.Sprintf("Proxy listening on localhost:%v", port))
		h.Send(&proxy.Reply{ProcRunning: &proxy.ProcRunningResult{
			Port: port,
			Pid:  os.Getpid(),
		}})

		if err := h.ReadMessages(); err != nil {
			log.Printf("host readMessages error: %v", err)
			addLog(fmt.Sprintf("Host Error: %v", err))
		}
	}()

	// UI State
	var exitNodes []proxy.ExitNode
	var loginURL string

	// Widgets
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
		sendCmd(proxy.Request{Cmd: proxy.CmdSetPort, Port: p})
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

	var currentSelection string = "None (Direct)"

	exitNodeSelect := widget.NewSelect([]string{"Loading nodes..."}, func(selected string) {
		cleanSelected := strings.TrimSuffix(selected, " (default)")
		currentSelection = cleanSelected
		if selected == "Loading nodes..." {
			return
		}
		if cleanSelected == "None (Direct)" {
			sendCmd(proxy.Request{Cmd: proxy.CmdSetExitNode, ExitNodeIP: ""})
			addLog("Set to Direct Mode (preference saved)")
			return
		}
		for _, node := range exitNodes {
			if node.Name == cleanSelected {
				sendCmd(proxy.Request{Cmd: proxy.CmdSetExitNode, ExitNodeIP: node.IP})
				addLog(fmt.Sprintf("Set Exit Node to %s (preference saved)", cleanSelected))
				return
			}
		}
	})
	exitNodeSelect.PlaceHolder = "Loading nodes..."

	saveDefaultBtn := widget.NewButton("Make Default", func() {
		if currentSelection == "" || currentSelection == "Loading nodes..." {
			return
		}
		addLog(fmt.Sprintf("Saving %s as default...", currentSelection))
		exitNodeSelect.OnChanged(currentSelection)
	})

	var connectBtn *widget.Button
	connectBtn = widget.NewButton("Connect to Tailscale", func() {
		if connectBtn.Text == "Connect to Tailscale" {
			sendCmd(proxy.Request{Cmd: proxy.CmdUp})
			connectBtn.SetText("Connecting...")
			connectBtn.Disable()
		} else {
			sendCmd(proxy.Request{Cmd: proxy.CmdDown})
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
			var msg proxy.Reply
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
				statusText := "Status: Disconnected"
				if msg.Status.Running {
					statusText = "Status: Connected"
				} else if msg.Status.State == "Starting" {
					statusText = "Status: Connecting..."
				} else if msg.Status.State == "NeedsLogin" || msg.Status.NeedsLogin {
					statusText = "Status: Login Required"
				} else if msg.Status.State != "" && msg.Status.State != "Stopped" && msg.Status.State != "NoState" {
					statusText = "Status: " + msg.Status.State
				}

				if msg.Status.NeedsLogin {
					loginURL = msg.Status.BrowseToURL
					loginBtn.Show()
				} else {
					loginBtn.Hide()
				}
				statusData.Set(statusText)

				if msg.Status.Running {
					connectBtn.SetText("Disconnect")
					connectBtn.Importance = widget.DangerImportance
					connectBtn.Enable()
				} else if msg.Status.State == "Starting" {
					connectBtn.SetText("Connecting...")
					connectBtn.Disable()
				} else {
					connectBtn.SetText("Connect to Tailscale")
					connectBtn.Importance = widget.HighImportance
					connectBtn.Enable()
				}
			}
			if msg.ExitNodes != nil {
				var options []string
				options = append(options, "None (Direct)")
				exitNodes = msg.ExitNodes.Nodes
				var selectedText string = "None (Direct)"

				for _, n := range exitNodes {
					name := n.Name
					if n.IP == msg.ExitNodes.SavedDefaultIP {
						name += " (default)"
					}
					options = append(options, name)
					if n.IP == msg.ExitNodes.CurrentNode {
						selectedText = name
					}
				}
				exitNodeSelect.Options = options
				exitNodeSelect.Refresh()

				exitNodeSelect.SetSelected(selectedText)
				currentSelection = strings.TrimSuffix(selectedText, " (default)")
				if selectedText != "None (Direct)" {
					statusData.Set(fmt.Sprintf("Status: Connected via %s", currentSelection))
				} else {
					statusData.Set("Status: Connected (Direct)")
				}
			}
		}
	}()

	// Init sequence
	go func() {
		time.Sleep(500 * time.Millisecond)
		addLog("Sending Init command...")
		sendCmd(proxy.Request{Cmd: proxy.CmdInit, InitID: initID})
		time.Sleep(500 * time.Millisecond)
		sendCmd(proxy.Request{Cmd: proxy.CmdGetStatus})
		time.Sleep(500 * time.Millisecond)
		addLog("Auto-connecting...")
		sendCmd(proxy.Request{Cmd: proxy.CmdUp})
		time.Sleep(2 * time.Second)
		sendCmd(proxy.Request{Cmd: proxy.CmdGetExitNodes})
		time.Sleep(2 * time.Second)
		sendCmd(proxy.Request{Cmd: proxy.CmdGetExitNodes})
	}()

	// Periodic refresh
	go func() {
		for range time.Tick(10 * time.Second) {
			sendCmd(proxy.Request{Cmd: proxy.CmdGetExitNodes})
			sendCmd(proxy.Request{Cmd: proxy.CmdGetStatus})
		}
	}()

	refreshBtn := widget.NewButton("Refresh Exit Nodes", func() {
		addLog("Refreshing exit nodes...")
		sendCmd(proxy.Request{Cmd: proxy.CmdGetExitNodes})
	})

	content := container.NewVBox(
		statusLabel,
		loginBtn,
		portContainer,
		connectBtn,
		widget.NewSeparator(),
		widget.NewLabel("Exit Node:"),
		exitNodeSelect,
		container.NewHBox(
			saveDefaultBtn,
			refreshBtn,
		),
		widget.NewSeparator(),
		container.NewHBox(
			widget.NewLabel("Logs:"),
			layout.NewSpacer(),
			widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
				w.Clipboard().SetContent(richLogs.String())
				addLog("Logs copied to clipboard.")
			}),
			widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
				clearLogs()
			}),
		),
		container.NewHBox(
			func() *widget.Button {
				var btn *widget.Button
				update := func() {
					if guiVerbose {
						btn.SetText("Debug Logs: ON")
						btn.Importance = widget.WarningImportance
					} else {
						btn.SetText("Debug Logs: OFF")
						btn.Importance = widget.MediumImportance
					}
				}
				btn = widget.NewButton("", func() {
					guiVerbose = !guiVerbose
					update()
					if guiVerbose {
						addLog("Detailed logging enabled.")
					} else {
						addLog("Detailed logging disabled.")
					}
				})
				update()
				return btn
			}(),
			func() *widget.Button {
				var btn *widget.Button
				update := func() {
					if autoScroll {
						btn.SetText("Auto-scroll: ON")
						btn.Importance = widget.SuccessImportance
					} else {
						btn.SetText("Auto-scroll: OFF")
						btn.Importance = widget.MediumImportance
					}
				}
				btn = widget.NewButton("", func() {
					autoScroll = !autoScroll
					update()
				})
				update()
				return btn
			}(),
		),
	)

	disclaimer := widget.NewLabelWithStyle("Independent Community Project - Not an official Tailscale product",
		fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

	w.SetContent(container.NewBorder(
		content,    // Top
		disclaimer, // Bottom
		nil,
		nil,
		logScroll, // Center (expands)
	))

	w.Resize(fyne.NewSize(450, 650))
	w.ShowAndRun()
}
