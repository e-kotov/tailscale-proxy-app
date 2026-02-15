# Proxy App for Tailscale (Community)

![CI](https://github.com/e-kotov/tailscale-proxy-app/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/e-kotov/tailscale-proxy-app/actions/workflows/release.yml/badge.svg)

A standalone GUI application that acts as a local **userspace egress proxy** for Tailscale.

This application allows your computer to route traffic through specific Tailscale Exit Nodes without needing full VPN permissions (root/sudo) or changing system-wide network settings. It exposes a local SOCKS5/HTTP proxy port that you can configure individual applications (like browsers, curl, or development tools) to use.

## ⚠️ Disclaimer: Highly Experimental

This project is **highly experimental** and is provided "AS IS", without warranty of any kind. 

It is a fork/adaptation of the [Tailscale Browser Extension](https://github.com/tailscale/ts-browser-ext) backend, repurposed to run as a standalone desktop application with a GUI. It is **not** an official Tailscale product.

## Features

-   **Selective Routing / "Split Tunneling"**: Unlike the standard Tailscale client which routes *all* traffic when an exit node is selected, this app only routes traffic for applications you explicitly configure to use the proxy. This allows you to use an exit node for just a specific browser, script, or command while keeping the rest of your system on your direct internet connection.
-   **Userspace Networking**: Runs entirely in userspace using `tsnet`. No root required.
-   **Exit Node Selection**: Choose any available exit node from your tailnet directly from the GUI.
-   **Local Proxy**: Exposes a local port (e.g., `1080` or `8080`) that handles both **SOCKS5** and **HTTP CONNECT** traffic.
-   **Cross-Platform**: Built with Go and Fyne, runs on macOS, Linux, and Windows.

## Use Cases

*   **Geolocated Browsing**: Route one browser window through an exit node in another country to test geo-restricted content, while keeping your main browser on your local connection.
*   **Development & Testing**: Test your application's behavior from a different network perspective.
*   **Privacy per App**: Isolate traffic for specific sensitive applications.

## Installation & Usage

Choose the easiest way for your platform:

### 🍎 macOS (Homebrew)
```bash
brew install e-kotov/tap/tailscale-proxy-app
```

### 🪟 Windows (Scoop)
```bash
scoop bucket add e-kotov https://github.com/e-kotov/homebrew-tap
scoop install tailscale-proxy-app
```
*Or download the `.zip` from the [Releases](https://github.com/e-kotov/tailscale-proxy-app/releases) page.*

### 🐧 Linux
**Recommended (Native):**
Download the `.deb` or `.rpm` from the [Releases](https://github.com/e-kotov/tailscale-proxy-app/releases) page and install:
```bash
# Ubuntu/Debian
sudo apt install ./proxy-app-for-tailscale.deb

# Fedora/RPM
sudo dnf install ./proxy-app-for-tailscale.rpm
```

**Homebrew (Optional):**
```bash
brew install e-kotov/tap/tailscale-proxy-app
```

## Usage Modes

This application can be run in two modes:

### 🎮 GUI Mode (Default)
Ideal for desktop users.
```bash
proxy-app-for-tailscale --gui
```
*(On macOS, simply open the `TailscaleProxy.app`)*

### ⌨️ CLI Mode
Ideal for headless servers, terminal power users, or automation scripts.

**First Run / Authentication:**
To log in, run the app interactively once. It will print a login URL if needed.
```bash
# Run interactively to authenticate
tailscale-proxy-app
# Output: Auth Required! Please visit: https://login.tailscale.com/...
```
*Alternatively, use a headless auth key:*
```bash
proxy-app-for-tailscale --auth-key="tskey-auth-..."
```

**Background / Daemon Mode:**
Once authenticated (or if using an auth-key), you can run as a background service.
```bash
# Start in background
proxy-app-for-tailscale --daemon --port=1080 --log-file=proxy.log

# Check status
proxy-app-for-tailscale --status

# Stop the background process
proxy-app-for-tailscale --stop

# Logout (clear state)
proxy-app-for-tailscale --logout
```

**Available Flags (as of v.0.0.2 - may change closer to more stable release!):**
- `--port`: Local port to listen on (default: `57320`).
- `--exit-node`: Pre-select an exit node by name or IP.
- `--hostname`: Hostname to use for the Tailscale node (default: `proxy-app-for-tailscale`).
- `--daemon`: Run the process in the background.
- `--stop`: Stop the running background process.
- `--status`: Check if the background process is running.
- `--log-file`: Path to a file for logging (default: stderr).
- `--quiet`: Silence all standard output.
- `--logout`: Force logout and remove state data.
- `--auth-key`: Provide a Tailscale Auth Key for headless login (e.g. `tskey-auth-...`).
- `--pprof-port`: Port to listen on for pprof debugging (default: 0/disabled).
- `--version`: Show version information.

## How to use
1.  **Run:** Open the installed application or use the CLI.
2.  **Connect:**
    - Log in to Tailscale (follow the instructions).
    - Select an exit node (optional).
    - Click **Connect** (GUI) or it will happen automatically (CLI).
3.  **Config:** Configure your browser or app to use the proxy (default port: `57320`).

## Development & Local Build

If you want to build the application from source:

```bash
# Build the macOS App Bundle
make app

# Build just the CLI binary (Linux/Windows/macOS)
make cli
```
*(Requires Go 1.22+ and a C compiler for Fyne GUI elements).*

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

Based on code Copyright (c) 2020 Tailscale Inc & AUTHORS.
