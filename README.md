# Proxy App for Tailscale (Community)

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
brew install e-kotov/tap/proxy-app-for-tailscale
```

### 🪟 Windows (Scoop)
```bash
scoop bucket add e-kotov https://github.com/e-kotov/homebrew-tap
scoop install proxy-app-for-tailscale
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
brew install e-kotov/tap/proxy-app-for-tailscale
```

## How to use
1.  **Run:** Open the installed application.
2.  **Connect:**
    - Log in to Tailscale (follow the instructions in the GUI).
    - Select an exit node (optional).
    - Click **Connect**.
3.  **Config:** Configure your browser or app to use the proxy (default port: `57320`).

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

Based on code Copyright (c) 2020 Tailscale Inc & AUTHORS.
