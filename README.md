# Proxy App for Tailscale (Community)

![CI](https://github.com/e-kotov/tailscale-proxy-app/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/e-kotov/tailscale-proxy-app/actions/workflows/release.yml/badge.svg)
![Downloads](https://img.shields.io/github/downloads/e-kotov/tailscale-proxy-app/total)

Standalone userspace egress proxies for Tailscale. Run any app through your exit nodes without root permissions or system-wide VPN settings.

> [!IMPORTANT]
> **Migration Note (v0.1.0+):** This project has been split into two separate binaries. The state directory has changed, so you will need to re-authenticate after upgrading.

## 🔀 Two Ways to Proxy

| Feature | [💻 CLI](https://github.com/e-kotov/tailscale-proxy-app#%EF%B8%8F-cli-installation-tailscale-proxy) | [🖥️ GUI](https://github.com/e-kotov/tailscale-proxy-app#%EF%B8%8F-desktop-gui-installation-tailscale-proxy-app) |
| :--- | :--- | :--- |
| **Binary Name** | `tailscale-proxy` | `tailscale-proxy-app` |
| **Build** | Lightweight, No CGO | Full GUI (Fyne) |
| **Size** | ~19 MB | ~38 MB |
| **Primary Use** | Servers, scripts, power users | Desktop users |
| **Platforms** | macOS, Linux, Windows | macOS, Linux, Windows |

## ⚠️ Disclaimer: Highly Experimental

This project is **highly experimental** and is provided "AS IS", without warranty of any kind. It is a fork/adaptation of the [Tailscale Browser Extension](https://github.com/tailscale/ts-browser-ext) backend. It is **not** an official Tailscale product.

## 🛠️ Installation

### 🍎 macOS

```bash
# Install the lightweight CLI
brew install e-kotov/tap/tailscale-proxy

# OR install the full Desktop GUI app
brew install --cask e-kotov/tap/tailscale-proxy-app
```

### 🐧 Linux

**Recommended (Native):**
Download the `.deb` or `.rpm` for either `tailscale-proxy` or `tailscale-proxy-app` from the [Releases](https://github.com/e-kotov/tailscale-proxy-app/releases) page.

**Homebrew (CLI only):**
```bash
brew install e-kotov/tap/tailscale-proxy
```

### 🪟 Windows

**Scoop (CLI only):**
```bash
scoop bucket add e-kotov https://github.com/e-kotov/homebrew-tap
scoop install tailscale-proxy
```

*For the GUI on Windows, download the `.zip` from the [Releases](https://github.com/e-kotov/tailscale-proxy-app/releases) page.*

## 🚀 Usage

### 🖥️ Desktop GUI (`tailscale-proxy-app`)
Specifically designed for desktop experience with a status window, rich logs, and easy exit node selection.
- **macOS:** Open `Tailscale Proxy App` from Applications.
- **Linux/Windows:** Run the `tailscale-proxy-app` binary.

### 💻 CLI (`tailscale-proxy`)
Optimized for terminal use and server environments.

**Interactive Auth:**
```bash
tailscale-proxy
# Follow the printed Tailscale login URL
```

**Daemon Mode:**
```bash
tailscale-proxy --daemon --port=1080
tailscale-proxy --status
tailscale-proxy --stop
```

## ⚙️ How it Works
1.  **Selective Routing**: Unlike the standard Tailscale client, this app only routes traffic for applications you explicitly configure to use the proxy (SOCKS5/HTTP).
2.  **Userspace Networking**: Runs entirely in userspace using `tsnet`. No root/sudo required.
3.  **Local Proxy**: Exposes a local port (default: `57320`) that handles both SOCKS5 and HTTP CONNECT traffic.

## 🛠️ Development

```bash
# Build the macOS App Bundle
make app

# Build CLI and GUI binaries
make cli
make gui
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
Based on code Copyright (c) 2020 Tailscale Inc & AUTHORS.
