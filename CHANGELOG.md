# Release v0.1.0 - CLI/GUI Split

> [!CAUTION]
> **BREAKING CHANGE:** This release restructures the application into two separate binaries.
> The internal state directory has changed, so **re-authentication is required** after upgrading.
> Your existing `tailscale-browser-ext/` data will not be used by the new binaries.

## 🔀 Architecture: Binary Split

The project is now split into two independently installable programs:

| Binary | Name | CGO | Description |
|--------|------|-----|-------------|
| **CLI** | `tailscale-proxy` | No | Lightweight CLI-only proxy (19 MB stripped) |
| **GUI** | `tailscale-proxy-app` | Yes | Full GUI app with Fyne window (38 MB stripped) |

### Installation

- **Homebrew (CLI):** `brew install e-kotov/tap/tailscale-proxy`
- **macOS GUI:** Download `tailscale-proxy-app_*_macOS_*.tar.gz` from Releases
- **Linux/Windows:** Download from Releases or use package manager

### State Directories

Each binary now uses its own isolated state directory:

- CLI: `~/.config/tailscale-proxy-cli/<id>/`
- GUI: `~/.config/tailscale-proxy-app/<id>/`

This means both can run simultaneously without conflicts.

## 🚀 What's New

- CLI builds **without CGO** — smaller binary, simpler cross-compilation
- GUI binary is always in GUI mode — no `TS_GUI_MODE` env var needed
- Shared core logic in `internal/proxy/` package
- Updated GoReleaser for dual builds
- Separate Homebrew formula for CLI

---

# Release v0.0.2 - Advanced GUI Controls & Stability

This release introduces significant improvements to the Tailscale Proxy GUI, focusing on stateful controls, persistence, and better log management.

## 🚀 New Features & Improvements

### 1. Stateful GUI Controls
- **Toggle Debug Logs**: A new stateful button to switch between clean and detailed debug logs on the fly.
- **Auto-scroll Toggle**: Added a dedicated button to enable/disable auto-scrolling in the log window, allowing for easier reading of historical logs.
- **Log Management**: Introduced a "Copy Logs" button to instantly copy the entire text buffer to the clipboard, complementing the "Clear Logs" functionality.

### 2. Persistence & Feedback
- **Default Exit Node Marker**: The exit node dropdown now explicitly marks your saved default choice with a `(default)` suffix.
- **Improved Status Logic**: Corrected "Connecting..." state handling during startup and auto-connection phases.

### 3. Stability & Optimization
- **Memory Fixes**: Resolved memory leaks related to the rich text logging buffer and improved the log flusher efficiency.
- **Auto-scroll Accuracy**: Fixed timing issues where the scroll window wouldn't always snap to the absolute bottom of new entries.

### 3. Dedicated CLI Experience
- **Daemon Mode**: Built-in process management with `--daemon`, `--stop`, and `--status` commands.
- **Port Selection**: New `--port` flag to specify a custom listening port (default: `57320`).
- **Improved Logging**: New `--log-file` and `--quiet` flags for better control over output.
- **Simplified Usage**: Running without arguments now defaults to proxy mode (removed redundant `--proxy` flag).

## 📦 What's Included
- MacOS App Bundle (`TailscaleProxy.app`)
- Standalone binaries for Windows and Linux.
