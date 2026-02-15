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
