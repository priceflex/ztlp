# ZTLP Desktop

Cross-platform desktop client for the **Zero Trust Layer Protocol** (ZTLP), built with [Tauri 2](https://v2.tauri.app).

Produces native Windows and Linux desktop apps with:
- System tray icon with quick-connect menu
- Full connection management UI
- Service discovery browser
- Identity & enrollment management
- Configuration panel

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.77+ | `rustup update stable` |
| Tauri CLI | 2.x | `cargo install tauri-cli --version "^2"` |
| Node.js | 18+ | Only for `package.json` scripts |
| GTK 3 | — | Linux only: `libgtk-3-dev` |
| WebKit2GTK | 4.1 | Linux only: `libwebkit2gtk-4.1-dev` |

## Quick Start

```bash
# Development (hot-reload)
cd desktop
cargo tauri dev

# Production build
cargo tauri build
```

Built artifacts land in `src-tauri/target/release/bundle/`.

## Project Structure

```
desktop/
├── src-tauri/           # Rust backend
│   ├── src/
│   │   ├── main.rs      # App entry point
│   │   ├── commands.rs   # Tauri IPC command handlers
│   │   ├── tray.rs       # System tray setup & events
│   │   ├── tunnel.rs     # VPN tunnel management (mock → FFI)
│   │   └── state.rs      # Shared app state
│   ├── icons/            # App icons
│   └── capabilities/     # Tauri v2 permission capabilities
├── src/                  # Frontend (vanilla HTML/CSS/JS)
│   ├── index.html
│   ├── styles.css
│   ├── app.js
│   └── components/       # Page modules (home, services, etc.)
└── package.json
```

## Architecture

```
┌──────────────────────────────────┐
│         Frontend (WebView)       │
│  HTML/CSS/JS  ←→  Tauri IPC     │
├──────────────────────────────────┤
│         Rust Backend             │
│  commands.rs → tunnel.rs → FFI  │
│  state.rs (Mutex<AppState>)     │
│  tray.rs (system tray)          │
├──────────────────────────────────┤
│     libztlp_proto (C FFI)       │
│  Identity · Noise_XX · Tunnel   │
└──────────────────────────────────┘
```

## FFI Integration

The Rust backend currently uses **mock implementations** for all tunnel operations. To integrate with the real `ztlp-proto` library:

1. Build `libztlp_proto.a` from `../proto/`
2. Link it via `build.rs` (`println!("cargo:rustc-link-lib=static=ztlp_proto")`)
3. Replace mock calls in `tunnel.rs` with real FFI calls matching `../proto/include/ztlp.h`

## System Tray

The app installs a system tray icon with:
- **Left-click:** Show/focus the main window
- **Right-click:** Context menu with status, connect/disconnect, open, quit

## CI/CD

GitHub Actions workflow at `.github/workflows/desktop-build.yml` builds for:
- **Windows** (windows-latest) → NSIS installer + MSI
- **Linux** (ubuntu-22.04) → AppImage + .deb

Artifacts are uploaded on every push to `main` and on tags matching `v*`.

## License

See the repository root [LICENSE](../LICENSE) file.
