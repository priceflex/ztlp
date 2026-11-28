Type: grilling
Status: resolved
Blocked by:

## Question

What is the desktop client's destination + scope, and how does it relate to the existing
Tauri `ztlp-desktop` app?

## Answer

(Framing, resolved 2026-08-20.)

The focus Steven wants (2026-08-20): a **stable, production-usable ZTLP desktop app (Mac +
PC)** with (1) a **connection manager**, (2) a **session manager**, (3) **multi-threaded
handling so a single bad connection can't crash the app** ("very stable, so we can use it").
He has **existing use cases** and wants it usable **right away**, including on our own apps.

This is a **refocus of the existing `ztlp-desktop` Tauri 2 app** (not from-scratch). The app
already exists in `desktop/` (Rust backend `src-tauri/src/{main,commands,state,setup,ipc,
tunnel,tray}.rs` + web frontend), with a UI redesign in flight (spec in `desktop/GOALS.md`,
ledger in `desktop/PROGRESS.md`, headless DOM tests 35/35 passing). The new focus =
**stability + the connection/session managers + crash isolation**, tracked in this map as a
sibling to the production-readiness map.

**Platform priority:** macOS + Windows (the "Mac + PC" apps); Linux follows. (Tauri 2,
targets "all" per tauri.conf.json.)
