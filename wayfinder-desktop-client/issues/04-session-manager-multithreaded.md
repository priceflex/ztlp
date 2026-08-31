Type: grilling
Status: resolved
Blocked by:
- 02-current-connection-model

## Question

What does the multi-threaded CONCURRENT CONNECTION model look like — can the app hold MULTIPLE
concurrent tunnels/connections, and how are they isolated (one tokio task/thread per
connection, independent state, independent crash domains)?

(Steven said "multi-threaded so it doesn't crash on a single connection" + "session manager."
Decide: is a "session" = one connection/tunnel? Can the app run N of them at once (one per
target/zone), each with its own state + crash isolation? What's the session manager's state
machine (pending → connecting → connected → degraded → disconnected → reconnecting), and how
does the UI surface N sessions?)

## Why this ticket

The "session manager" + "multi-threaded" requirement. Depends on #02 (current model: is it
single-connection today?).

## Answer

(Grilling, 2026-08-20. Steven away during Q&A — **PROVISIONAL design** (best judgment,
draft) for review. Incorporates the #02 findings (single-connection state today, 6 gaps) +
the #03 crash-isolation model. This is the "multi-threaded / session manager" half of the
stability ask.)

**Session model (draft default = ZONE-level):** a **session = one ZTLP zone connection**
(one enrolled device identity + one relay/NS). The daemon already supports N service
tunnels/forwards *within* a zone (per #02), so the app's session manager generalizes the
current single `ConnectionStatus` to **N zone sessions**, each with:
- its own **identity** (device id + zone name),
- its own **relay/NS** + zone,
- its own **lifecycle state** (Disconnected/Connecting/Connected/Reconnecting/Disconnecting),
- its own **health/crash boundary** (a bad session can't affect the others — see #03).

**[OPEN — needs Steven] session granularity:** the draft default is **zone-level**
(matches the current single-connection model generalized + simplest for "stay ready").
Alternatives noted: **per-forward** (each local port mapping = a session; finer "multi-
threaded per forward") and **per-profile** (a saved device+zone profile the user starts/
stops independently, with N forwards inside). For the pilot, zone-level is the simple
choice; the design is structured so forward-level is an incremental refinement.

**The session manager (closes #02 gaps #1, #4, #5, #6):**

1. **Per-session state (gap #4):** replace the single global `AppState.status:
   Mutex<ConnectionStatus>` with a `HashMap<SessionId, Session>` where each `Session` has
   its own status + health + backoff state. Per-session isolation = one bad session's
   state can't corrupt another's. Keep the shared `Mutex` **poison-tolerant** (per #03) so
   no session can panic the app.
2. **Daemon-backed authoritative status (gap #1):** `get_status` (and the session manager)
   must reflect the **daemon's real state**, not a cached value set once at connect. The
   app re-queries the daemon (or consumes events, #5) so a dead/dropped session shows
   disconnected/reconnecting, not stale "Connected."
3. **Daemon→app event stream (gap #5):** add a channel for the daemon to push per-session
   lifecycle + health events (connected / dropped / reconnecting / failed / forward-
   attached). Today IPC is request/response only (`PROGRESS.md:44-45`) so detection is
   ~2s poll-based; an event stream makes containment **reactive**, not poll-based. (If the
   daemon can't easily emit events, fall back to a faster app-side poll of the daemon's
   `tunnels` control command — the event stream is the target, the faster poll is the
   interim.)
4. **Per-session supervisor (gap #2, pairs with #03):** the #03 supervisor restarts a dead
   *elevated daemon*; the session manager tracks per-session lifecycle and, on a dropped
   session, drives the reconnect (re-invoke the daemon/zone connect with backoff) and
   surfaces the real state. A bad relay for session A doesn't wedge session B.
5. **Drive the real lifecycle states (gap #6):** the backend must actually set
   Connecting/Reconnecting/Disconnecting (from the daemon events) so the UI can show + bound
   a reconnect — today these are decorative (never set by Rust).

**Concurrency model:** no tokio needed for the app (per #02, it's blocking + the daemon is
the concurrent unit). The "multi-threaded" guarantee comes from: (a) the daemon handling
concurrent forwards out-of-process, (b) per-session state isolation in the app, (c) the
bounded non-UI-blocking spawn (#03) so one session's slow/hung operation can't wedge the
UI-thread command runner.

**CMMC / SOC 2 (per #01):** per-session lifecycle events (connect/drop/reconnect/fail) +
the supervisor's per-session backoff are auditable events. The event stream + session
state transitions should feed the audit trail (who/what re-established a session, when,
on what backoff).
