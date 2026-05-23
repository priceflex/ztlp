# EnrollmentToken Lifecycle (Bootstrap)

This document is the operator-facing reference for how ZTLP Bootstrap
issues, tracks, and retires enrollment tokens. Implementation is in
`app/models/enrollment_token.rb`; this doc describes the *contract*
the model exposes to operators, controllers, and rake tasks.

## What an enrollment token is

A short-lived, opaque credential that lets a single device (or, for
kiosk-style flows, a bounded number of devices) join a ZTLP network.
The credential is exchanged for a `ZtlpDevice` row via
`POST /api/enrollment/confirm`.

Each token row carries:

| Column          | Meaning                                                            |
|-----------------|--------------------------------------------------------------------|
| `network_id`    | The zone the enrolling device will join                            |
| `token_id`      | Opaque hex string embedded in the `ztlp://enroll/?token=...` URI   |
| `max_uses`      | How many devices may consume this token (default 1)                |
| `current_uses`  | How many have consumed it so far                                   |
| `expires_at`    | Wall-clock deadline (default **24h from creation**, see below)     |
| `status`        | One of `active`, `exhausted`, `expired`, `revoked`                 |
| `notes`         | Free-text annotation for ops / audit context                       |
| `ztlp_user_id`  | Optional binding — the user this device should attach to           |

## Status machine

```
            use! reaches max_uses                  revoke! (admin)
   ┌──────────────────────────────────────► exhausted   ─────────┐
   │                                                              │
active                                                            ├──► (terminal)
   │                                                              │
   │  expires_at < now  (caught by refresh_status!                │
   ├──────────────────  or by EnrollmentToken.sweep_expired!) ──► expired
   │                                                              │
   │                                          revoke!             │
   └─────────────────────────────────────────────────────────► revoked
```

Terminal states are **sticky**. `revoke!` on an already-exhausted
token returns `false` and does NOT overwrite the truthful
`exhausted` (a device DID successfully enroll — we don't want to
retroactively claim it was revoked).

## Default lifetime

Per Steve's 2026-05-23 brief — *"Enrollment tokens should last 24
hours by default."*

The default is enforced at the model layer via
`before_validation :set_default_expires_at, on: :create`. Any caller
that does NOT pass an explicit `expires_at:` gets `24.hours.from_now`.

The single source of truth is `EnrollmentToken::DEFAULT_LIFETIME`
(`24.hours`). The model spec
(`test/models/enrollment_token_test.rb#test_DEFAULT_LIFETIME_constant_is_24_hours`)
pins the constant — any future change must update the test
consciously.

## Single-use enforcement and atomicity

`use!` is the only path that transitions `current_uses` upward. It:

1. Acquires a `with_lock` (row-level `SELECT … FOR UPDATE` for
   ActiveRecord) on the token row.
2. Reloads inside the lock.
3. Re-checks `usable?` — refuses if another transaction transitioned
   the token between the controller's read and our lock acquisition.
4. Increments `current_uses`.
5. Transitions to `exhausted` if `current_uses >= max_uses`.
6. Releases the lock.

The atomicity test
(`test_use!_is_atomic_under_concurrent_callers`) spins up two
threads racing on the same single-use token and asserts exactly one
wins, exactly one loses, and `current_uses` never exceeds
`max_uses`.

## Auditing

Every successful transition writes an `AuditLog` row:

| Transition                                | `action`                                 |
|-------------------------------------------|------------------------------------------|
| `use!` succeeds                           | `enrollment_token.used`                  |
| `use!` exhausts the token                 | `enrollment_token.exhausted` (extra row) |
| `revoke!` succeeds                        | `enrollment_token.revoked`               |
| `refresh_status!` transitions to expired  | `enrollment_token.expired`               |
| `sweep_expired!` finishes (any rows changed) | `enrollment_token.sweep_expired` (single summary, not one per token) |

No audit row is written for no-op calls — e.g. `revoke!` on an
already-terminal token returns `false` without touching the log.

`AuditLog.record(...)` writes the JSON `details` payload; values
useful for forensics:

- `token_id` (always)
- `uses_before`, `uses_after`, `max_uses` (on `used`)
- `expired_at` (on `expired`)
- `count`, `token_ids` (first 100; on `sweep_expired`)

## Operator commands

### Daily sweep (cron)

Schedule from the host crontab, Solid Queue, or whatever scheduler
the bootstrap deployment runs:

```cron
17 4 * * * cd /rails && bundle exec rails ztlp:tokens:sweep_expired >> /var/log/ztlp/tokens.log 2>&1
```

The task:

- Transitions `status="active" AND expires_at <= now` rows to
  `expired`.
- Writes a single `enrollment_token.sweep_expired` audit log entry
  with the count + the first 100 affected token IDs.
- Prints a one-line summary to STDOUT:
  `[ztlp:tokens:sweep_expired] transitioned=N took=Xms at=ISO8601`

It's idempotent. Running it twice in a row will report `transitioned=0`
on the second run.

### Inspecting current state

```bash
bundle exec rails ztlp:tokens:stats
# [ztlp:tokens:stats] active=12 exhausted=87 expired=4 revoked=1
```

### Rails console patterns

```ruby
# Find a specific token by the URI fragment a user pasted
EnrollmentToken.find_by(token_id: "abc123def4567890")

# Tokens issued today
EnrollmentToken.where(created_at: Time.current.beginning_of_day..).count

# Tokens that should NOT exist (active but past deadline — sweep
# missed them somehow)
EnrollmentToken.past_expiry_but_active.count

# Manually revoke
t = EnrollmentToken.find_by(token_id: "...")
t.revoke!   # returns true on success, false if already terminal
```

## Known limitations

- **`sweep_expired!` is single-threaded** and uses `find_each` so it
  scales to millions of rows but is slow at that size. For
  multi-million-row deployments, replace the per-row
  `refresh_status!` loop with a bulk `UPDATE`. Audit log granularity
  drops (only the summary, no per-token transition events) — that's
  intentional, but if you need per-token audit events under bulk
  sweeps, do the bulk update inside an explicit DB transaction and
  emit a second bulk `AuditLog.insert_all`.

- **The model has no built-in rate limiting.** A misbehaving Z2LS
  instance can mint 1000 tokens/minute against `EnrollmentToken.create!`.
  Rate limiting belongs in the API controller layer (BS-PR-3
  `POST /api/v1/enrollment_tokens` will use Rack::Attack).

- **Audit log retention is not enforced by this model.** Audit rows
  are kept forever per the design doc. If retention becomes a
  concern, add a separate `ztlp:audit:prune_older_than` rake task —
  do NOT couple it to `sweep_expired!`.

## Troubleshooting

| Symptom                                              | Likely cause + fix                                                                                                 |
|------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| Token always returns `usable? == false` immediately | Check `status` first — most-common cause is fixture/seed code leaving it as `expired` or `revoked` accidentally.  |
| `use!` returns `false` but `current_uses` looks fine | Reload the row (`token.reload`) — another transaction probably transitioned status under you.                     |
| Two devices both succeeded on a `max_uses=1` token   | Concurrency bug — check the test `test_use!_is_atomic_under_concurrent_callers` still passes against your branch. |
| `sweep_expired!` count is 0 every night              | Either no tokens are expiring (look at TTL) or another process is already transitioning them — check `audit_logs`.|

## References

- Model: `app/models/enrollment_token.rb`
- Tests: `test/models/enrollment_token_test.rb`
- Controller: `app/controllers/api/enrollment_controller.rb`
- Rake tasks: `lib/tasks/ztlp_tokens.rake`
- API URI format spec: `~/.hermes/skills/devops/ztlp-bootstrap-enrollment/SKILL.md`
- Z2LS API endpoint (queued in BS-PR-3): see `~/hermes_session_handoff.md`
