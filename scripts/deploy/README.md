# `scripts/deploy/`

Operator scripts for ZTLP production deploys. These are designed to be
run from a developer workstation against the AWS production triplet
(`35.91.88.177` NS+Launch, `34.218.240.106` Relay, `54.218.127.30`
Gateway) or against any equivalent Docker host.

## `capture-env.sh`

Pre-stop env snapshot for a running container, hardened against the
`docker inspect` `***`-redaction pitfall that cost the v0.30.4 deploy
~2 hours of NS auth enforcement.

### Why this script exists

Docker redacts env vars whose names match secret patterns (`*_SECRET`,
`*_AUTH`, `*_TOKEN`, ...) as the literal string `"***"` in
`docker inspect` and `docker exec env` output. If a deploy script
snapshots that and replays it on container recreate, those values are
now literally `"***"` — and Elixir/Rust/Go all parse `"***"` as
boolean-false for security flags. The v0.30.4 NS recreate flipped
`ZTLP_NS_REQUIRE_REGISTRATION_AUTH` from `true` to `***` (false) and
the NS accepted unsigned registrations for ~2h before the audit log
caught it.

See `docs/skills/ztlp-prod-deployment/references/env-redaction-and-mnesia-restart-pitfalls.md`
for the full incident write-up.

### What it does

For a running container, captures:

| File | Contents |
|---|---|
| `exec-env.txt` | `docker exec <c> env`, sorted. The redacted view. |
| `inspect.json` | `docker inspect <c>` full JSON. |
| `source.env` | Copy of the authoritative `.env` on the host (if present). |
| `docker-compose.yml` | Copy of the source compose file (if present). |
| `redactions.txt` | Names of vars whose value is literally `***`. |
| `trusted-values.env` | Resolved `KEY=value` pairs from `source.env` for each redaction — these are what you re-inject on recreate. |
| `SUMMARY.md` | Human-readable forensic report. Safe to share. |

The script prints **only variable names** to stdout/stderr — it never
echoes a secret value. The bundle on disk DOES contain values
(deliberately — that's the whole point). Treat the bundle dir as a
credentials store.

### Usage

```bash
# Local container
./scripts/deploy/capture-env.sh ztlp-ns

# Remote container over SSH (uses CAPTURE_ENV_DOCKER override)
CAPTURE_ENV_DOCKER="ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@35.91.88.177 docker" \
  CAPTURE_ENV_SOURCE_DIR=/tmp/ns-source-from-rsync \
  ./scripts/deploy/capture-env.sh ztlp-ns

# Custom output location
CAPTURE_ENV_OUT_DIR=/secure/captures ./scripts/deploy/capture-env.sh ztlp-launch
```

### Recommended pre-stop workflow

```bash
# 1. Capture env BEFORE touching the container
./scripts/deploy/capture-env.sh ztlp-ns
# -> writes ./env-captures/ztlp-ns-20260525T024500Z/

# 2. Review the bundle's SUMMARY.md before proceeding
cat ./env-captures/ztlp-ns-*/SUMMARY.md

# 3. Stop / recreate the container using docker compose
ssh ubuntu@35.91.88.177 'cd ~/ztlp.net && docker compose up -d ztlp-ns'
#    ^^ this re-reads .env from disk; values DO get re-injected correctly.

# 4. Verify post-recreate env matches captured source
ssh ubuntu@35.91.88.177 'docker exec ztlp-ns env' \
  | grep -v '=\*\*\*$' | sort > /tmp/post.env
diff <(sort ./env-captures/ztlp-ns-*/source.env) /tmp/post.env
```

### Environment overrides (for tests / SSH)

| Variable | Purpose | Default |
|---|---|---|
| `CAPTURE_ENV_DOCKER` | Command in place of `docker`. Supports multi-word (e.g. `ssh host docker`). | `docker` |
| `CAPTURE_ENV_SOURCE_DIR` | Directory holding `.env` and `docker-compose.yml`. | `~/ztlp.net` |
| `CAPTURE_ENV_OUT_DIR` | Where to write bundles. | `./env-captures` |

### Tests

```bash
python3 -m pytest scripts/deploy/tests/test_capture_env.py -v
```

12 tests covering: bundle creation, redaction detection, trusted-value
resolution, stdout safety, idempotency (distinct bundle per run),
missing-container failure, missing-source-env graceful degradation,
no-redactions clean path, and SUMMARY.md well-formedness. Also
shellcheck-clean (`--severity=error`).
