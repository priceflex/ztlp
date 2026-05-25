#!/usr/bin/env bash
# capture-env.sh — pre-stop env snapshot for ZTLP production containers.
#
# WHAT
# ----
# Captures everything you need to forensically reconstruct a running
# Docker container's environment BEFORE you stop / recreate it. Pairs
# the redacted `docker inspect` view with the authoritative source `.env`
# so you can spot variables Docker is masking as `***`.
#
# WHY
# ---
# The v0.30.4 ZTLP fleet deploy lost ~2 hours of NS auth enforcement
# because someone snapshotted env with `docker inspect`, restarted the
# container, and `ZTLP_NS_REQUIRE_REGISTRATION_AUTH` came back as the
# literal string `"***"` (Docker's redaction). Elixir parsed that as
# false. NS accepted unsigned registrations until the audit log review
# flagged it. See:
#   docs/skills/ztlp-prod-deployment/references/
#     env-redaction-and-mnesia-restart-pitfalls.md
#
# USAGE
# -----
#     scripts/deploy/capture-env.sh <container-name>
#
# Writes a timestamped bundle under ./env-captures/ (or
# $CAPTURE_ENV_OUT_DIR if set).
#
# ENVIRONMENT (overrides for testing / SSH)
# -----------------------------------------
#   CAPTURE_ENV_DOCKER       command to invoke instead of `docker` (e.g.
#                            `ssh ubuntu@host docker`). Default: `docker`.
#   CAPTURE_ENV_SOURCE_DIR   dir holding the authoritative `.env` and
#                            `docker-compose.yml`. Default: ~/ztlp.net
#                            (the SaaS host's compose dir). Tests inject
#                            a tmpdir here.
#   CAPTURE_ENV_OUT_DIR      where to write bundles. Default:
#                            ./env-captures
#
# BUNDLE CONTENTS
# ---------------
#   exec-env.txt        raw `docker exec <c> env` output (the redacted view)
#   inspect.json        full `docker inspect <c>` JSON
#   source.env          authoritative source `.env` (if available)
#   redactions.txt      names of vars whose value is literally `***`
#   trusted-values.env  resolved KEY=VALUE pairs from source.env for each
#                       redacted name (the values you SHOULD re-inject
#                       on recreate)
#   SUMMARY.md          human-readable forensic report
#
# SAFETY
# ------
# - stdout/stderr only ever mentions variable NAMES, never VALUES.
# - The on-disk bundle DOES contain values (it must — that's the whole
#   point). Treat the bundle dir as a secrets store. Don't commit it.
#
set -euo pipefail

# ── Argument parsing ──────────────────────────────────────────────────

usage() {
    cat >&2 <<'EOF'
Usage: capture-env.sh <container-name>

Captures the env of a running container before you stop / recreate it,
flagging any values Docker is redacting as `***` and resolving them
from the authoritative source `.env` file.

Output: a timestamped bundle under $CAPTURE_ENV_OUT_DIR (default
./env-captures/).

Environment overrides (mostly for tests):
  CAPTURE_ENV_DOCKER      Command in place of `docker` (e.g. for SSH)
  CAPTURE_ENV_SOURCE_DIR  Where `.env` lives. Default: ~/ztlp.net
  CAPTURE_ENV_OUT_DIR     Where to write bundles. Default: ./env-captures

Background:
  docs/skills/ztlp-prod-deployment/references/
    env-redaction-and-mnesia-restart-pitfalls.md
EOF
}

if [[ $# -lt 1 ]] || [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    usage
    # `--help` is a successful query, missing-arg is an error
    if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
        exit 0
    fi
    exit 2
fi

container="$1"
# CAPTURE_ENV_DOCKER may be either a single binary (`docker`) or a
# multi-word command like `ssh ubuntu@host docker`. Use `read -ra` to
# split into an array so every site invokes it identically and tests
# can still pass a single path.
read -ra docker_cmd <<< "${CAPTURE_ENV_DOCKER:-docker}"
source_dir="${CAPTURE_ENV_SOURCE_DIR:-$HOME/ztlp.net}"
out_root="${CAPTURE_ENV_OUT_DIR:-./env-captures}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
bundle="$out_root/${container}-${timestamp}"
mkdir -p "$bundle"

# ── Step 1: confirm the container exists ──────────────────────────────
# `docker ps -q -f name=<c>` returns empty when not found, container ID
# when found. We use this rather than `docker exec` because exec's error
# message format is not stable across docker versions.

if ! ps_out="$("${docker_cmd[@]}" ps -q -f "name=^${container}$" 2>&1)"; then
    echo "ERROR: docker query failed for container '${container}':" >&2
    echo "$ps_out" >&2
    exit 1
fi

if [[ -z "$ps_out" ]]; then
    echo "ERROR: container '${container}' not found (docker ps returned empty)" >&2
    exit 1
fi

# ── Step 2: capture the container's reported env (Docker view) ────────
# This is the source of the `***` redactions. We capture it verbatim
# even though it's "lying" about secrets — the redacted view is itself
# diagnostic evidence.

if ! "${docker_cmd[@]}" exec "$container" env > "$bundle/exec-env.txt" 2>&1; then
    echo "ERROR: docker exec env failed for container '${container}':" >&2
    cat "$bundle/exec-env.txt" >&2
    exit 1
fi

# Sort for stable diffs across runs
sort -o "$bundle/exec-env.txt" "$bundle/exec-env.txt"

# ── Step 3: capture full inspect JSON ─────────────────────────────────
# `docker inspect` also redacts via *** but exposes labels, image refs,
# mounts, and the running command — all of which we want preserved for
# forensic recovery.

"${docker_cmd[@]}" inspect "$container" > "$bundle/inspect.json"

# ── Step 4: detect the `***` redactions ───────────────────────────────
# A redacted line looks like  KEY=***   (with nothing after).
# We extract just the KEY name — values, including the *** itself, never
# go to stdout (the test asserts this).

grep -E '^[A-Za-z_][A-Za-z0-9_]*=\*\*\*$' "$bundle/exec-env.txt" \
    | sed 's/=\*\*\*$//' \
    | sort -u > "$bundle/redactions.txt" || true
redaction_count="$(wc -l < "$bundle/redactions.txt" | tr -d ' ')"

# ── Step 5: copy authoritative source .env (if available) ─────────────
# This is the file the operator should always trust over the running
# container's env when reconstructing values.

source_env="$source_dir/.env"
source_compose="$source_dir/docker-compose.yml"
source_available=0
if [[ -f "$source_env" ]]; then
    cp "$source_env" "$bundle/source.env"
    source_available=1
else
    echo "# .env source not found at: $source_env" > "$bundle/source.env"
fi
if [[ -f "$source_compose" ]]; then
    cp "$source_compose" "$bundle/docker-compose.yml"
fi

# ── Step 6: resolve redactions against source.env ─────────────────────
# For each redacted KEY, look it up in source.env. If we find it, write
# KEY=value to trusted-values.env. If we don't, write KEY=UNAVAILABLE.

: > "$bundle/trusted-values.env"
if [[ "$redaction_count" -gt 0 ]]; then
    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        if [[ "$source_available" -eq 1 ]]; then
            # Match `KEY=...` at start of line in source .env, take the
            # first occurrence, strip the leading `KEY=`.
            # Using awk rather than grep|cut so we tolerate `=` in the value.
            value="$(awk -v k="$key" 'BEGIN{FS="="} $1==k {sub("^"k"=","",$0); print; exit}' "$bundle/source.env" || true)"
            if [[ -n "$value" ]]; then
                printf '%s=%s\n' "$key" "$value" >> "$bundle/trusted-values.env"
            else
                printf '%s=UNAVAILABLE_not_in_source_env\n' "$key" >> "$bundle/trusted-values.env"
            fi
        else
            printf '%s=UNAVAILABLE_source_env_missing\n' "$key" >> "$bundle/trusted-values.env"
        fi
    done < "$bundle/redactions.txt"
fi

# ── Step 7: emit SUMMARY.md (human-readable, safe to share) ───────────

# Build a list of redacted var names for the summary body without leaking
# any values.
if [[ "$redaction_count" -gt 0 ]]; then
    redacted_list="$(sed 's/^/- `/;s/$/`/' "$bundle/redactions.txt")"
else
    redacted_list="_(none)_"
fi

# Get source presence for the summary
if [[ "$source_available" -eq 1 ]]; then
    source_line="✅ \`$source_env\` (copied to source.env)"
else
    source_line="⚠️  NOT FOUND at \`$source_env\` — trusted-values.env will list UNAVAILABLE entries"
fi

cat > "$bundle/SUMMARY.md" <<EOF
# Env capture: \`$container\` @ $timestamp

**Captured by:** \`scripts/deploy/capture-env.sh\`
**Bundle:** \`$bundle\`
**Purpose:** pre-stop snapshot for safe container recreate. Pair with
the authoritative source \`.env\` to defeat the \`docker inspect\`
\`***\`-redaction pitfall (see env-redaction-and-mnesia-restart-pitfalls.md).

## Redactions detected: $redaction_count

The following env vars came back from \`docker exec env\` as the literal
string \`***\`. If you redeploy by replaying the running container's
env, these values will become the four-character string \`"***"\` and
break any code that compares them to real values.

$redacted_list

## Sources

- Running container env: ✅ \`exec-env.txt\` (sorted)
- Inspect JSON: ✅ \`inspect.json\`
- Source .env: $source_line
- Trusted-values bundle: ✅ \`trusted-values.env\` — re-inject from here on recreate

## Recovery procedure

1. Stop the container only AFTER reviewing \`SUMMARY.md\` + \`trusted-values.env\`.
2. On recreate, source values from \`trusted-values.env\`, NOT from a docker-inspect snapshot.
3. After recreate, verify with:

       ${docker_cmd[*]} exec $container env | grep -v '=\\*\\*\\*\$' | sort > /tmp/post-recreate.env
       diff <(sort $bundle/source.env) /tmp/post-recreate.env

   Any KEY missing or with a different value is a regression.

## Safety

This bundle CONTAINS SECRET VALUES (\`source.env\`, \`trusted-values.env\`).
Treat it as a credentials store. Do NOT commit, do NOT paste into chat.
The script's stdout/stderr deliberately omits all values; pasting THAT
is safe.
EOF

# ── Step 8: print a safe human summary to stdout ──────────────────────
# Only names, never values. This is the "safe to paste" line.

cat <<EOF
Captured env for container '$container' → $bundle
  - exec-env.txt:        $(wc -l < "$bundle/exec-env.txt" | tr -d ' ') vars
  - redactions detected: $redaction_count
  - source.env:          $([ "$source_available" -eq 1 ] && echo "✅ present" || echo "⚠️  missing")
  - trusted-values.env:  $(wc -l < "$bundle/trusted-values.env" | tr -d ' ') resolved entries

EOF

if [[ "$redaction_count" -gt 0 ]]; then
    echo "Redacted variable names (review SUMMARY.md before recreating):"
    sed 's/^/  - /' "$bundle/redactions.txt"
fi

if [[ "$source_available" -eq 0 ]]; then
    echo "" >&2
    echo "WARNING: source .env not found at $source_env — could not resolve redacted values." >&2
    echo "         The redacted snapshot is still captured for forensic use." >&2
fi

exit 0
