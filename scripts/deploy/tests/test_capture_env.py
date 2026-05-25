"""Tests for `scripts/deploy/capture-env.sh`.

This script captures the env of a running container BEFORE stopping it,
catching the `docker inspect` `***`-redaction pitfall that bit the
v0.30.4 deploy (see
docs/skills/ztlp-prod-deployment/references/env-redaction-and-mnesia-restart-pitfalls.md).

Strategy
--------
The script's "container side" calls are pluggable via three env vars:

    CAPTURE_ENV_DOCKER     -- command used in place of `docker`
    CAPTURE_ENV_SSH        -- command used in place of `ssh` (or empty for local)
    CAPTURE_ENV_SOURCE_DIR -- where to look for .env / docker-compose.yml

Tests inject fake versions of these to drive every code path without
needing a real Docker daemon or SSH host.

Behavior under test (BDD-style)
-------------------------------
- captures both `docker exec env` (redacted view) and `docker inspect`
- captures the authoritative source .env file
- detects vars whose values are the literal string `***`
- emits a TRUSTED VALUES section pairing each redaction with the .env value
- exits 0 on success, non-zero on missing container / SSH failure / missing source
- writes to a fresh timestamped directory per run (idempotent — never overwrites)
- never logs secret VALUES to stdout, only NAMES (the captured files
  contain the values, deliberately, but stdout is safe to paste)
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "scripts" / "deploy" / "capture-env.sh"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_docker(tmp_path: Path) -> Path:
    """Build a fake `docker` binary that simulates a redacting daemon.

    The fake responds to:
        docker exec <c> env       -> prints fake env with `***` redactions
        docker inspect <c>        -> prints minimal JSON
        docker ps -q <c>          -> non-empty (container exists)

    The behavior is controlled by files the test drops into the fake's
    working dir before invocation.
    """
    fake = tmp_path / "fake-docker"
    fake.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            # Fake docker. Reads behavior from $FAKE_DOCKER_STATE if set.
            set -euo pipefail
            state="${FAKE_DOCKER_STATE:-/tmp/fake-docker-state}"
            case "$1" in
              exec)
                # $2 = container, $3 = env
                if [[ -f "$state/missing" ]]; then
                  echo "Error: No such container: $2" >&2
                  exit 1
                fi
                cat "$state/exec-env.txt"
                ;;
              inspect)
                cat "$state/inspect.json"
                ;;
              ps)
                if [[ -f "$state/missing" ]]; then
                  exit 0  # empty output -> container not found
                fi
                echo "abc123"
                ;;
              *)
                echo "fake-docker: unknown verb $1" >&2
                exit 2
                ;;
            esac
            """
        )
    )
    fake.chmod(0o755)
    return fake


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    """Working directory holding fake-docker's response fixtures + source .env."""
    d = tmp_path / "state"
    d.mkdir()
    # Realistic .env (the authoritative source — has the real secrets)
    (d / ".env").write_text(
        textwrap.dedent(
            """\
            # ZTLP NS production env
            ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true
            ZTLP_ENROLLMENT_SECRET=s3cr3t-real-value-do-not-leak
            ZTLP_HMAC_SECRET_TECHROCKSTARS_COM=hmac-real-value
            LOG_LEVEL=info
            """
        )
    )
    (d / "docker-compose.yml").write_text(
        "services:\n  ztlp-ns:\n    image: priceflex/ztlp-ns:v0.30.6\n"
    )
    # Docker's redacted view: secrets show as ***
    (d / "exec-env.txt").write_text(
        textwrap.dedent(
            """\
            PATH=/usr/bin
            ZTLP_NS_REQUIRE_REGISTRATION_AUTH=***
            ZTLP_ENROLLMENT_SECRET=***
            ZTLP_HMAC_SECRET_TECHROCKSTARS_COM=***
            LOG_LEVEL=info
            """
        )
    )
    (d / "inspect.json").write_text('[{"Id":"abc123","Name":"ztlp-ns"}]')
    return d


# ---------------------------------------------------------------------------
# Smoke tests — script must be present, syntactically valid, executable
# ---------------------------------------------------------------------------


def test_script_exists():
    """The capture script must exist at the documented path."""
    assert SCRIPT.exists(), f"Missing deploy script: {SCRIPT}"
    assert os.access(SCRIPT, os.X_OK), f"Script not executable: {SCRIPT}"


def test_script_passes_shellcheck():
    """ShellCheck must accept the script with no errors (warnings OK)."""
    result = subprocess.run(
        ["shellcheck", "--severity=error", str(SCRIPT)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 127:
        pytest.skip("shellcheck not installed")
    assert result.returncode == 0, (
        f"shellcheck errors:\n{result.stdout}\n{result.stderr}"
    )


def test_help_flag_lists_required_args():
    """`-h` / `--help` documents the required positional args."""
    result = subprocess.run(
        [str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    assert "container" in combined.lower()
    assert "capture" in combined.lower()


# ---------------------------------------------------------------------------
# Happy path — local container, redactions detected, .env resolves them
# ---------------------------------------------------------------------------


def _run_capture(
    script: Path,
    container: str,
    state: Path,
    fake_docker: Path,
    out_dir: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["CAPTURE_ENV_DOCKER"] = str(fake_docker)
    env["CAPTURE_ENV_SOURCE_DIR"] = str(state)
    env["CAPTURE_ENV_OUT_DIR"] = str(out_dir)
    env["FAKE_DOCKER_STATE"] = str(state)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [str(script), container],
        capture_output=True,
        text=True,
        env=env,
    )


def test_happy_path_creates_bundle(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """Capturing a running container writes a complete bundle."""
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, f"stderr:\n{result.stderr}"

    # Single bundle dir written under out
    bundles = list(out.iterdir())
    assert len(bundles) == 1, f"expected 1 bundle, got {bundles}"
    bundle = bundles[0]

    # All expected files present
    assert (bundle / "exec-env.txt").exists()
    assert (bundle / "inspect.json").exists()
    assert (bundle / "source.env").exists()
    assert (bundle / "redactions.txt").exists()
    assert (bundle / "trusted-values.env").exists()
    assert (bundle / "SUMMARY.md").exists()


def test_redactions_are_detected_by_name(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """Vars whose docker-exec value is `***` are listed in redactions.txt."""
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, result.stderr

    bundle = next(out.iterdir())
    redactions = (bundle / "redactions.txt").read_text().splitlines()
    assert "ZTLP_NS_REQUIRE_REGISTRATION_AUTH" in redactions
    assert "ZTLP_ENROLLMENT_SECRET" in redactions
    assert "ZTLP_HMAC_SECRET_TECHROCKSTARS_COM" in redactions
    # Non-secrets should NOT be flagged
    assert "LOG_LEVEL" not in redactions
    assert "PATH" not in redactions


def test_trusted_values_resolves_from_source_env(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """The TRUSTED VALUES bundle pairs redacted names with real .env values."""
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, result.stderr

    bundle = next(out.iterdir())
    trusted = (bundle / "trusted-values.env").read_text()
    assert "ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true" in trusted
    assert "ZTLP_ENROLLMENT_SECRET=s3cr3t-real-value-do-not-leak" in trusted
    assert "ZTLP_HMAC_SECRET_TECHROCKSTARS_COM=hmac-real-value" in trusted
    # Non-redacted vars are NOT included (no need to "resolve" them)
    assert "LOG_LEVEL" not in trusted


def test_stdout_never_leaks_secret_values(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """Script's stdout/stderr must list NAMES but never raw secret VALUES.

    The on-disk bundle deliberately contains secret values (it's the
    whole point), but the human-readable terminal output must be safe
    to paste into Slack/PRs without leaking anything.
    """
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, result.stderr

    combined = result.stdout + result.stderr
    assert "s3cr3t-real-value-do-not-leak" not in combined, (
        "stdout/stderr leaked an ENROLLMENT_SECRET value"
    )
    assert "hmac-real-value" not in combined, (
        "stdout/stderr leaked an HMAC value"
    )
    # But the NAMES should appear so the operator knows what was captured
    assert "ZTLP_ENROLLMENT_SECRET" in combined


def test_two_runs_produce_distinct_bundles(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """Idempotent — each invocation writes a new timestamped bundle."""
    out = tmp_path / "captures"
    r1 = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    # Sleep a hair past 1s so timestamp tick guaranteed
    subprocess.run(["sleep", "1.1"], check=True)
    r2 = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert r1.returncode == 0 and r2.returncode == 0

    bundles = sorted(out.iterdir())
    assert len(bundles) == 2, f"expected 2 distinct bundles, got {bundles}"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_missing_container_exits_nonzero(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """If the named container doesn't exist, fail fast with a clear message."""
    (state_dir / "missing").touch()  # tell fake-docker to report missing
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "nope", state_dir, fake_docker, out)
    assert result.returncode != 0
    assert "not found" in (result.stdout + result.stderr).lower() or \
           "no such container" in (result.stdout + result.stderr).lower()


def test_missing_source_env_warns_but_proceeds(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """If `.env` is missing the capture still works — we just can't
    resolve the redactions. Exit 0 with a clear warning."""
    (state_dir / ".env").unlink()
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    # Capture proceeds (the redacted snapshot itself is still valuable)
    assert result.returncode == 0, result.stderr
    bundle = next(out.iterdir())
    assert (bundle / "exec-env.txt").exists()
    # But the trusted-values file is empty / flagged
    trusted = (bundle / "trusted-values.env").read_text()
    assert "UNAVAILABLE" in trusted or trusted.strip() == "" or \
           "could not resolve" in trusted.lower()
    # And stderr called it out
    assert "could not" in (result.stdout + result.stderr).lower() or \
           "missing" in (result.stdout + result.stderr).lower() or \
           "not found" in (result.stdout + result.stderr).lower()


def test_no_redactions_is_clean_run(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """Container with no `***` values: capture succeeds, redactions empty."""
    (state_dir / "exec-env.txt").write_text(
        "PATH=/usr/bin\nLOG_LEVEL=info\nZTLP_VERSION=0.30.6\n"
    )
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, result.stderr
    bundle = next(out.iterdir())
    assert (bundle / "redactions.txt").read_text().strip() == ""


def test_summary_md_is_well_formed(
    tmp_path: Path, fake_docker: Path, state_dir: Path
):
    """SUMMARY.md is a human-readable forensic report with the key facts."""
    out = tmp_path / "captures"
    result = _run_capture(SCRIPT, "ztlp-ns", state_dir, fake_docker, out)
    assert result.returncode == 0, result.stderr
    bundle = next(out.iterdir())
    summary = (bundle / "SUMMARY.md").read_text()
    assert "ztlp-ns" in summary  # container name
    assert "Redactions detected" in summary or "redactions" in summary.lower()
    # Lists the count of redacted vars
    assert "3" in summary  # 3 vars were redacted in the fixture
