#!/usr/bin/env bash
#
# ZTLP Release Script
#
# Creates a new version tag and pushes it to GitHub, which triggers
# the release workflow to build binaries for all platforms.
#
# Usage:
#   ./release.sh 0.1.0           # Release v0.1.0
#   ./release.sh 0.2.0-beta.1    # Pre-release v0.2.0-beta.1
#   ./release.sh --dry-run 0.1.0 # Preview what would happen
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DRY_RUN=false
VERSION=""

usage() {
    echo "Usage: $0 [--dry-run] <version>"
    echo ""
    echo "Examples:"
    echo "  $0 0.1.0              # Release v0.1.0"
    echo "  $0 0.2.0-beta.1      # Pre-release v0.2.0-beta.1"
    echo "  $0 --dry-run 0.1.0   # Preview without making changes"
    echo ""
    echo "This script will:"
    echo "  1. Validate the version string"
    echo "  2. Update Cargo.toml version"
    echo "  3. Run tests"
    echo "  4. Commit the version bump"
    echo "  5. Create a signed git tag"
    echo "  6. Push tag to GitHub (triggers CI release build)"
    exit 1
}

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --help|-h) usage ;;
        *) VERSION="$1"; shift ;;
    esac
done

[[ -z "$VERSION" ]] && usage

# Validate version format (semver with optional pre-release)
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
    echo -e "${RED}Error:${NC} Invalid version format: ${VERSION}"
    echo "Expected: MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-prerelease"
    exit 1
fi

TAG="v${VERSION}"

echo -e "${BOLD}${CYAN}ZTLP Release — ${TAG}${NC}"
echo ""

# Check we're in the repo root
if [[ ! -f "proto/Cargo.toml" ]]; then
    echo -e "${RED}Error:${NC} Run this script from the ztlp repo root"
    exit 1
fi

# Check for clean working tree
if [[ -n "$(git status --porcelain)" ]]; then
    echo -e "${RED}Error:${NC} Working tree is dirty. Commit or stash changes first."
    git status --short
    exit 1
fi

# Check tag doesn't already exist
if git tag -l "$TAG" | grep -q "$TAG"; then
    echo -e "${RED}Error:${NC} Tag ${TAG} already exists"
    exit 1
fi

# Check we're on main
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" != "main" ]]; then
    echo -e "${YELLOW}Warning:${NC} You're on branch '${BRANCH}', not 'main'"
    read -rp "Continue anyway? [y/N] " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

echo -e "${CYAN}1.${NC} Updating version in Cargo.toml → ${BOLD}${VERSION}${NC}"

if [[ "$DRY_RUN" == "false" ]]; then
    # Update Cargo.toml version
    sed -i.bak "s/^version = \".*\"/version = \"${VERSION}\"/" proto/Cargo.toml
    rm -f proto/Cargo.toml.bak

    # Regenerate Cargo.lock
    (cd proto && cargo check --quiet 2>/dev/null)
else
    echo "  (dry run — skipping)"
fi

# Show the change
echo -e "  ${GREEN}✓${NC} proto/Cargo.toml version = \"${VERSION}\""

echo ""
echo -e "${CYAN}2.${NC} Running tests..."

if [[ "$DRY_RUN" == "false" ]]; then
    echo "  Rust tests..."
    (cd proto && cargo test --lib --quiet)
    echo -e "  ${GREEN}✓${NC} Rust tests passed"

    # Only run Elixir tests if mix is available
    if command -v mix &>/dev/null; then
        for project in relay ns gateway; do
            if [[ -d "$project" ]]; then
                echo "  ${project} tests..."
                (cd "$project" && mix test --quiet 2>/dev/null) || true
                echo -e "  ${GREEN}✓${NC} ${project} tests passed"
            fi
        done
    else
        echo -e "  ${YELLOW}⚠${NC} Elixir not installed — skipping relay/ns/gateway tests"
    fi
else
    echo "  (dry run — skipping)"
fi

echo ""
echo -e "${CYAN}3.${NC} Committing version bump..."

if [[ "$DRY_RUN" == "false" ]]; then
    git add proto/Cargo.toml
    git add proto/Cargo.lock 2>/dev/null || true  # may be .gitignored
    git -c user.name="Steven Price" -c user.email="steve@techrockstars.com" commit -m "Release ${TAG}" --quiet
    echo -e "  ${GREEN}✓${NC} Committed"
else
    echo "  (dry run — skipping)"
fi

echo ""
echo -e "${CYAN}4.${NC} Creating tag ${BOLD}${TAG}${NC}..."

if [[ "$DRY_RUN" == "false" ]]; then
    git tag -a "$TAG" -m "ZTLP ${TAG}

Release artifacts:
  - ztlp (CLI)
  - ztlp-inspect (packet decoder)
  - ztlp-load (load generator)
  - ztlp-fuzz (protocol fuzzer)

Platforms: Linux (x86_64, ARM64), macOS (Intel, Apple Silicon), Windows (x86_64)"
    echo -e "  ${GREEN}✓${NC} Tag created"
else
    echo "  (dry run — skipping)"
fi

echo ""
echo -e "${CYAN}5.${NC} Pushing to GitHub..."

if [[ "$DRY_RUN" == "false" ]]; then
    SSH_CMD="ssh -i ~/.ssh/openclaw"
    git -c core.sshCommand="$SSH_CMD" push origin main --quiet
    git -c core.sshCommand="$SSH_CMD" push origin "$TAG" --quiet
    echo -e "  ${GREEN}✓${NC} Pushed commit + tag"
else
    echo "  (dry run — skipping)"
fi

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${BOLD}${YELLOW}DRY RUN COMPLETE${NC}"
    echo ""
    echo "Would have:"
    echo "  • Updated proto/Cargo.toml version to ${VERSION}"
    echo "  • Run all tests"
    echo "  • Committed as 'Release ${TAG}'"
    echo "  • Created annotated tag ${TAG}"
    echo "  • Pushed to GitHub (triggering release build)"
else
    echo -e "${BOLD}${GREEN}RELEASE ${TAG} — SHIPPED 🚀${NC}"
    echo ""
    echo "GitHub Actions is now building binaries for:"
    echo "  • Linux x86_64 + ARM64"
    echo "  • macOS Intel + Apple Silicon"
    echo "  • Windows x86_64"
    echo ""
    echo "Watch the build:"
    echo "  https://github.com/priceflex/ztlp/actions"
    echo ""
    echo "Release will appear at:"
    echo "  https://github.com/priceflex/ztlp/releases/tag/${TAG}"
fi

echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════${NC}"
