#!/usr/bin/env bash
# ============================================================================
# ZTLP DEF CON Demo — Mint a user identity, then show admin vs standard-user
# access control live
# ============================================================================
#
# This walks through the full user identity lifecycle in ZTLP:
#
#   1. Mint a new USER identity in the namespace ("crash" — the demo's own
#      badge name) with role=admin, generating a real Ed25519 keypair and
#      registering a signed USER record in NS.
#   2. Mint a second, standard-role user ("alice") for contrast.
#   3. Query both users back from NS to show the records are real and
#      independently resolvable — not just local files.
#   4. Show the gateway's live policy check: the SAME "admin-panel" service
#      is authorized for crash (role=admin) and denied for alice (role=user)
#      — same code path a browser hitting an admin-only URL would trigger.
#   5. Recap the actual gateway config driving this (ZTLP_GATEWAY_POLICIES)
#      so the audience can see the policy is data, not special-cased code.
#
# Run this ON the Kali box, with the defcon stack already running.
# ============================================================================

set -uo pipefail

ZONE="defcon.ztlp"
NS_SERVER="127.0.0.1:23096"
ZTLP="$HOME/ztlp/proto/target/release/ztlp"
ADMIN_NAME="crash@${ZONE}"
STD_NAME="alice@${ZONE}"

BOLD=$(tput bold 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
CYAN=$(tput setaf 6 2>/dev/null || echo "")

section() {
  echo
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
  echo "${BOLD}${CYAN} $1${RESET}"
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════${RESET}"
}

pause() {
  if [ -t 0 ]; then
    read -rp "$(echo -e "${YELLOW}  -> press Enter to continue...${RESET}")" _
  else
    sleep 2
  fi
}

section "STEP 1 — Mint a new admin user identity: ${ADMIN_NAME}"
echo "This generates a fresh Ed25519 keypair locally, then registers a"
echo "SIGNED USER record for it in ZTLP-NS. Nothing here is a static"
echo "config file entry — it's a real cryptographic identity."
echo
echo "${CYAN}\$ ztlp admin create-user ${ADMIN_NAME} --role admin --email ${ADMIN_NAME} --ns-server ${NS_SERVER} --json${RESET}"
ADMIN_RESULT=$("$ZTLP" admin create-user "$ADMIN_NAME" --role admin --email "$ADMIN_NAME" --ns-server "$NS_SERVER" --json 2>&1)
echo "$ADMIN_RESULT" | python3 -m json.tool 2>/dev/null || echo "$ADMIN_RESULT"
ADMIN_PUBKEY=$(echo "$ADMIN_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('pubkey','?'))" 2>/dev/null)
echo
echo "${GREEN}${BOLD}-> New admin identity minted. Public key: ${ADMIN_PUBKEY}${RESET}"
echo "   Private key saved locally at ~/.ztlp/users/$(echo "$ADMIN_NAME" | sed 's/@/_at_/').json"
echo "   (that private key is what \"crash\" would actually use to"
echo "   authenticate as this identity going forward — this mint step"
echo "   only needs to happen once)"
pause

section "STEP 2 — Mint a standard (non-admin) user for contrast: ${STD_NAME}"
echo "${CYAN}\$ ztlp admin create-user ${STD_NAME} --role user --email ${STD_NAME} --ns-server ${NS_SERVER} --json${RESET}"
STD_RESULT=$("$ZTLP" admin create-user "$STD_NAME" --role user --email "$STD_NAME" --ns-server "$NS_SERVER" --json 2>&1)
echo "$STD_RESULT" | python3 -m json.tool 2>/dev/null || echo "$STD_RESULT"
pause

section "STEP 3 — Prove both records are real: query them back from NS"
echo "USER records are type 0x11 (17) in the ZTLP namespace. Querying"
echo "each name back independently, live, from the namespace service:"
echo
echo "${CYAN}\$ ztlp ns lookup ${ADMIN_NAME} --ns-server ${NS_SERVER} --record-type 17${RESET}"
"$ZTLP" ns lookup "$ADMIN_NAME" --ns-server "$NS_SERVER" --record-type 17 2>&1
echo
echo "${CYAN}\$ ztlp ns lookup ${STD_NAME} --ns-server ${NS_SERVER} --record-type 17${RESET}"
"$ZTLP" ns lookup "$STD_NAME" --ns-server "$NS_SERVER" --record-type 17 2>&1
pause

section "STEP 4 — Live gateway policy check: admin-panel access"
echo "The gateway is configured with:"
echo "${CYAN}  ZTLP_GATEWAY_POLICIES=\"role:admin:admin-panel,*:tcp:443\"${RESET}"
echo
echo "That means: the 'admin-panel' service requires role=admin. Every"
echo "other authenticated identity gets the standard dashboard (tcp:443)"
echo "but NOT admin-panel. This isn't hardcoded per-user — it's a role"
echo "check evaluated fresh on every request against each user's live"
echo "USER record in NS."
echo
echo "${CYAN}\$ ztlp_gateway rpc PolicyEngine.authorize?(\"${ADMIN_NAME}\", \"admin-panel\")${RESET}"
CRASH_ADMIN=$(sudo -n docker exec ztlp-gateway-defcon /app/bin/ztlp_gateway rpc "IO.puts(ZtlpGateway.PolicyEngine.authorize?(\"${ADMIN_NAME}\", \"admin-panel\"))" 2>/dev/null)
if [ "$CRASH_ADMIN" = "true" ]; then
  echo "  ${GREEN}${BOLD}✓ ALLOWED${RESET} — crash (role=admin) can reach admin-panel"
else
  echo "  ${RED}${BOLD}✗ DENIED${RESET} — unexpected, check the policy config"
fi

echo
echo "${CYAN}\$ ztlp_gateway rpc PolicyEngine.authorize?(\"${STD_NAME}\", \"admin-panel\")${RESET}"
ALICE_ADMIN=$(sudo -n docker exec ztlp-gateway-defcon /app/bin/ztlp_gateway rpc "IO.puts(ZtlpGateway.PolicyEngine.authorize?(\"${STD_NAME}\", \"admin-panel\"))" 2>/dev/null)
if [ "$ALICE_ADMIN" = "false" ]; then
  echo "  ${RED}${BOLD}✗ DENIED${RESET} — alice (role=user) correctly blocked from admin-panel"
else
  echo "  ${YELLOW}${BOLD}⚠ ALLOWED${RESET} — unexpected, this should be denied"
fi

echo
echo "${CYAN}\$ ztlp_gateway rpc PolicyEngine.authorize?(\"${ADMIN_NAME}\", \"tcp:443\")${RESET}"
CRASH_DASH=$(sudo -n docker exec ztlp-gateway-defcon /app/bin/ztlp_gateway rpc "IO.puts(ZtlpGateway.PolicyEngine.authorize?(\"${ADMIN_NAME}\", \"tcp:443\"))" 2>/dev/null)
echo "  crash -> standard dashboard: ${CRASH_DASH}"

echo "${CYAN}\$ ztlp_gateway rpc PolicyEngine.authorize?(\"${STD_NAME}\", \"tcp:443\")${RESET}"
ALICE_DASH=$(sudo -n docker exec ztlp-gateway-defcon /app/bin/ztlp_gateway rpc "IO.puts(ZtlpGateway.PolicyEngine.authorize?(\"${STD_NAME}\", \"tcp:443\"))" 2>/dev/null)
echo "  alice -> standard dashboard: ${ALICE_DASH}"
pause

section "SUMMARY"
cat <<EOF
${GREEN}${BOLD}What just happened, end to end:${RESET}

  1. Minted a real signed USER identity for "crash" with role=admin —
     a fresh Ed25519 keypair + a signed record in ZTLP-NS, not a config
     file edit.
  2. Minted a second standard-role user ("alice") for contrast.
  3. Independently queried both records back from NS, live, proving
     they're real namespace entries.
  4. Showed the SAME policy engine evaluate access to an admin-only
     service differently for the two identities based purely on their
     role attribute stored in NS:
       - crash (role=admin) -> admin-panel: ${CRASH_ADMIN}
       - alice (role=user)  -> admin-panel: ${ALICE_ADMIN}
       - crash              -> dashboard:   ${CRASH_DASH}
       - alice              -> dashboard:   ${ALICE_DASH}

This is driven entirely by ZTLP_GATEWAY_POLICIES="role:admin:admin-panel,*:tcp:443"
on the gateway plus the role field in each user's signed NS record —
no per-user special-casing in the gateway code.
EOF
