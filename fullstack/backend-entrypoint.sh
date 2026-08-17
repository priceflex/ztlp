#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Backend SSH server
# Simple SSH server as the "protected service" behind the
# ZTLP gateway. Uses password auth for simplicity.
# ─────────────────────────────────────────────────────────────
set -e

echo "═══════════════════════════════════════════════════════"
echo "  Backend SSH Server"
echo "═══════════════════════════════════════════════════════"

# Create test user. Password is fixed (matches the client's SSHPASS=ztlptest)
# unless BACKEND_SSH_PASS overrides it, so the tunnel tests can authenticate.
TEST_PASS="${BACKEND_SSH_PASS:-ztlptest}"
if ! id testuser >/dev/null 2>&1; then
    useradd -m -s /bin/bash testuser
    echo "testuser:${TEST_PASS}" | chpasswd 2>/dev/null
    echo "  Created user 'testuser' (password set via BACKEND_SSH_PASS, default ztlptest)" >&2
fi

# Generate host keys if missing
ssh-keygen -A 2>/dev/null
echo "  ✓ SSH host keys ready"

# Configure sshd for testing
mkdir -p /run/sshd
cat > /etc/ssh/sshd_config.d/ztlp-test.conf << 'EOF'
PasswordAuthentication yes
PermitRootLogin no
UsePAM yes
# Allow SCP and large transfers
MaxSessions 10
MaxStartups 10:30:60
EOF

echo "  ✓ sshd configured"
echo ""
echo "  Listening on port 22"
echo "  User: testuser (password generated at container startup)"
echo "═══════════════════════════════════════════════════════"

# Start HTTP echo server in background
echo "  Starting HTTP echo server on port 8080..."
python3 /http-echo.py &
echo "  ✓ HTTP echo server started"

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
