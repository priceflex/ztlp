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

# Create test user with password
if ! id testuser >/dev/null 2>&1; then
    useradd -m -s /bin/bash testuser
    echo "testuser:ztlptest" | chpasswd
    echo "  ✓ Created user 'testuser' (password: ztlptest)"
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
echo "  User: testuser / Password: ztlptest"
echo "═══════════════════════════════════════════════════════"

# Start sshd in foreground
exec /usr/sbin/sshd -D -e
