# Run your own ZTLP name server and admin panel

This guide takes you from a fresh Linux server to signing in to your own ZTLP admin panel
(`http://admin.<your zone>`) from your Mac. One script does the server side; a few commands
do your Mac.

What you end up with:

- A **name server** (NS) that is the authority for your zone (for example `example.ztlp`).
- A **relay** that carries traffic for devices that cannot reach each other directly.
- The **admin panel**, reachable only through ZTLP at `http://admin.example.ztlp`.
- Your Mac enrolled in the zone, signed in to the panel as its first administrator.

Throughout, replace `example.ztlp` with your zone and `203.0.113.10` with your server's
public IP.

---

## Part 1: the server

### 1.1 What you need

- A Linux server with a public IP. Ubuntu 24.04 is tested. 2 vCPU and 4 GB of RAM are enough.
- SSH access with `sudo`.
- The two files from a release:
  - `ztlp-bootstrap` (this repo: `scripts/ztlp-bootstrap`)
  - `ztlp-server-images-<version>.tar` (the server images: name server, relay, admin panel,
    gateway, database)

### 1.2 Open the firewall

In your cloud provider's firewall (AWS security group, Lightsail networking tab, and so on),
allow these from anywhere:

| Port | Protocol | What uses it |
|---|---|---|
| 22 | TCP | SSH (you) |
| 23095 | UDP | relay |
| 23096 | UDP | name server |

Nothing else needs to be open. The admin panel is never exposed directly; it is reached
through the relay.

### 1.3 Copy the files and run the installer

From your computer:

```bash
scp ztlp-bootstrap ztlp-server-images-<version>.tar ubuntu@203.0.113.10:~
ssh ubuntu@203.0.113.10
```

On the server:

```bash
chmod +x ztlp-bootstrap
./ztlp-bootstrap --load-from ztlp-server-images-<version>.tar
```

It asks a few questions. Press Enter to accept the value in brackets:

| Question | What to answer |
|---|---|
| Zone name this server is the authority for | your zone, for example `example.ztlp` |
| Public IP or DNS name devices use to reach this box | detected for you; check it is the public IP |
| Also install the admin panel? | `Y` |
| Docker is not installed. Install it now? | `Y` (only asked on a fresh server) |
| Panel username you will claim | the username you want, for example `alice` |
| Name of the computer you will manage it from | a name for your Mac, for example `alice-mac` |

It then runs seven steps and prints `[ ok ]` for each:

1. **Docker**: installs Docker and compose if missing.
2. **Images**: loads the server images.
3. **Name server + relay**: generates all secrets and starts both.
4. **Zone authority**: creates the key that signs your zone's users, devices and groups, and
   anchors your zone to it on the name server.
5. **Admin panel**: starts the panel and connects it to the name server and relay.
6. **Admin gateway**: publishes `admin.example.ztlp` so enrolled devices can reach the panel.
7. **Backup + your first device**: writes a backup, then prints two things you need next.

### 1.4 Save these from the output

At the end the installer prints:

- **An enrollment token** (`ztlp://enroll/...`). It works once, for 24 hours. It is how your
  Mac joins the zone. Treat it like a password.
- **A panel claim code** (`XXXX-XXXX-...`). It is valid for 24 hours, and whoever uses it
  first becomes the panel's administrator.
- **The backup file** (`~/ztlp-backup-<time>.tar.gz`). Copy it off the server now:

  ```bash
  scp ubuntu@203.0.113.10:~/ztlp-backup-*.tar.gz .
  ```

  It holds the zone authority key and every secret. Without it, a lost server means
  re-enrolling every device. Keep it somewhere safe, such as a password manager or an
  encrypted drive.

---

## Part 2: your Mac

### 2.1 Install the ztlp command

In Terminal:

```bash
ARCH=$(uname -m)                      # arm64 = Apple Silicon, x86_64 = Intel
[ "$ARCH" = arm64 ] && T=aarch64-apple-darwin || T=x86_64-apple-darwin
cd ~/Downloads
curl -LO "https://github.com/priceflex/ztlp/releases/download/v0.37.2/ztlp-v0.37.2-$T.tar.gz"
tar xzf "ztlp-v0.37.2-$T.tar.gz"
sudo mkdir -p /usr/local/bin
sudo install -m 755 "ztlp-v0.37.2-$T/ztlp" /usr/local/bin/ztlp
ztlp --version                        # should print: ztlp 0.37.2
```

### 2.2 Check for an existing ZTLP setup

The ZTLP agent on a Mac keeps its identity in `/Library/Application Support/ZTLP/.ztlp/`.
Check whether this Mac already has one:

```bash
sudo ls "/Library/Application Support/ZTLP/.ztlp/" 2>/dev/null
sudo launchctl print system/org.ztlp.agent 2>/dev/null | head -3
```

- **Nothing printed:** this Mac is new to ZTLP. Continue with 2.3.
- **Files or a running agent:** this Mac is already enrolled in some zone. Enrolling it in
  your new zone **replaces** that identity, and the old zone stops working on this Mac.
  If you still need the old zone, stop here and use another Mac or user account.
  Otherwise add `--force` to the `ztlp setup` command in 2.3; it moves the old files to
  `*.bak`.

### 2.3 Join your zone

Use the enrollment token from step 1.4. Run `setup` with the agent's home folder, so the
background agent finds the identity:

```bash
sudo mkdir -p "/Library/Application Support/ZTLP"
sudo HOME="/Library/Application Support/ZTLP" ztlp setup \
  --token 'ztlp://enroll/PASTE-THE-TOKEN-HERE' --name alice-mac --yes
```

Look for these lines:

```
✓ Enrolled as alice-mac.example.ztlp
✓ name server verified against the token's key
✓ relay secret taken from the enrollment token
```

`setup` ends with a "Paste this public key on your zone's claim page" message. **Ignore it.**
The claim helper in step 2.5 handles keys for you.

### 2.4 Start the agent

```bash
sudo ztlp agent install
sudo launchctl bootstrap system /Library/LaunchDaemons/org.ztlp.agent.plist
sudo HOME="/Library/Application Support/ZTLP" ztlp agent dns-setup
```

Check that the panel answers through ZTLP:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://admin.example.ztlp/up     # expect 200
```

### 2.5 Claim the panel

Download the claim helper from your own panel, then claim with the code from step 1.4:

```bash
curl -sO http://admin.example.ztlp/ztlp-admin-sign.py
sudo python3 ztlp-admin-sign.py \
  --identity "/Library/Application Support/ZTLP/.ztlp/identity.json" \
  claim-submit --url http://admin.example.ztlp \
  --code 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX' \
  --username alice --display-name "Alice Example" --email alice@example.com
```

It prints: `Claimed: alice is now the first administrator.`

If macOS asks to install the command line developer tools when you run `python3`, click
Install and run the command again.

### 2.6 Sign in without prompts (recommended)

Make the panel recognise this Mac as you, so opening `http://admin.example.ztlp` signs you
in automatically. Print this Mac's device key:

```bash
sudo python3 ztlp-admin-sign.py \
  --identity "/Library/Application Support/ZTLP/.ztlp/identity.json" device-key
```

On the server, with that key and your panel username:

```bash
sudo ./ztlp-bootstrap --admin-device <the 64-character key>=alice
```

Back on the Mac, restart the agent so it reconnects:

```bash
sudo launchctl kickstart -k system/org.ztlp.agent
```

Open **http://admin.example.ztlp** in your browser. The top of the page shows
`alice · Super admin · via ZTLP alice-mac.example.ztlp`.

---

## Part 3: after setup

| Task | Command (on the server) |
|---|---|
| Token for another device | `sudo ./ztlp-bootstrap --mint-token --device-name bob-laptop` |
| Another device signs in to the panel as you | `sudo ./ztlp-bootstrap --admin-device <key>=alice` |
| Fresh backup | `sudo ./ztlp-bootstrap --backup` |
| Re-run the installer (keeps everything) | `sudo ./ztlp-bootstrap` |

Where things live on the server:

| Path | What |
|---|---|
| `/opt/ztlp/` | name server + relay (`docker-compose.yml`, `.env` secrets, `ns-data/`) |
| `/opt/ztlp/admin/` | admin panel, database, zone authority key (`authority/`) |
| `/opt/ztlp/admin-gateway/` | the gateway that publishes `admin.<zone>` |
| `/opt/ztlp-backups/` | backups (also copied to your home folder) |

---

## Troubleshooting

**`curl http://admin.example.ztlp/up` hangs or fails on the Mac.**
Check the agent: `sudo HOME="/Library/Application Support/ZTLP" ztlp agent status`. Check
that the server's firewall allows UDP 23095 and 23096 (step 1.2). On the server,
`sudo docker logs ztlp-relay | grep CLIENT_ROUTE | tail` shows your Mac's connection
attempts and why any were refused.

**The panel says "Connect through ZTLP".**
The request reached the panel without going through the ZTLP gateway. Use
`http://admin.example.ztlp`, not the server's IP address.

**The claim code expired.**
On the server: `sudo docker exec ztlp-admin-web /rails/bin/docker-entrypoint ./bin/rails admin:reset_claim`,
then `sudo docker logs ztlp-admin-web | grep "Claim code"`.

**The enrollment token expired or was used.**
Mint a new one: `sudo ./ztlp-bootstrap --mint-token --device-name alice-mac`.

## How the pieces fit (for the curious)

- The name server signs every answer with its own key. The enrollment token carries that
  key, so your Mac trusts only answers from your name server.
- The **zone authority** is a separate key. The name server's anchor record for your zone
  says "this key speaks for `example.ztlp`", and the panel signs users, devices and groups
  with it. The installer creates it on the server; it leaves the server only inside your
  backup.
- The admin panel listens only on the server's loopback address. The admin gateway accepts
  ZTLP connections for `admin.example.ztlp` (through the relay), forwards them to the
  panel, and stamps each request with signed identity headers. The panel refuses any
  request without them.
- Devices send their relay traffic signed with the relay registration secret, which the
  enrollment token carries. Gateways register with the relay using the zone's own secret.
