# D4 Windows Smoke Test — NRPT DNS Interception

**Goal:** Verify on a real Windows box (TRSDC or Charly) that
`ztlp agent dns-setup` installs an NRPT rule pointing `*.<zone>.ztlp`
at the agent's local DNS resolver, and that `ztlp agent dns-teardown`
removes ONLY the ZTLP-managed rule.

**Prerequisites:**

- D4 PR is merged AND a Windows build is available (CI uploads
  `ztlp.exe` artifacts on every push to `feat/d4-*`).
- The bench machine already has the ZTLP agent installed (D2's
  `ztlp-service.exe`) and is enrolled into a zone.
- You're on an Administrator PowerShell session (NRPT modification
  requires elevation).

---

## 0 — Pull the new ztlp.exe onto the bench

The simplest path is the CI release artifact:

```powershell
# From the bench, replace <BUILD-RUN-URL> with the CI run for D4
cd $env:TEMP
Invoke-WebRequest -Uri "https://github.com/priceflex/ztlp/actions/runs/<BUILD-RUN-URL>" `
  -OutFile ztlp-d4-zip
Expand-Archive ztlp-d4-zip -Force
Copy-Item .\ztlp.exe "C:\Program Files\ZTLP\ztlp.exe" -Force
```

Verify version:

```powershell
& "C:\Program Files\ZTLP\ztlp.exe" --version
# expect: ztlp 0.34.3 (or higher)
```

---

## 1 — Capture baseline state

Make sure there are no pre-existing ZTLP-managed NRPT rules. If there
are, this is a re-run; teardown them first.

```powershell
Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed"
# Expected: nothing returned

# If there are stale ones from a prior smoke:
& "C:\Program Files\ZTLP\ztlp.exe" agent dns-teardown
```

---

## 2 — Run dns-setup

```powershell
& "C:\Program Files\ZTLP\ztlp.exe" agent dns-setup
```

Expected output (rendered with green check):

```
✓ NRPT rules installed (1 namespace)
  .techrockstars.ztlp → 127.0.0.53:5353

Verify with: Get-DnsClientNrptRule | Where-Object Comment -Match 'ZTLP-managed'
```

If the device is enrolled into a sub-zone (`tech-rockstars.trs.ztlp`),
both that zone and the parent `trs.ztlp` are installed if both appear
in `agent.toml::dns.zones`.

---

## 3 — Verify the rule is registered

```powershell
Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed" |
  Format-List Namespace, NameServers, Comment
```

Expected (one entry per zone in agent.toml):

```
Namespace   : .techrockstars.ztlp
NameServers : {127.0.0.53:5353}
Comment     : ZTLP-managed
```

---

## 4 — Verify DNS resolution actually hits the agent

```powershell
nslookup vault.techrockstars.ztlp
```

Expected: the query lands at `127.0.0.53:5353` (the agent's DNS
listener) and returns a VIP from the agent's VIP pool, NOT a
`server can't find` from your upstream DNS.

If `nslookup` shows the upstream DNS instead, the NRPT rule didn't
take. Common causes:
- The agent isn't running on `127.0.0.53:5353`. Check with
  `Get-Service ztlp-service` and the agent's `agent.toml::dns.listen`.
- DNS Client service didn't reload. `Restart-Service Dnscache`.
- The rule was added in a non-admin context (NRPT requires elevation —
  this shouldn't happen via the service since LocalSystem is elevated,
  but it CAN happen if you ran `ztlp agent dns-setup` from a
  non-elevated user shell).

---

## 5 — Verify idempotency

```powershell
& "C:\Program Files\ZTLP\ztlp.exe" agent dns-setup
Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed" |
  Measure-Object | Select-Object -ExpandProperty Count
# Expected: still 1 (or however many zones — NOT 2)
```

The second call should report the same "1 namespace installed" line.
The total rule count must NOT grow — D4.T1's `setup_zones` dedups
within one call AND the production add path replaces an existing rule
with the same namespace.

---

## 6 — Verify an operator's pre-existing rule survives teardown

Critical safety property. The `ZTLP-managed` marker on the comment is
the ONLY thing that tells teardown which rules it owns.

```powershell
# Seed an operator-style rule by hand
Add-DnsClientNrptRule -Namespace ".corp.internal" `
  -NameServers @("10.0.0.53") `
  -Comment "IT-managed"

Get-DnsClientNrptRule | Where-Object Namespace -eq ".corp.internal"
# Confirm it exists
```

Now teardown:

```powershell
& "C:\Program Files\ZTLP\ztlp.exe" agent dns-teardown
```

Expected output:

```
✓ Removed 1 NRPT rule
  .techrockstars.ztlp
```

Re-check both rule sets:

```powershell
Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed"
# Expected: empty (ZTLP rule removed)

Get-DnsClientNrptRule | Where-Object Namespace -eq ".corp.internal"
# Expected: STILL THERE (operator rule untouched)
```

**If the IT-managed rule is gone, this is a bug — file as critical.**
The marker-based teardown is what protects operator rules from being
clobbered when ZTLP unenrolls.

Clean up the operator-style rule after the smoke:

```powershell
Get-DnsClientNrptRule | Where-Object Namespace -eq ".corp.internal" |
  Remove-DnsClientNrptRule -Force
```

---

## 7 — Verify teardown is idempotent

```powershell
& "C:\Program Files\ZTLP\ztlp.exe" agent dns-teardown
# Expected: "No ZTLP-managed NRPT rules found"
```

Running teardown twice in a row must not error.

---

## 8 — Capture evidence for the PR

After the smoke passes:

```powershell
# Take a final snapshot for the PR
Get-DnsClientNrptRule | Format-Table Namespace, NameServers, Comment -AutoSize |
  Out-String > "$env:USERPROFILE\Desktop\ztlp-d4-smoke-final.txt"
```

Paste the file contents into the PR description plus the timestamp of
each step. If any step failed, file as a blocker — D4 doesn't ship
without a clean run.

---

## Known good output format (for sanity comparison)

```
PS> & "C:\Program Files\ZTLP\ztlp.exe" agent dns-setup
✓ NRPT rules installed (2 namespaces)
  .techrockstars.ztlp → 127.0.0.53:5353
  .trs.ztlp → 127.0.0.53:5353

Verify with: Get-DnsClientNrptRule | Where-Object Comment -Match 'ZTLP-managed'

PS> Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed" |
       Format-List Namespace, NameServers, Comment

Namespace   : .techrockstars.ztlp
NameServers : {127.0.0.53:5353}
Comment     : ZTLP-managed

Namespace   : .trs.ztlp
NameServers : {127.0.0.53:5353}
Comment     : ZTLP-managed

PS> nslookup vault.techrockstars.ztlp
Server:   ztlp-agent (127.0.0.53)
Address:  127.0.0.53#5353

Name:     vault.techrockstars.ztlp
Address:  10.255.0.42  # agent-allocated VIP

PS> & "C:\Program Files\ZTLP\ztlp.exe" agent dns-teardown
✓ Removed 2 NRPT rules
  .techrockstars.ztlp
  .trs.ztlp
```

If your run matches this shape end-to-end, D4 is good to merge.

---

## What this smoke does NOT cover (deferred to D5)

- Browser TLS green-lock on `https://vault.techrockstars.ztlp` — that
  requires the ZTLP CA installed at machine scope + on-demand cert
  minting for arbitrary `*.<zone>.ztlp` SNI. Both are D5.T1 and D5.T2.

- WinTun / IFF_TUN packet-level interception — explicitly deferred per
  the parent plan's "out of scope" section. v0.32 RFC.

- macOS / Linux paths — `dns_setup_windows` is Windows-only by design.
  The existing `dns_setup.rs` handles those.
