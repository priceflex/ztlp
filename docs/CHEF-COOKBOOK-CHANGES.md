# Z2LS Chef Cookbook — Required Changes

**Status:** 2026-05-26 — what needs to change in the `ztlp` Chef cookbook on Z2LS Gitea.
**Why:** the cookbook on the Windows VM `desktop-lrc8dkh` is silently broken in several ways
that I caught during the e2e debug session tonight.

This doc enumerates what needs to change. **None of these are fixed yet — they're tasks for
the next Chef cookbook update.**

---

## 1. ADD: Windows Firewall inbound rule for UDP/23095 🔴 (highest priority)

**Symptom:** Without this rule, every Windows endpoint silently drops inbound UDP/23095
packets. Clients (Mac, iOS, other gateways) cannot reach the ZTLP listener even though
it's bound and "running."

**Reproduction:** Before adding the rule manually, every `ztlp connect` attempt to the
Windows VM hung in QUIC PTO retries with no response. Adding the rule unblocked it
immediately.

**Recipe change:**

```ruby
windows_firewall_rule 'ZTLP Gateway (UDP 23095)' do
  description 'Allow inbound UDP/23095 for ZTLP gateway listener'
  local_port  '23095'
  protocol    'UDP'
  firewall_action :allow
  profile     :any
  direction   :inbound
  action      :create
end
```

**Verification (after Chef converge):**

```powershell
Get-NetFirewallRule -DisplayName "ZTLP Gateway (UDP 23095)" | Format-List DisplayName, Enabled, Action, Direction, Profile
# Expected: Enabled=True, Action=Allow, Direction=Inbound, Profile=Any
```

---

## 2. ADD: NSSM `AppRestartDelay` to prevent bind-loop on restart 🟡

**Symptom:** When `ztlp_listener` restarts (Chef converge, manual restart, crash), NSSM
launches the new `ztlp.exe` before the old process has fully released UDP/23095. The new
process emits 10+ `error: failed to bind UDP socket: error 10048` lines before succeeding.
Self-corrects, but pollutes the error log and adds ~5-10s of downtime.

**Recipe change:**

```ruby
# In whatever resource sets up the NSSM service:
nssm 'ztlp_listener' do
  action :install
  # ... existing properties ...
  parameters(
    'AppRestartDelay' => '5000',          # 5s delay before restart
    'AppThrottle'     => '5000',          # treat sub-5s exits as "throttle"
    'AppExit'         => 'Default Restart',
    'AppStopMethodSkip' => '6',           # skip Ctrl-C, send WM_CLOSE then TerminateProcess
    'AppStopMethodConsole' => '1500',     # wait 1.5s after WM_CLOSE
    'AppStopMethodWindow'  => '1500',
  )
end
```

**Verification (after Chef converge):**

```powershell
& "C:\TRS_Tools\ztlp\nssm.exe" get ztlp_listener AppRestartDelay
# Expected: 5000
```

---

## 3. CHANGE: Service-name in config — currently confusing 🟡

**Symptom:** The gateway runs with `--service-name z2ls-desktop-lrc8dkh-dcc1e2` (from
some template variable in Chef) but the NS still has the SVC record under
`desktop-lrc8dkh-e2e`. Two different names for the same gateway, and the client has to
know both.

**Root cause:** The Chef recipe is computing the `--service-name` differently than the
NS bootstrap script did when it injected the original SVC record.

**Recipe change:** Pick **one** of these two:

### Option A: Make `--service-name` match the NS SVC record name

```ruby
# Have the recipe read the SVC name from node attributes set at enrollment time:
service_name = node['ztlp']['svc_name']  # e.g., 'desktop-lrc8dkh-e2e'
```

The enrollment script (or wherever the NS record gets created) should write this
attribute back so Chef knows what name to use.

### Option B: Have the gateway publish its SVC record on startup

This is a code change to ztlp itself (filed as a GitHub issue), but until that lands,
option A is the fix.

**Verification:**

```bash
# On the NS:
ssh ubuntu@16.147.41.195 'sudo docker exec ztlp-ns /app/bin/ztlp_ns rpc \
  "ZtlpNs.Store.list_by_zone(\"z2ls-final-e2e.techrockstars.ztlp\") |> IO.inspect()"'
# The SVC record name should match the --service-name on the gateway.
```

---

## 4. ADD: Health check for ztlp_listener 🟢

**Symptom:** No way to tell from Chef-side whether the listener is actually healthy
or just running-but-broken.

**Recipe change:**

```ruby
# After the service install:
ruby_block 'verify ztlp_listener health' do
  block do
    require 'net/http'
    require 'socket'

    # 1. Service running?
    state = `sc query ztlp_listener`
    raise "ztlp_listener not running" unless state.include?('RUNNING')

    # 2. UDP socket bound?
    sock = UDPSocket.new
    begin
      sock.bind('0.0.0.0', 23095)
      raise "UDP 23095 is free — ztlp_listener didn't bind"
    rescue Errno::EADDRINUSE
      # Good, something has the port
    ensure
      sock.close
    end

    # 3. Recent register success in log?
    log = File.read('C:\TRS_Tools\ztlp\logs\ztlp-listener.out.log') rescue ''
    raise "no gateway register in stdout log" unless log.include?('gateway registered with')
  end
  action :run
end
```

This catches "service running but failing to register" cases that Chef would otherwise
think are healthy.

---

## 5. CHANGE: config.toml comment is a lie 🟢 (cosmetic)

**Symptom:** `config.toml` starts with `# Managed by Chef cookbook ztlp.` but Chef
isn't installed on the bench (`C:\chef` doesn't exist). The file was placed by
something other than Chef.

**Action:** Either (a) actually deploy Chef to the bench so the comment is accurate, or
(b) remove the misleading comment. **Probably (a)** — the bench should be Chef-managed.

---

## 6. ADD: `nssm` log rotation 🟢

**Symptom:** `C:\TRS_Tools\ztlp\logs\ztlp-listener.{out,err}.log` grow unbounded. Over
weeks of operation these can fill the disk.

**Recipe change:**

```ruby
nssm 'ztlp_listener' do
  parameters(
    'AppRotateFiles'      => '1',
    'AppRotateOnline'     => '1',
    'AppRotateSeconds'    => '86400',     # rotate daily
    'AppRotateBytes'      => '10485760',  # or at 10MB, whichever first
    # ... existing parameters ...
  )
end
```

---

## 7. ADD: ZTLP-Listener scheduled task cleanup 🟢

**Symptom:** There's still a stale Scheduled Task on the Windows VM called
`\ZTLP-Listener` pointing at the old `10.42.42.115` z2ls relay. It hasn't run since
the cutover (because NSSM has the port) but it'll fire on next reboot and either fail
or compete with the NSSM service.

**Recipe change:**

```ruby
windows_task '\ZTLP-Listener' do
  action :delete
end
```

---

## 8. INVESTIGATE: ztlp_listener.err.log mojibake 🟢

**Symptom:** Some lines in the stderr log start with `�o` (replacement character +
'o') — Unicode encoding mismatch between what ztlp.exe writes and what NSSM captures.

```
�o" gateway registered with 34.218.240.106:23095 (service: z2ls-desktop-lrc8dkh-dcc1e2)
```

Probably a UTF-8 BOM or ANSI color escape that NSSM doesn't strip. Cosmetic, but worth
filing against `priceflex/ztlp` to emit colorless plain UTF-8 when stderr isn't a TTY.

---

## Priority order for the next Chef PR

1. **Item 1** (firewall rule) — blocks every customer install
2. **Item 7** (scheduled task cleanup) — ticking time bomb on reboot
3. **Item 2** (NSSM restart delay) — quality of life
4. **Item 6** (log rotation) — disk-fill prevention
5. **Item 3** (service-name alignment) — depends on enrollment workflow change
6. **Items 4, 5, 8** — nice-to-haves

---

## How to test the cookbook changes

The bench Windows VM at `10.170.3.111` is the perfect testbed. Before each cookbook
change, snapshot the current state:

```powershell
# State before
sc query ztlp_listener
Get-NetFirewallRule -DisplayName "ZTLP*" | Format-Table
Get-ScheduledTask -TaskName "ZTLP*" -ErrorAction SilentlyContinue
Get-Service ztlp* | Format-Table

# Run Chef converge
chef-client -z

# State after — diff
sc query ztlp_listener
Get-NetFirewallRule -DisplayName "ZTLP*" | Format-Table
# etc.
```

End-to-end smoke after Chef converge:

```bash
# From Steve's Mac
./ztlp connect 10.170.3.111:23095 --service ssh -L 2222:127.0.0.1:22 &
ssh -p 2222 trs@127.0.0.1 'hostname'
# Should print: DESKTOP-LRC8DKH
```

If that works, the cookbook is good.

---

## Related docs

- `Z2LS-E2E-RUNBOOK.md` — what the working setup looks like
- `NAT-TRAVERSAL.md` — why some customers will still need `--punch`
