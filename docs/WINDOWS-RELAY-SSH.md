# Windows relay SSH via ZTLP

This document captures the relay-based SSH workflow for reaching a Windows machine through ZTLP when direct Internet SSH is not available.

## What this enables

- Hermes/Linux operator uses `ssh` with `ProxyCommand ztlp proxy %h %p`
- `ztlp proxy` can now resolve a host from either:
  - normal ZTLP name / `dns.domain_map` + NS lookup, or
  - a static `proxy_targets` entry in `~/.ztlp/agent.toml`
- Static targets are intended as an operational bridge for real-world relay testing before NS/SVC/KEY registration is fully in place

## Current Windows test host

- SSH host: `trs@10.170.3.111`
- Observed live state during this session:
  - OpenSSH service `sshd` is running
  - TCP port 22 is listening on `0.0.0.0` and `::`
  - firewall rules for OpenSSH are enabled
  - `ztlp` is not currently installed on the Windows host PATH

Because `ztlp` is not yet installed on the Windows machine, this session completed the client-side proxy/config work but did not complete a full end-to-end ZTLP SSH login.

## Operator configuration on the Hermes/Linux side

Example `~/.ztlp/agent.toml`:

```toml
[ns]
servers = ["<ns-host>:23096"]

[tunnel]
prefer_relay = true
relays = ["<relay-host>:23095"]

[proxy_targets."windows-relay.internal.techrockstars.com"]
ztlp_name = "windows.techrockstars.ztlp"
addr = "10.170.3.111:23095"
node_id = "b88397923c2518ca6aa400eb79a18c7b"
```

Notes:
- `addr` is the reachable ZTLP endpoint for the remote host/listener
- `node_id` is optional, but useful when known for validation/logging
- if NS registration is completed later, the static target can be removed and normal NS resolution can take over

Example `~/.ssh/config`:

```sshconfig
Host windows-relay.internal.techrockstars.com
    User trs
    ProxyCommand ztlp proxy %h %p
```

Connect with:

```bash
ssh windows-relay.internal.techrockstars.com
```

Or directly:

```bash
ssh -o ProxyCommand='ztlp proxy %h %p' trs@windows-relay.internal.techrockstars.com
```

## Windows-side target requirements

The Windows machine needs a ZTLP listener reachable through the relay path.

Minimum shape:

```powershell
ztlp listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 --forward ssh:127.0.0.1:22
```

If unnamed forwarding is preferred, this also works for raw port 22 forwarding:

```powershell
ztlp listen --key C:\ProgramData\ztlp\machine.json --bind 0.0.0.0:23095 --forward 127.0.0.1:22
```

For relay-first operation, the deployment should also include the correct relay/NS settings used by the environment.

## Validation checklist

1. Windows host has `ztlp` installed
2. Windows host has an identity file
3. Windows host runs `ztlp listen` forwarding to local SSH on 127.0.0.1:22
4. Hermes/Linux side has `~/.ztlp/agent.toml` with relay and `proxy_targets` configured
5. `ztlp proxy <host> 22` completes Noise handshake
6. `ssh <host>` succeeds through ProxyCommand

## Troubleshooting

- `hostname ... does not match dns.domain_map`
  - add a `proxy_targets` entry or fix `dns.domain_map`
- `SVC record missing address`
  - NS record is incomplete; use a static proxy target until NS is corrected
- handshake timeout
  - verify Windows `ztlp listen` is running and reachable on UDP 23095
  - verify relay address is correct and reachable
- SSH connects directly today but not through ZTLP
  - confirm Windows host actually has `ztlp` installed and listening; in this session it did not
