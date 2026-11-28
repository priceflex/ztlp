# ZTLP documentation

Everything here is about the code in this repository. For the project overview
start with the [README](../README.md); the rendered documentation site is at
[ztlp.org](https://ztlp.org).

## Getting started

| Document | What it covers |
|---|---|
| [Quick start](getting-started/quick-start.md) | What ZTLP is, the core concepts, and a first authenticated connection |
| [Use cases](getting-started/use-cases.md) | Real-world scenarios and what ZTLP changes in each |
| [Docker](getting-started/docker.md) | The compose files and images for running the stack |
| [Run your own zone](getting-started/run-your-own-zone.md) | Name server, relay and admin panel on one server, step by step |

## Architecture

| Document | What it covers |
|---|---|
| [Overview](architecture/overview.md) | Components, data path and design decisions |
| [Diagrams](architecture/diagrams/README.md) | System overview, admission pipeline, connection lifecycle, repository map |
| [Identity](architecture/identity.md) | Device, user and group records and how policy uses them |
| [Device and user binding](architecture/device-user-binding.md) | How a device identity is tied to a person |
| [Access control](architecture/access-control.md) | How gateways decide who may reach a service |
| [Agent](architecture/agent.md) | The device agent: local names, virtual addresses and tunnels |
| [QUIC and Noise handshake](architecture/quic-noise-handshake.md) | Transport and session establishment |
| [NAT traversal](architecture/nat-traversal.md) | Direct paths, hole punching and relay fallback |
| [Relay virtual addresses](architecture/relay-vip.md) | Relay selection driven by the name server |
| [Per-zone relay authentication](architecture/per-zone-hmac.md) | How relays authenticate gateways and clients per zone |
| [TLS termination](architecture/tls-termination.md) | TLS at the gateway |
| [Credential renewal](architecture/credential-renewal.md) | Lifecycle of keys and certificates across components |
| [Signing oracle](architecture/signing-oracle.md) | Hardware-bound certificate authority |
| [Client type detection](architecture/client-type-detection.md) | How gateways tell client kinds apart |
| [Threat model](architecture/threat-model.md) | What ZTLP defends against, and what it does not |

## Operations

| Document | What it covers |
|---|---|
| [Deployment](operations/deployment.md) | Production deployment for a service provider |
| [Runbook](operations/runbook.md) | Day-to-day operation, monitoring and troubleshooting |
| [Firewall](operations/firewall.md) | Locking a host down to ZTLP |
| [Key management](operations/key-management.md) | Generating, storing, rotating and revoking keys and secrets |
| [Internal CA](operations/internal-ca.md) | The built-in certificate authority |
| [TLS](operations/tls.md) and [mutual TLS](operations/mtls.md) | Certificates at the gateway and client certificate authentication |
| [Passwordless sign-in](operations/passwordless.md) | Signing users in to backends from their ZTLP identity |
| [Name server tenant isolation](operations/ns-admin-tenant-isolation.md) | Running the name server admin API on shared infrastructure |
| [SSH to Windows over a relay](operations/windows-ssh-over-relay.md) | Reaching a Windows machine that has no inbound access |

## Reference

| Document | What it covers |
|---|---|
| [Protocol specification](reference/specification.md) | The complete protocol: packet format, namespace, handshake, relays |
| [CLI guide](reference/cli.md) and [quick reference](reference/cli-quick-reference.md) | Every `ztlp` command |
| [Identity headers](reference/identity-headers.md) | The signed headers a gateway adds for backends |
| [Go SDK](reference/go-sdk.md) | Client library for Go |
| [Peer discovery](reference/peer-discovery.md) | Discovery and direct connectivity |
| [User authentication](reference/user-auth.md) | Application-aware user authentication |
| [Assurance levels](reference/assurance-levels.md) | How strongly a device identity is attested |
| [Post-quantum migration](reference/post-quantum-migration.md) | Plan for post-quantum key exchange and signatures |

## Admin panel

| Document | What it covers |
|---|---|
| [Specification](admin-panel/specification.md) | What the panel does and how it talks to the name server |
| [Walkthrough](admin-panel/UI-WALKTHROUGH-whoami.md) | Publishing a new service using only the panel |
| [Build record](admin-panel/BUILD_LOOP.md) | The slice-by-slice build log the code comments refer to |

## Security

| Document | What it covers |
|---|---|
| [Security policy](../SECURITY.md) | How to report a vulnerability |
| [Name server hardening](security/name-server-hardening.md) | Hardening work on ZTLP-NS |
| [v0.35.4 static analysis audit](security/v0.35.4-sast-audit.md) | Findings, triage and patches |

## Development

| Document | What it covers |
|---|---|
| [Contributing](../CONTRIBUTING.md) | Building and testing each component |
| [Reference implementation guide](development/reference-implementation.md) | How the implementation is put together |
| [Good first issues](development/good-first-issues.md) | Scoped tasks for new contributors |
| [Benchmarks](../bench/README.md) | How performance is measured, and the results |
| [Demo scripts](demo-scripts/README.md) | Scripts used in live demonstrations |

## Design records

[`plans/`](plans/) holds design proposals and implementation plans, named by
date. They record why something was built the way it was; where a plan and the
code disagree, the code is right. [`research/`](research/) holds background
studies used while designing features.

| Plan | Subject |
|---|---|
| [iOS native agent](plans/2026-11-27-ios-native-agent.md) | The iPhone app: design, what was built, and what was measured on a device |
| [Windows agent per user](plans/2026-10-29-windows-agent-per-user-unelevated.md) | Running the Windows agent without a system service |
| [Relay multi-client QUIC](plans/2026-10-20-relay-multi-client-quic.md) | Many concurrent flows per gateway through a relay |
| [Desktop parity](plans/2026-09-21-windows-linux-desktop-parity.md) | Bringing Windows and Linux to the macOS single-page experience |
| [Relay authorization v3](plans/2026-09-19-relay-auth-v3-identity-signed.md) | Identity-signed relay messages |
| [Relay-side VIP termination](plans/2026-09-13-relay-vip-design.md) | A parked design |
| [Zero-touch enrollment](plans/zero-touch-enrollment.md) | Enrollment without user interaction |
| [Unified audit logging](plans/unified-audit-logging.md) | Planned |
| [Monotonic data sequence numbers](plans/monotonic-data-sequence.md) | Deferred to 1.0 |
