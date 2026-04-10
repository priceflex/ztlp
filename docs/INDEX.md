# ZTLP Documentation Index

Auto-generated documentation index. Last updated: 2026-04-10 07:55 UTC

## Project Documentation

Core documentation organized by topic.

### Architecture & Design
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture overview
- [THREAT-MODEL.md](THREAT-MODEL.md) — Security threat analysis
- [NEBULA-ANALYSIS.md](NEBULA-ANALYSIS.md) — Nebula comparison and analysis

### Protocol & Cryptography
- [CREDENTIAL-RENEWAL.md](CREDENTIAL-RENEWAL.md) — Credential lifecycle and rotation
- [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md) — Key management system
- [SIGNING-ORACLE.md](SIGNING-ORACLE.md) — Signing oracle implementation
- [PQ-MIGRATION.md](PQ-MIGRATION.md) — Post-quantum migration plan
- [IDENTITY-HEADERS.md](IDENTITY-HEADERS.md) — Identity header specification
- [MONOTONIC-DATA-SEQ.md](MONOTONIC-DATA-SEQ.md) — Monotonic data sequences
- [MTLS-SETUP.md](MTLS-SETUP.md) — Mutual TLS configuration

### Identity & Authentication
- [SPEC-USER-AUTH.md](SPEC-USER-AUTH.md) — User authentication specification
- [PASSWORDLESS.md](PASSWORDLESS.md) — Passwordless authentication flow
- [UNIFIED-AUDIT.md](UNIFIED-AUDIT.md) — Unified audit logging

### Security
- [FIREWALL.md](FIREWALL.md) — Firewall rules and configuration
- [TLS.md](TLS.md) — TLS implementation details
- [INTERNAL-CA.md](INTERNAL-CA.md) — Internal certificate authority
- [NS-SECURITY-HARDENING.md](NS-SECURITY-HARDENING.md) — Name service security

### Development
- [GOOD-FIRST-ISSUES.md](GOOD-FIRST-ISSUES.md) — Beginner-friendly issues
- [PERF-PLAN.md](PERF-PLAN.md) — Performance improvement plans
- [GAP-ANALYSIS.md](GAP-ANALYSIS.md) — Feature gap analysis

### iOS & Mobile
- [IOS-MEMORY-OPTIMIZATION.md](IOS-MEMORY-OPTIMIZATION.md) — iOS memory optimization
- [IOS-RELAY-ARCHITECTURE.md](IOS-RELAY-ARCHITECTURE.md) — iOS relay architecture
- [CLIENT-TYPE-DETECTION.md](CLIENT-TYPE-DETECTION.md) — Client type detection
- [CLIENT-TYPE-DETECTION-PLAN.md](CLIENT-TYPE-DETECTION-PLAN.md) — Client detection implementation plan

### Session Notes
- [IOS-SESSION3-STATUS.md](IOS-SESSION3-STATUS.md)
- [IOS-SESSION4-STATUS.md](IOS-SESSION4-STATUS.md)
- [IOS-SESSION5-STATUS.md](IOS-SESSION5-STATUS.md)
- [IOS-SESSION5B-STATUS.md](IOS-SESSION5B-STATUS.md)
- [IOS-SESSION5C-STATUS.md](IOS-SESSION5C-STATUS.md)
- [SESSION-6-SUMMARY.md](SESSION-6-SUMMARY.md)
- [SESSION-7-SUMMARY.md](SESSION-7-SUMMARY.md)
- [SESSION-8-DESKTOP-TESTING.md](SESSION-8-DESKTOP-TESTING.md)
- [SESSION-10-IOS-VAULTWARDEN-PLAN.md](SESSION-10-IOS-VAULTWARDEN-PLAN.md)
- [SESSION-11-IOS-NS-MEMORY-AUDIT.md](SESSION-11-IOS-NS-MEMORY-AUDIT.md)
- [SESSION-12-LINUX-NE-SIMULATION-HANDOFF.md](SESSION-12-LINUX-NE-SIMULATION-HANDOFF.md)

### Planning & Roadmap
- [ROADMAP.md](ROADMAP.md) — Project roadmap (root)
- [PRODUCTION-LAUNCH-PLAN.md](PRODUCTION-LAUNCH-PLAN.md) — Production launch checklist
- [RELAY-VIP-ARCHITECTURE.md](RELAY-VIP-ARCHITECTURE.md) — Relay-side VIP architecture
- [IOS-RELAY-VIP-IMPLEMENTATION-CHECKLIST.md](IOS-RELAY-VIP-IMPLEMENTATION-CHECKLIST.md)

### Operations & Deployment
- [OPS-RUNBOOK.md](OPS-RUNBOOK.md) — Operations runbook
- [LINUX-NE-SIMULATION-PLAN.md](LINUX-NE-SIMULATION-PLAN.md) — Linux NE simulation plan

### Feature Documentation
- [SPEED-FIX-PLAN.md](SPEED-FIX-PLAN.md) — iOS throughput fix plan
- [HANDSHAKE-RETRANSMIT-TASK.md](HANDSHAKE-RETRANSMIT-TASK.md) — Handshake retransmission
- [IDENTITY-AND-GROUPS-TASK.md](IDENTITY-AND-GROUPS-TASK.md) — Identity and groups
- [FEATURE-USER-IDENTITY.md](FEATURE-USER-IDENTITY.md) — User identity feature
- [SPEC-PEER-DISCOVERY.md](SPEC-PEER-DISCOVERY.md) — Peer discovery specification
- [TLS-TERMINATION.md](TLS-TERMINATION.md) — TLS termination details

### Agent & Automation
- [ADVANCED-CC-TASK.md](ADVANCED-CC-TASK.md) — Advanced agent tasks
- [AGENT-DESIGN.md](AGENT-DESIGN.md) — Agent design specification

### Reference
- [CLI.md](CLI.md) — CLI documentation
- [CLI-REF.md](CLI-REF.md) — CLI reference
- [IDENTITY.md](IDENTITY.md) — Identity documentation
- [GO-SDK.md](GO-SDK.md) — Go SDK documentation
- [NEBULA-ANALYSIS.md](NEBULA-ANALYSIS.md) — Nebula analysis
- [PROTOTYPE.md](PROTOTYPE.md) — Prototype notes
- [DEPLOYMENT.md](DEPLOYMENT.md) — Deployment guide
- [DOCKER.md](DOCKER.md) — Docker configuration
- [STRESS-TEST-REPORT.md](STRESS-TEST-REPORT.md) — Stress test results
- [TODO.md](TODO.md) — TODO list
- [TUNING-LOG.md](TUNING-LOG.md) — Tuning log
- [USE-CASES.md](USE-CASES.md) — Use cases

## Component Documentation

Component-specific READMEs for each subdirectory:

| Component | Description |
|-----------|-------------|
| [gateway/](../gateway/) | UDP gateway — session mux, congestion control, mobile tuning |
| [relay/](../relay/) | UDP relay — TCP/UDP bridge, VIP forwarding |
| [ns/](../ns/) | Name service — enrollment, routing, credential management |
| [proto/](../proto/) | Core protocol library — Noise XX, FFI, cross-platform types |
| [bootstrap/](../bootstrap/) | Enrollment bootstrap — Ruby web app, token management |
| [desktop/](../desktop/) | Cross-platform desktop client (Tauri) |
| [macos/](../macos/) | macOS native app — Xcode, system extension |
| [ios/](../ios/) | iOS app — Network Extension, SwiftUI |
| [sdk/](../sdk/) | Client SDKs (Go, etc.) |
| [bench/](../bench/) | Performance benchmarks |
| [stress/](../stress/) | Stress test framework and scenarios |
| [ops/](../ops/) | Production ops — Grafana, Prometheus, systemd, packaging |
| [tests/](../tests/) | Integration and network test infrastructure |
| [tools/netlab/](../tools/netlab/) | Network lab simulation tool |
