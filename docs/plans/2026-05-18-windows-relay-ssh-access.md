# Windows relay SSH access implementation plan

> For Hermes: use subagent-driven-development and strict TDD for code changes.

Goal: enable Hermes to reach a Windows host over ZTLP using relay-based SSH ProxyCommand flow, without depending on ad-hoc source hacks.

Architecture:
- Replace the current hardcoded dev hack in proto/src/agent/proxy.rs with a documented, config-driven override path.
- Let ztlp proxy resolve a host either from NS/domain mapping or from an explicit static target entry in ~/.ztlp/agent.toml.
- Support relay-first operation by documenting/configuring tunnel.relays and prefer_relay for real-world Windows SSH access.

Tech stack: Rust, tokio, existing agent config loader, ztlp proxy CLI, cargo test.

Tasks:
1. Add failing unit tests for static target parsing and resolution behavior in proto/src/agent/config.rs and proto/src/agent/proxy.rs.
2. Implement config model for static proxy targets (hostname -> ztlp_name, endpoint, node_id optional) and update proxy resolution to use it before NS lookup.
3. Remove the hardcoded Windows-specific hack from proto/src/agent/proxy.rs and restore normal NS behavior with config-driven fallback.
4. Add documentation for Steve’s Windows relay-SSH workflow, including example ~/.ztlp/agent.toml and ~/.ssh/config.
5. Run targeted Rust tests, then broader proto test/lint commands as far as practical.
6. Update hermes_session_handoff.md with the new Windows-over-relay SSH workflow, current validation status, and next operational steps.
