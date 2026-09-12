# ZTLP Architecture Diagrams

High-level Mermaid diagrams for getting oriented in the ZTLP repository. These are
deliberately zoomed out — for implementation-level detail see `docs/ARCHITECTURE.md`
and the whitepaper (`whitepaper/ZTLP-Whitepaper.md`).

| Diagram | What it shows |
|---|---|
| [01-system-overview.md](01-system-overview.md) | All major components and how they talk to each other |
| [02-admission-pipeline.md](02-admission-pipeline.md) | The 3-layer cheap-rejection/expensive-admission packet pipeline |
| [03-connection-lifecycle.md](03-connection-lifecycle.md) | Sequence diagram: identity lookup → Noise_XX handshake → data → teardown |
| [04-repo-map.md](04-repo-map.md) | Which top-level directory implements which architectural component |

## Reading order

If you're new to the project, go in order: the system overview gives you the
nouns (components), the admission pipeline and connection lifecycle give you the
verbs (what happens on the wire), and the repo map tells you where to go read
code for any of it.
