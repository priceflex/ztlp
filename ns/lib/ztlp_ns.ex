defmodule ZtlpNs do
  @moduledoc """
  ZTLP-NS — Distributed Trust Namespace for the Zero Trust Layer Protocol.

  ZTLP-NS is the control-plane identity and discovery layer for ZTLP. It provides:

  - **Signed record storage** — All records are Ed25519-signed; unsigned records
    are rejected. This ensures that identity claims, service definitions, relay
    advertisements, and access policies cannot be forged.

  - **Hierarchical namespace** — Names are dot-separated, read right-to-left
    (like DNS). Trust flows from root anchors through operator zones to tenant
    zones to individual node records.

  - **Trust chain verification** — Every record's signature is verified against
    its zone authority's public key, which is itself signed by the parent zone,
    all the way up to a hardcoded root trust anchor.

  - **Revocation** — ZTLP_REVOKE records have the highest priority. Any lookup
    checks the revocation set first, ensuring compromised identities are
    promptly invalidated.

  - **Bootstrap discovery** — New nodes discover their first relay connections
    through a three-step fallback: HTTPS discovery → DNS-SRV → hardcoded anchors.

  ## Record Types

  | Type           | Purpose                                              |
  |----------------|------------------------------------------------------|
  | `ZTLP_KEY`     | Binds NodeID ↔ public key (identity certificate)    |
  | `ZTLP_SVC`     | Service definition with allowed node list            |
  | `ZTLP_RELAY`   | Relay endpoint, capacity, and region                 |
  | `ZTLP_POLICY`  | Access control rules for services                    |
  | `ZTLP_REVOKE`  | Revocation notice (highest priority on lookup)       |
  | `ZTLP_BOOTSTRAP` | Signed relay list for initial node discovery       |

  ## Architecture

  This implementation is a single-node prototype using:
  - ETS for in-memory record storage
  - Ed25519 via OTP 24's `:crypto` module
  - UDP query protocol for lookups
  - Pure Elixir/OTP with zero external dependencies
  """
end
