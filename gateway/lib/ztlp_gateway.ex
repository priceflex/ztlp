defmodule ZtlpGateway do
  @moduledoc """
  ZTLP Gateway — bridges ZTLP's identity-first overlay to legacy TCP services.

  The gateway terminates ZTLP sessions on behalf of backend services.
  Unlike a relay (which forwards opaque encrypted packets), the gateway:

  1. Performs the Noise_XX handshake as the responder
  2. Derives session encryption keys
  3. Decrypts inbound ZTLP data payloads
  4. Forwards plaintext to backend TCP services
  5. Encrypts backend responses and sends them back as ZTLP packets
  6. Enforces access policy (which NodeIDs may reach which services)
  7. Logs all session events for audit

  ## Architecture

      ZTLP Client → [Relay Mesh] → Gateway (UDP) → Backend Service (TCP)

  ## Supervision Tree

      ZtlpGateway.Application
      ├── ZtlpGateway.Stats
      ├── ZtlpGateway.AuditLog
      ├── ZtlpGateway.SessionRegistry
      ├── ZtlpGateway.PolicyEngine
      ├── ZtlpGateway.SessionSupervisor (DynamicSupervisor)
      └── ZtlpGateway.Listener (UDP)

  ## Protocol

  Uses `Noise_XX_25519_ChaChaPoly_BLAKE2s`:
  - X25519 for Diffie-Hellman key exchange
  - ChaCha20-Poly1305 for AEAD encryption
  - BLAKE2s for hashing

  All crypto is handled by OTP 24's `:crypto` module — zero external deps.
  """
end
