# frozen_string_literal: true

# POST /api/v1/enrollment_tokens — Z2LS-driven single-device enrollment.
#
# This is the headline deliverable of the BS-PR-3 bootstrap workstream
# step. A trusted Z2LS instance (authenticated via the per-zone HMAC
# header chain — see `Api::V1::BaseController` and
# `bootstrap/docs/api_v1_ztlp_secured.md`) requests an enrollment
# token for a single new device. The endpoint:
#
#   1. Validates the `computer_name` payload field (RFC1035 DNS-label
#      shape, 1..63 bytes, optional `.zone` suffix).
#   2. Finds the `Network` row for the authenticated client's zone.
#      The authenticated client is bound to a `zone` via the
#      `api_clients` allowlist, so there's no way for a Z2LS in
#      zone A to mint tokens for zone B.
#   3. Delegates to `TokenGenerator#generate!` which already builds
#      the `ztlp://enroll/?...` URI, picks the right NS/relay
#      addresses from the Network's machines, and writes the
#      `EnrollmentToken` row.
#   4. Writes an `api.v1.enrollment_token.issued` audit log row
#      (separate from the `token_generate` row TokenGenerator writes)
#      that records WHO issued the token (the API client) — useful
#      for forensics that distinguish Z2LS-minted tokens from
#      admin-UI-minted tokens.
#   5. Returns the URI plus expiry metadata in the JSON response.
#
# Request payload:
#
#   { "computer_name": "alice-laptop", "metadata": { ... } }
#
# `metadata` is optional and stored as the EnrollmentToken's `notes`
# column (JSON-stringified) so future additions to the payload don't
# require a schema change. `computer_name` is currently the only
# required field per Steve's brief — "Design the API so more
# metadata can be added later."
#
# Response (201 Created):
#
#   {
#     "enrollment_token":       "ztlp://enroll/?zone=...&token=...",
#     "token_id":               "<hex>",
#     "expiration_datetime":    "2026-05-24T07:18:54Z",
#     "token_lifetime_seconds": 86400,
#     "status":                 "issued",
#     "message":                "Token issued; valid for 24h, single use."
#   }
#
# Failure responses:
#
#   401 — auth headers missing / bad / expired / client inactive
#         (handled by Api::V1::BaseController)
#   422 — computer_name missing / malformed / duplicates an
#         already-active token in the same zone
#   503 — the zone has no NS machine yet (TokenGenerator can't
#         build the URI); operator should provision the network
#         before pointing Z2LS at it
module Api
  module V1
    class EnrollmentTokensController < BaseController
      # RFC1035 DNS label: 1..63 chars, [a-z0-9], internal dots/hyphens
      # allowed, must start+end alphanumeric. Steve's brief calls
      # `computer_name` the only required field, so we accept the
      # widest sensible shape: a hostname OR a fully-qualified
      # hostname.zone.
      COMPUTER_NAME_REGEX = /\A[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\z/i.freeze

      MAX_COMPUTER_NAME_LENGTH = 253  # RFC1035 fully-qualified limit

      def create
        computer_name = params[:computer_name].to_s.strip

        if computer_name.empty?
          return render_validation_error("computer_name is required")
        end

        if computer_name.length > MAX_COMPUTER_NAME_LENGTH
          return render_validation_error(
            "computer_name exceeds RFC1035 length limit (#{MAX_COMPUTER_NAME_LENGTH})"
          )
        end

        unless computer_name.match?(COMPUTER_NAME_REGEX)
          return render_validation_error(
            "computer_name must be a valid DNS label (lowercase alphanumeric + hyphens/dots)"
          )
        end

        network = Network.find_by(zone: current_api_client.zone)

        unless network
          # The authenticated client's zone has no Network row in
          # bootstrap. This means the zone was authorized to call us
          # (we have an api_clients row) but the network itself was
          # never provisioned via the dashboard. Surface a clear 503
          # so the operator knows what to fix.
          return render_service_unavailable(
            "no network configured for zone=#{current_api_client.zone}; " \
            "create one via the admin dashboard first"
          )
        end

        # Single-use, 24h default. The 24h default is enforced by
        # EnrollmentToken#set_default_expires_at (BS-PR-1) — TokenGenerator
        # passes through `expires_in:` explicitly so we set it here as
        # a paranoia belt-and-suspenders.
        token = TokenGenerator.new(network).generate!(
          max_uses: 1,
          expires_in: EnrollmentToken::DEFAULT_LIFETIME,
          notes: build_notes(computer_name, params[:metadata])
        )

        AuditLog.record(
          action: "api.v1.enrollment_token.issued",
          target: token,
          details: {
            token_id: token.token_id,
            computer_name: computer_name,
            zone: network.zone,
            issued_by_api_client: current_api_client.name,
            expires_at: token.expires_at.iso8601
          },
          ip_address: request.remote_ip
        )

        render json: build_response(token), status: :created
      rescue TokenGenerator::TokenError => e
        # Most likely cause: the zone is configured but has no
        # ns_machine yet (TokenGenerator can't build the URI without
        # one). 503 because the network/operator state is the gap,
        # not the caller's payload.
        render_service_unavailable(e.message)
      end

      private

      def render_validation_error(message)
        render json: { status: "error", message: message }, status: :unprocessable_entity
      end

      def render_service_unavailable(message)
        render json: { status: "error", message: message }, status: :service_unavailable
      end

      def build_response(token)
        {
          enrollment_token: token.token_uri,
          token_id: token.token_id,
          expiration_datetime: token.expires_at.utc.iso8601,
          token_lifetime_seconds: (token.expires_at - Time.current).to_i,
          status: "issued",
          message: "Token issued; valid for #{(token.expires_at - Time.current).to_i / 3600}h, single use."
        }
      end

      # `metadata` is an opaque JSON object — we store it stringified in
      # `notes` so future additions to the payload don't require a
      # schema migration. Always prepend the computer_name + issuer so
      # admin-UI displays of `notes` carry the most useful context.
      def build_notes(computer_name, metadata)
        prefix = "computer_name=#{computer_name} issued_by=#{current_api_client.name}"
        metadata = metadata.is_a?(ActionController::Parameters) ? metadata.permit!.to_h : metadata
        return prefix if metadata.blank?

        prefix + " metadata=" + metadata.to_json
      end
    end
  end
end
