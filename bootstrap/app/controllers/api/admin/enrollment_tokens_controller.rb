# frozen_string_literal: true

# POST /api/admin/enrollment_tokens — Gateway-auth enrollment-token API for Z2LS.
#
# This is the "Option C" alternative to the HMAC v1 API
# (`POST /api/v1/enrollment_tokens`, see `bootstrap/docs/api_v1_ztlp_secured.md`).
# The HMAC contract is unusable in the current Launch-provisioned
# topology because the per-tenant ZTLP gateway is started with
# `--http-inject-headers`, which strips ALL inbound `X-ZTLP-*` headers
# as a defense against admin-auth spoofing. The HMAC API headers
# share that prefix, so they get stripped before reaching Rails.
# (Diagnosis: `docs/findings/2026-05-23-v1-api-header-collision.md`.)
#
# This endpoint side-steps the collision entirely by reusing the same
# gateway-auth path that the Bootstrap UI already uses:
#
#   Z2LS host (ZTLP-enrolled admin device)
#         │
#         │ ZTLP tunnel  (`ztlp connect bootstrap.<zone>`)
#         ▼
#   ZTLP gateway (injects authoritative X-ZTLP-Authenticated,
#                 X-ZTLP-Admin-Email, X-ZTLP-Timestamp, and HMACs
#                 them all into X-ZTLP-Signature using
#                 ZTLP_GATEWAY_HEADER_SECRET)
#         │
#         ▼
#   Rails — `ApplicationController#trusted_gateway_admin` verifies the
#           signature via `Ztlp::HeaderVerifier`, looks up the
#           AdminUser, and (when this controller's
#           `require_gateway_auth!` confirms gateway-auth specifically
#           succeeded) lets the request proceed.
#
# Z2LS becomes "an admin-equivalent client over ZTLP" rather than
# "a separately-credentialed system" — the trust boundary is the
# ZTLP device identity, not a shared HMAC secret.
#
# ── Why CSRF is safe to skip on this endpoint ──────────────────────
#
#   * The endpoint is only reachable when `require_gateway_auth!`
#     confirms `trusted_gateway_admin` succeeded.
#   * `trusted_gateway_admin` verifies the request carries a valid
#     gateway HMAC signature (`Ztlp::HeaderVerifier.verify_request`)
#     over `X-ZTLP-Authenticated`, `X-ZTLP-Admin-Email`,
#     `X-ZTLP-Timestamp`, `X-ZTLP-Signature`.
#   * Those headers can only be produced by the ZTLP gateway, which
#     only injects them when the connecting device is a ZTLP-enrolled
#     admin device for this zone.
#   * Therefore the ZTLP device-identity check is strictly stronger
#     than CSRF would be — there is no browser-driven cross-origin
#     surface to attack.
#   * Cookie-session admins (UI logins) are EXPLICITLY not allowed on
#     this endpoint: gateway-auth-only. This keeps the surface
#     auditable and the threat model crisp.
#
# Request payload (JSON):
#
#   {
#     "computer_name": "alice-laptop",
#     "metadata":      { "os": "macOS 14.5", "owner": "alice@..." },
#     "max_uses":      1,            # optional, defaults to 1
#     "expires_in":    "24h",        # optional, defaults to 24h
#     "zone":          "acme.ztlp"   # optional; only needed when this
#                                    # bootstrap host serves multiple
#                                    # zones (typical Launch container
#                                    # is single-zone)
#   }
#
# Response (201 Created) — identical shape to the HMAC v1 controller:
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
#   401 — gateway-auth headers missing/invalid/expired, OR admin
#         present only via cookie session (this endpoint requires
#         the gateway-auth path specifically).
#         Body: {"error": "unauthorized"}.
#   422 — computer_name missing / malformed; or zone ambiguous when
#         more than one Network row exists and the body didn't
#         disambiguate.
#         Body: {"error": "validation_failed", "message": "..."}.
#   503 — the requested zone has no NS machine yet (TokenGenerator
#         can't build the URI); operator should provision the
#         network before pointing Z2LS at it.
module Api
  module Admin
    class EnrollmentTokensController < ApplicationController
      # Gateway-auth means CSRF is redundant — see the threat-model
      # discussion in the file header. Skip ahead of the
      # `verify_authenticity_token` chain.
      skip_forgery_protection

      # Bypass the inherited `require_authentication` redirect-to-login
      # behavior: this endpoint is JSON-only and must return 401 JSON
      # on failure, never an HTML redirect.
      skip_before_action :require_authentication
      before_action :require_gateway_auth!

      # RFC1035 DNS label shape. Matches the HMAC v1 controller exactly
      # so behavior is consistent across both API surfaces.
      COMPUTER_NAME_REGEX = /\A[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\z/i.freeze

      MAX_COMPUTER_NAME_LENGTH = 253 # RFC1035 fully-qualified limit.

      # Map the most-common `expires_in` shorthand strings to durations.
      # Anything not in the map falls through to the model default
      # (`EnrollmentToken::DEFAULT_LIFETIME`, 24h).
      EXPIRES_IN_MAP = {
        "1h"  => 1.hour,
        "6h"  => 6.hours,
        "12h" => 12.hours,
        "24h" => 24.hours,
        "1d"  => 1.day,
        "3d"  => 3.days,
        "7d"  => 7.days,
        "1w"  => 7.days
      }.freeze

      def create
        computer_name = params[:computer_name].to_s.strip

        return render_validation_error("computer_name is required") if computer_name.empty?

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

        network = resolve_network
        unless network
          return render_validation_error(
            "could not resolve a Network for this request — pass `zone` in the body, " \
            "or ensure exactly one Network row exists for this tenant"
          )
        end

        max_uses   = parse_max_uses(params[:max_uses])
        expires_in = parse_expires_in(params[:expires_in])

        token = TokenGenerator.new(network).generate!(
          max_uses:   max_uses,
          expires_in: expires_in,
          notes:      build_notes(computer_name, params[:metadata]),
          # Phase B: admin-API path also needs to mint callback-capable tokens.
          bootstrap_url: request.base_url
        )

        AuditLog.record(
          action: "api.admin.enrollment_token.issued",
          target: token,
          details: {
            token_id:      token.token_id,
            computer_name: computer_name,
            zone:          network.zone,
            admin_email:   current_admin&.email,
            max_uses:      max_uses,
            expires_at:    token.expires_at.iso8601
          },
          ip_address: request.remote_ip
        )

        render json: build_response(token), status: :created
      rescue TokenGenerator::TokenError => e
        # Most likely cause: the zone is configured but has no
        # ns_machine yet (TokenGenerator can't build the URI without
        # one). 503 because the network/operator state is the gap,
        # not the caller's payload.
        render json: { error: "service_unavailable", message: e.message },
               status: :service_unavailable
      end

      private

      # Reject anything that did NOT pass through the gateway-auth path
      # (`trusted_gateway_admin`). Cookie-session admins are *not*
      # accepted here even though they would satisfy `current_admin`
      # in other controllers — see file header for rationale.
      def require_gateway_auth!
        admin = trusted_gateway_admin
        return if admin

        render json: { error: "unauthorized" }, status: :unauthorized
      end

      # Find the Network row this token should belong to. Resolution:
      #
      #   1. If `params[:zone]` was supplied, use that exact zone.
      #   2. Else if the current_admin record carries a `zone`
      #      attribute (forward-compat — not used in current schema),
      #      use that.
      #   3. Else fall back to the single Network row that exists
      #      per-tenant container (Launch topology is single-zone).
      #
      # Returns nil when none of these resolve a unique Network.
      def resolve_network
        if params[:zone].present?
          return Network.find_by(zone: params[:zone].to_s)
        end

        if current_admin.respond_to?(:zone) && current_admin.zone.present?
          row = Network.find_by(zone: current_admin.zone)
          return row if row
        end

        networks = Network.all.limit(2).to_a
        networks.length == 1 ? networks.first : nil
      end

      def parse_max_uses(raw)
        n = raw.to_i
        n > 0 ? n : 1
      end

      def parse_expires_in(raw)
        return EnrollmentToken::DEFAULT_LIFETIME if raw.blank?

        EXPIRES_IN_MAP[raw.to_s.downcase] || EnrollmentToken::DEFAULT_LIFETIME
      end

      def render_validation_error(message)
        render json: { error: "validation_failed", message: message },
               status: :unprocessable_entity
      end

      def build_response(token)
        lifetime = (token.expires_at - Time.current).to_i
        {
          enrollment_token:       token.token_uri,
          token_id:               token.token_id,
          expiration_datetime:    token.expires_at.utc.iso8601,
          token_lifetime_seconds: lifetime,
          status:                 "issued",
          message:                "Token issued; valid for #{lifetime / 3600}h, " \
                                  "#{token.max_uses == 1 ? 'single use' : "#{token.max_uses} uses"}."
        }
      end

      # `metadata` is an opaque JSON object — stored stringified in
      # `notes` so future additions to the payload don't require a
      # schema migration. Always prepend the computer_name + issuer.
      def build_notes(computer_name, metadata)
        issuer = current_admin&.email || "gateway-auth"
        prefix = "computer_name=#{computer_name} issued_by=#{issuer}"
        metadata = metadata.is_a?(ActionController::Parameters) ? metadata.permit!.to_h : metadata
        return prefix if metadata.blank?

        prefix + " metadata=" + metadata.to_json
      end
    end
  end
end
