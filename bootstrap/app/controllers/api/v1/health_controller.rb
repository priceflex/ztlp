# frozen_string_literal: true

# Smoke endpoint for the ZTLP-secured API namespace.
#
# Returns a tiny JSON payload echoing the authenticated client back
# to the caller. Useful for Z2LS / API client developers to verify
# their HMAC signing implementation before moving on to mutating
# endpoints (BS-PR-3 `POST /api/v1/enrollment_tokens`).
#
#   GET /api/v1/health
#   X-ZTLP-Zone: acme.ztlp
#   X-ZTLP-Client: z2ls.acme
#   X-ZTLP-Timestamp: 1700000000
#   X-ZTLP-Signature: <hex>
#
#   → 200 {"ok": true, "client": "z2ls.acme", "zone": "acme.ztlp",
#          "server_time": "2026-05-23T06:55:00Z"}
module Api
  module V1
    class HealthController < BaseController
      def show
        render json: {
          ok: true,
          client: current_api_client.name,
          zone: current_api_client.zone,
          server_time: Time.current.iso8601
        }
      end
    end
  end
end
