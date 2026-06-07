# frozen_string_literal: true

# NS sync-health endpoint for external monitoring (Datadog,
# Better Stack, etc). Returns the current Ztlp::SyncState as
# JSON. Authenticated via the same per-zone HMAC scheme used by
# the rest of the Api::V1 surface — see Api::V1::BaseController
# and `app/services/ztlp/api_authenticator.rb` for the request
# contract.
#
#   GET /api/v1/sync_health
#   X-ZTLP-Zone: acme.ztlp
#   X-ZTLP-Client: z2ls.acme
#   X-ZTLP-Timestamp: <unix>
#   X-ZTLP-Signature: <hex>
#
#   → 200 {
#       "status":               "green",        # green | yellow | red
#       "last_success_at":      "2026-06-07T14:32:01Z" | null,
#       "last_failure_at":      "..." | null,
#       "consecutive_failures": 0,
#       "last_error_class":     null | "TransportError",
#       "next_retry_at":        null | "..."
#     }
#
# Status band is computed by SyncHealthHelper#sync_health_status
# (single source of truth shared with the dashboard banner).
module Api
  module V1
    class SyncHealthController < BaseController
      include SyncHealthHelper

      def show
        state = Ztlp::SyncState.current
        render json: {
          status:               sync_health_status(state).to_s,
          last_success_at:      state[:last_success_at]&.iso8601,
          last_failure_at:      state[:last_failure_at]&.iso8601,
          consecutive_failures: state[:consecutive_failures].to_i,
          last_error_class:     state[:last_error_class],
          next_retry_at:        state[:next_retry_at]&.iso8601
        }
      end
    end
  end
end
