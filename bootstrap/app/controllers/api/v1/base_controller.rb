# frozen_string_literal: true

# Api::V1::BaseController — the parent class for the ZTLP-secured
# Bootstrap API namespace.
#
# Every action in `Api::V1::*` runs `authenticate_ztlp_request!` as a
# before_action. A request that fails authentication is rejected with
# a generic 401 — the reason code is logged but NOT sent in the
# response body (don't help an attacker enumerate why their forgery
# failed).
#
# On success, the authenticated `ApiClient` is exposed to the action
# as `current_api_client`.
#
# See `Ztlp::ApiAuthenticator` for the request-canonicalization rule
# and the per-zone HMAC contract.
module Api
  module V1
    class BaseController < ::Api::BaseController
      before_action :authenticate_ztlp_request!

      attr_reader :current_api_client

      private

      def authenticate_ztlp_request!
        result = Ztlp::ApiAuthenticator.new(request).authenticate

        if result.ok?
          @current_api_client = result.client
          AuditLog.record(
            action: "api.v1.auth.success",
            target: result.client,
            details: {
              client: result.client.name,
              zone: result.client.zone,
              path: request.fullpath,
              method: request.request_method
            },
            ip_address: request.remote_ip
          )
          return
        end

        # Log the reason at WARN level so ops can grep failed auths.
        Rails.logger.warn(
          "[Api::V1] auth rejected reason=#{result.reason} " \
          "ip=#{request.remote_ip} path=#{request.fullpath}"
        )

        AuditLog.record(
          action: "api.v1.auth.failure",
          target: nil,
          status: "failure",
          details: {
            reason: result.reason.to_s,
            path: request.fullpath,
            method: request.request_method
          },
          ip_address: request.remote_ip
        )

        render json: { error: "unauthorized" }, status: :unauthorized
      end
    end
  end
end
