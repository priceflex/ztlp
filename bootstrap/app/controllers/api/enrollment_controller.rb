# frozen_string_literal: true

module Api
  class EnrollmentController < BaseController
    # POST /api/enrollment/confirm
    # Called by the CLI after successful enrollment to update token usage.
    #
    # Params:
    #   token_id: the hex token identifier
    #   node_id:  the enrolled device's NodeID (hex)
    #   name:     the enrolled device name (FQDN)
    def confirm
      token = EnrollmentToken.find_by(token_id: params[:token_id])

      unless token
        render json: { error: "Token not found" }, status: :not_found
        return
      end

      unless token.usable?
        render json: { error: "Token is no longer usable", status: token.status }, status: :unprocessable_entity
        return
      end

      token.use!

      render json: {
        status: "confirmed",
        token_id: token.token_id,
        current_uses: token.current_uses,
        max_uses: token.max_uses,
        exhausted: token.exhausted?
      }
    end
  end
end
