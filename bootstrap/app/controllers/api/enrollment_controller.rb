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
      token = EnrollmentToken.lock("FOR UPDATE NOWAIT").find_by(token_id: params[:token_id])

      unless token
        render json: { error: "Token not found" }, status: :not_found
        return
      end

      unless token.usable?
        render json: { error: "Token is no longer usable", status: token.status }, status: :unprocessable_entity
        return
      end

      if params[:node_id].blank?
        render json: { error: "node_id is required" }, status: :unprocessable_entity
        return
      end

      device = nil
      EnrollmentToken.transaction do
        token.use!

        device_name = params[:name].presence || "device-#{params[:node_id][0..7]}"

        device = token.network.ztlp_devices.find_or_initialize_by(node_id: params[:node_id])
        
        # Set values, only overwrite name if it's a new device or if name is explicitly given
        device.name = device_name if device.new_record? || params[:name].present?
        device.status = "enrolled"
        device.enrolled_at ||= Time.current
        # Only assign user if the token relation exists and is set
        if token.respond_to?(:ztlp_user_id) && token.ztlp_user_id.present?
          device.ztlp_user_id = token.ztlp_user_id
        end
        
        device.save!
        
        AuditLog.record(
          action: "enrollment_confirmed",
          target: device,
          details: { token_id: token.token_id, node_id: device.node_id }
        )
      end

      render json: {
        status: "confirmed",
        token_id: token.token_id,
        current_uses: token.current_uses,
        max_uses: token.max_uses,
        exhausted: token.exhausted?,
        device_id: device.id,
        device_name: device.name
      }
    end
  end
end
