# frozen_string_literal: true

module Api
  class StatusController < BaseController
    before_action :authenticate_api_token!

    # POST /api/heartbeat
    def heartbeat
      device = find_device(params[:device_id] || params[:node_id])
      return render json: { error: "Device not found" }, status: :not_found unless device

      # Rate limit: max 1 heartbeat per device per 30 seconds
      last_heartbeat = device.device_heartbeats.order(created_at: :desc).first
      if last_heartbeat && last_heartbeat.created_at > 30.seconds.ago
        return render json: { error: "Rate limited. Max 1 heartbeat per 30 seconds." }, status: :too_many_requests
      end

      heartbeat = DeviceHeartbeat.new(
        ztlp_device: device,
        network: device.network,
        source_ip: params[:source_ip] || request.remote_ip,
        source_port: params[:source_port],
        relay_name: params[:relay_name],
        latency_ms: params[:latency_ms],
        bytes_sent: params[:bytes_sent] || 0,
        bytes_received: params[:bytes_received] || 0,
        active_streams: params[:active_streams] || 0,
        client_version: params[:client_version],
        os_info: params[:os_info],
        created_at: Time.current
      )

      if heartbeat.save
        # Update device's last-seen info
        device.update!(
          last_seen_at: Time.current,
          last_source_ip: heartbeat.source_ip,
          last_relay: heartbeat.relay_name,
          client_version: heartbeat.client_version,
          os_info: heartbeat.os_info
        )

        render json: { status: "ok", heartbeat_id: heartbeat.id }, status: :created
      else
        render json: { error: heartbeat.errors.full_messages }, status: :unprocessable_entity
      end
    end

    # POST /api/events
    def event
      device = find_device(params[:device_id] || params[:node_id])
      return render json: { error: "Device not found" }, status: :not_found unless device

      conn_event = ConnectionEvent.new(
        ztlp_device: device,
        network: device.network,
        ztlp_user: device.ztlp_user,
        event_type: params[:event_type],
        source_ip: params[:source_ip] || request.remote_ip,
        relay_name: params[:relay_name],
        disconnect_reason: params[:disconnect_reason],
        session_duration_seconds: params[:session_duration_seconds],
        details: params[:details],
        created_at: Time.current
      )

      if conn_event.save
        # Update device last_seen on connect/reconnect events
        if %w[connected reconnected].include?(conn_event.event_type)
          device.update!(
            last_seen_at: Time.current,
            last_source_ip: conn_event.source_ip,
            last_relay: conn_event.relay_name
          )
        end

        render json: { status: "ok", event_id: conn_event.id }, status: :created
      else
        render json: { error: conn_event.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def authenticate_api_token!
      token = request.headers["Authorization"]&.sub(/\ABearer\s+/, "")
      return render json: { error: "Unauthorized" }, status: :unauthorized if token.blank?

      # Accept any network's enrollment secret as a valid API token
      @api_network = Network.all.find { |n| n.enrollment_secret_ciphertext == token }
      return render json: { error: "Unauthorized" }, status: :unauthorized unless @api_network
    end

    def find_device(identifier)
      return nil if identifier.blank?

      # Try by ID first, then by node_id
      ZtlpDevice.find_by(id: identifier) || ZtlpDevice.find_by(node_id: identifier)
    end
  end
end
