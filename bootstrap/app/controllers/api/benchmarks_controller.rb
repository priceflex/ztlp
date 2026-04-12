# frozen_string_literal: true

module Api
  class BenchmarksController < BaseController
    before_action :authenticate_api_token!

    # POST /api/benchmarks
    def create
      # Try to find the device by node_id or device_id
      device = find_device(params[:node_id] || params[:device_id])

      benchmark = BenchmarkResult.new(
        ztlp_device: device,
        network: @api_network,
        device_id: params[:device_id],
        node_id: params[:node_id],
        app_version: params[:app_version],
        build_tag: params[:build_tag],
        device_model: params[:device_model],
        ios_version: params[:ios_version],
        ne_memory_mb: params[:ne_memory_mb],
        ne_virtual_mb: params[:ne_virtual_mb],
        ne_memory_pass: params[:ne_memory_pass],
        benchmarks_passed: params[:benchmarks_passed],
        benchmarks_total: params[:benchmarks_total],
        individual_results: params[:individual_results],
        relay_address: params[:relay_address],
        gateway_address: params[:gateway_address],
        ns_address: params[:ns_address],
        latency_ms: params[:latency_ms],
        throughput_kbps: params[:throughput_kbps],
        p99_latency_ms: params[:p99_latency_ms],
        packet_loss_pct: params[:packet_loss_pct],
        errors: params[:errors]
      )

      if benchmark.save
        # Update device's last_seen if found
        device&.update!(
          last_seen_at: Time.current,
          client_version: benchmark.app_version,
          os_info: "#{benchmark.device_model} #{benchmark.ios_version}"
        )

        render json: {
          status: "ok",
          benchmark_id: benchmark.id,
          summary: {
            all_passed: benchmark.all_passed?,
            memory_ok: benchmark.memory_ok?,
            score: "#{benchmark.benchmarks_passed}/#{benchmark.benchmarks_total}"
          }
        }, status: :created
      else
        render json: { error: benchmark.errors.full_messages }, status: :unprocessable_entity
      end
    end

    # GET /api/benchmarks
    def index
      scope = @api_network.benchmark_results.includes(:ztlp_device)
      scope = scope.recent.limit(params[:limit] || 50)
      render json: scope.as_json(include: { ztlp_device: { only: %i[node_id name] } })
    end

    private

    def authenticate_api_token!
      token = request.headers["Authorization"]&.gsub(/^Bearer\s+/i, "")
      return render json: { error: "Unauthorized" }, status: :unauthorized if token.blank?

      @api_network = Network.all.find do |n|
        # Try decrypted value (for encrypted data)
        secret = begin
          ActiveRecord::Encryption.encryptor.decrypt(
            n[:enrollment_secret_ciphertext],
            message_serializer: ActiveRecord::Encryption::MessageSerializer
          )
        rescue
          n[:enrollment_secret_ciphertext]
        end
        secret.nil? ? false : secret.strip == token.strip
      end
      return render json: { error: "Unauthorized" }, status: :unauthorized unless @api_network
    end

    def find_device(identifier)
      return nil if identifier.blank?
      ZtlpDevice.find_by(id: identifier) || ZtlpDevice.find_by(node_id: identifier)
    end
  end
end
