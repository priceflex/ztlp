# frozen_string_literal: true

class EnrollmentController < ApplicationController
  before_action :set_network

  def index
    @tokens = @network.enrollment_tokens.order(created_at: :desc)
    @active_tokens = @tokens.select(&:usable?)
    @recent_devices = @network.ztlp_devices.enrolled.order(enrolled_at: :desc).limit(10)
  end

  def create
    generator = TokenGenerator.new(@network)

    begin
      expires_in = parse_duration(params[:expires_in] || "24h")
      max_uses = (params[:max_uses] || 1).to_i
      roles = params[:roles]
      notes = params[:notes]

      @token = generator.generate!(
        expires_in: expires_in,
        max_uses: max_uses,
        roles: roles,
        notes: notes
      )

      AuditLog.record(
        action: "enrollment_token_create",
        target: @token,
        details: { token_id: @token.token_id, max_uses: max_uses, network: @network.name }
      )

      redirect_to network_enrollment_index_path(@network), notice: "Enrollment token generated!"
    rescue TokenGenerator::TokenError => e
      redirect_to network_enrollment_index_path(@network), alert: e.message
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def parse_duration(str)
    case str
    when /\A(\d+)h\z/ then $1.to_i.hours
    when /\A(\d+)d\z/ then $1.to_i.days
    when /\A(\d+)m\z/ then $1.to_i.minutes
    else 24.hours
    end
  end
end
