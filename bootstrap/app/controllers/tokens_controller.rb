class TokensController < ApplicationController
  before_action :set_network
  before_action :set_token, only: [:show, :revoke]

  def index
    @tokens = @network.enrollment_tokens.order(created_at: :desc)
    # Refresh stale statuses
    @tokens.select(&:usable?).each(&:refresh_status!)
  end

  def show
  end

  def new
    @token = @network.enrollment_tokens.new
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

      redirect_to network_token_path(@network, @token), notice: "Enrollment token generated!"
    rescue TokenGenerator::TokenError => e
      redirect_to network_tokens_path(@network), alert: e.message
    end
  end

  # POST /networks/:network_id/tokens/:id/revoke
  def revoke
    @token.revoke!
    AuditLog.record(action: "token_revoke", target: @token, details: { token_id: @token.token_id })
    redirect_to network_tokens_path(@network), notice: "Token revoked."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_token
    @token = @network.enrollment_tokens.find(params[:id])
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
