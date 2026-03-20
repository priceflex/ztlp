# frozen_string_literal: true

class NotificationChannelsController < ApplicationController
  before_action :set_network
  before_action :set_channel, only: [:show, :edit, :update, :destroy, :test, :toggle]

  def index
    @channels = @network.notification_channels.order(:name)
  end

  def show
  end

  def new
    @channel = @network.notification_channels.new(
      channel_type: params[:type] || "email",
      severity_filter: "all",
      config_json: default_config_json(params[:type] || "email")
    )
  end

  def create
    @channel = @network.notification_channels.new(channel_params)
    @channel.config_json = build_config_json

    if @channel.save
      redirect_to network_notification_channels_path(@network), notice: "Notification channel created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    @channel.assign_attributes(channel_params)
    @channel.config_json = build_config_json

    if @channel.save
      redirect_to network_notification_channels_path(@network), notice: "Notification channel updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    @channel.destroy
    redirect_to network_notification_channels_path(@network), notice: "Notification channel deleted."
  end

  # POST /networks/:network_id/notifications/:id/test
  def test
    NotificationService.test_channel(@channel)
    @channel.reload
    if @channel.last_error.present?
      redirect_to network_notification_channels_path(@network),
        alert: "Test failed: #{@channel.last_error}"
    else
      redirect_to network_notification_channels_path(@network),
        notice: "Test notification sent successfully!"
    end
  end

  # POST /networks/:network_id/notifications/:id/toggle
  def toggle
    @channel.toggle!
    status = @channel.enabled? ? "enabled" : "disabled"
    redirect_to network_notification_channels_path(@network),
      notice: "#{@channel.name} #{status}."
  end

  # GET /networks/:network_id/notifications/logs
  def logs
    @logs = NotificationLog
      .joins(:notification_channel)
      .where(notification_channels: { network_id: @network.id })
      .order(created_at: :desc)

    @logs = @logs.where(notification_channel_id: params[:channel_id]) if params[:channel_id].present?
    @logs = @logs.where(status: params[:status]) if params[:status].present?
    @logs = @logs.where(event_type: params[:event_type]) if params[:event_type].present?

    @page = (params[:page] || 1).to_i
    @per_page = 25
    @total = @logs.count
    @logs = @logs.offset((@page - 1) * @per_page).limit(@per_page)

    @channels = @network.notification_channels.order(:name)
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_channel
    @channel = @network.notification_channels.find(params[:id])
  end

  def channel_params
    params.require(:notification_channel).permit(
      :name, :channel_type, :severity_filter, :event_filter, :enabled
    )
  end

  def build_config_json
    config = params[:config] || {}
    case params.dig(:notification_channel, :channel_type) || @channel&.channel_type
    when "email"
      {
        recipients: (config[:recipients] || "").split(",").map(&:strip).reject(&:empty?),
        from: config[:from].presence || "ztlp@localhost",
        smtp_server: config[:smtp_server].presence || "localhost",
        smtp_port: (config[:smtp_port].presence || 25).to_i,
        smtp_user: config[:smtp_user].presence,
        smtp_password: config[:smtp_password].presence
      }.compact.to_json
    when "webhook"
      {
        url: config[:url].presence,
        method: config[:method].presence || "POST",
        headers: parse_headers(config[:headers]),
        template: config[:template].presence
      }.compact.to_json
    when "slack"
      {
        webhook_url: config[:webhook_url].presence,
        channel: config[:channel].presence
      }.compact.to_json
    else
      "{}"
    end
  end

  def parse_headers(headers_str)
    return { "Content-Type" => "application/json" } if headers_str.blank?
    begin
      JSON.parse(headers_str)
    rescue JSON::ParserError
      { "Content-Type" => "application/json" }
    end
  end

  def default_config_json(type)
    case type
    when "email"
      { recipients: [], from: "ztlp@localhost", smtp_server: "localhost", smtp_port: 25 }.to_json
    when "webhook"
      { url: "", method: "POST", headers: { "Content-Type" => "application/json" } }.to_json
    when "slack"
      { webhook_url: "", channel: "#alerts" }.to_json
    else
      "{}"
    end
  end
end
