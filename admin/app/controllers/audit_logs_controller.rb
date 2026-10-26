# frozen_string_literal: true

class AuditLogsController < ApplicationController
  def index
    @logs = AuditLog.order(created_at: :desc).includes(:admin)
    @logs = @logs.where(action: params[:action_filter]) if params[:action_filter].present?
    @logs = @logs.limit(200)
    @actions = AuditLog.distinct.order(:action).pluck(:action)
  end
end
