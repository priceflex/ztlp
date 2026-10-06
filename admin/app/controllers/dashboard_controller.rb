# frozen_string_literal: true

class DashboardController < ApplicationController
  def show
    @admins = Admin.order(:username)
    @zone = Zone.primary
    @recent_audit = AuditLog.order(created_at: :desc).limit(15).includes(:admin)
  end
end
