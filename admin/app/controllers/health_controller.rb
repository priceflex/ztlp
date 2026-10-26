# frozen_string_literal: true

class HealthController < ActionController::Base
  def up
    ActiveRecord::Base.connection.execute("SELECT 1")
    render plain: "ok"
  end
end
