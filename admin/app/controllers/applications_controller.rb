# frozen_string_literal: true

# Slice 9b sub-slice 2: Applications directory — read side (spec Slice 9).
# Index across the zone's gateways; show = page or drawer fragment (X-Drawer: 1,
# same contract as users/groups show). No Publisher calls: the rendered policy
# is computed locally with Ztlp::PolicyRenderer; publishing it is the operator's
# job at gateway deploy time (the page says so).
class ApplicationsController < ApplicationController
  def index
    @apps = @zone.gateways.includes(applications: %i[policy_rules]).flat_map(&:applications)
  end

  def show
    @application = Application
                     .where(id: params[:id])
                     .where(gateway_id: @zone.gateways.select(:id))
                     .includes(gateway: :zone, policy_rules: [])
                     .first
    raise ActiveRecord::RecordNotFound, "application" if @application.nil?

    render :show, layout: false if request.headers["X-Drawer"] == "1"
  end
end
