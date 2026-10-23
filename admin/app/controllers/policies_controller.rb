# frozen_string_literal: true

# Slice 9c sub-slice 1: the Policies page — read-only overview of every
# application's rules (grouped by application, across the zone's gateways)
# plus the Test access widget (device + application pickers). No mutations,
# no Publisher calls. The widget's POST target (POST /policies/test) and its
# decision rendering land in sub-slice 2; the form posts there and the page
# renders the result once the action exists.
class PoliciesController < ApplicationController
  def index
    @gateways = @zone.gateways.order(:name).includes(applications: :policy_rules)
    @policy_docs = @gateways.index_with { |gw| Ztlp::PolicyRenderer.render(gw) }
    @test_devices = @zone.devices.order(:name).limit(500)
    @test_apps = @gateways.flat_map { |gw| gw.applications.order(:name).to_a.map { |a| [ gw, a ] } }
  end
end
