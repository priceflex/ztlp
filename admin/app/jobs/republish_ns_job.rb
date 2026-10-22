# frozen_string_literal: true

# Slice 5b: re-publish the zone's NS records (authority KEY, active users,
# groups, enrolled devices), spaced ~1.1 s (spec Slice 5: 6-hourly republish).
# Delegates to Ztlp::Republisher (5b-ii) which holds the NS write + audit;
# this job is the solid_queue seam.
class RepublishNsJob < ApplicationJob
  queue_as :default

  def perform
    zone = Zone.primary
    Ztlp::Republisher.run(zone, admin: nil)
  end
end
