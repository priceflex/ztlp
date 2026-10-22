# frozen_string_literal: true

# Slice 5b: compare panel rows against the NS record list every 30 min and
# store drift counts in system_settings `ns_drift_json`. Delegates to
# Ztlp::Reconciler (5b-ii); this job is the solid_queue seam.
class ReconcileNsJob < ApplicationJob
  queue_as :default

  def perform
    zone = Zone.primary
    Ztlp::Reconciler.run(zone, admin: nil)
  end
end
