# frozen_string_literal: true

# Slice 5b: compare panel rows against the NS record list every 30 min and
# store drift counts in system_settings `ns_drift_json`. Delegates to
# Ztlp::Reconciler (5b-ii); this job is the solid_queue seam.
class ReconcileNsJob < ApplicationJob
  queue_as :default

  def perform
    # One NS, several zones: run for each (a zone without its secrets/authority reports
    # :not_configured and is skipped by the service itself).
    # Returns { zone name => result }. One zone's NS error does not stop the others; the first error is
    # re-raised after every zone has run, so the job still fails visibly.
    results = {}
    first_error = nil
    Zone.order(:id).each do |zone|
      results[zone.name] = Ztlp::Reconciler.run(zone, admin: nil)
    rescue Ztlp::NsClient::NsError => e
      first_error ||= e
      results[zone.name] = :error
    end
    raise first_error if first_error

    results
  end
end
