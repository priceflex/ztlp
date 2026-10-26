# frozen_string_literal: true

# Every 30 minutes: look up each Rust gateway's SVC record and mark it online / stale
# (Ztlp::GatewayStatus). One gateway's NS error does not stop the others; the first error is
# re-raised at the end so the job still fails visibly.
class GatewayStatusJob < ApplicationJob
  queue_as :default

  def perform
    first_error = nil
    results = {}
    Gateway.includes(:zone).where(kind: "rust_listen").find_each do |gateway|
      results[gateway.ns_name] = Ztlp::GatewayStatus.check!(gateway)
    rescue Ztlp::NsClient::NsError, SystemCallError, IOError, Timeout::Error => e
      first_error ||= e
      results[gateway.ns_name] = :error
    end
    raise first_error if first_error

    results
  end
end
