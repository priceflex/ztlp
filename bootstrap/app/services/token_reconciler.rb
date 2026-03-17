# frozen_string_literal: true

# Reconciles Bootstrap enrollment tokens with NS server state.
#
# After a device enrolls via ZTLP, the NS server logs the enrollment
# (device name, node_id, timestamp). This service queries the NS via
# the ZTLP tunnel during health checks and marks tokens as exhausted
# when their corresponding enrollments are confirmed.
#
# Matching logic: Each NS enrollment has a timestamp. If an enrollment
# occurred after a token was created and within the same zone, the
# oldest matching pending token is marked as consumed.
#
# Called during health checks after NS connectivity is confirmed.
#
# Usage:
#   TokenReconciler.reconcile!(network)
#
class TokenReconciler
  RECONCILE_INTERVAL = 5.minutes  # Don't reconcile more often than this

  class << self
    def reconcile!(network)
      return unless should_reconcile?(network)

      pending = network.enrollment_tokens
                       .where(status: "active")
                       .where("current_uses < max_uses")
                       .order(:created_at)
      return if pending.none?

      Rails.logger.info("[TokenReconciler] Checking #{pending.count} pending tokens for #{network.name}")

      # First: expire any tokens past their expiry date
      expired_count = expire_stale_tokens!(pending)

      # Re-query after expiring
      pending = network.enrollment_tokens
                       .where(status: "active")
                       .where("current_uses < max_uses")
                       .order(:created_at)
      return touch_reconcile_timestamp!(network) if pending.none?

      # Fetch enrollment log from NS via ZTLP tunnel
      ns_machine = network.ns_machines.first
      unless ns_machine
        Rails.logger.warn("[TokenReconciler] No NS machine found for #{network.name}")
        touch_reconcile_timestamp!(network)
        return
      end

      enrollments = fetch_ns_enrollments(ns_machine)
      unless enrollments
        Rails.logger.warn("[TokenReconciler] Could not reach NS for token reconciliation")
        touch_reconcile_timestamp!(network)
        return
      end

      Rails.logger.info("[TokenReconciler] NS reports #{enrollments.size} enrollments")

      # Match enrollments to pending tokens
      reconciled = match_enrollments_to_tokens!(pending, enrollments)

      if reconciled > 0 || expired_count > 0
        Rails.logger.info("[TokenReconciler] Done: #{reconciled} reconciled, #{expired_count} expired for #{network.name}")
      else
        Rails.logger.info("[TokenReconciler] No changes needed for #{network.name}")
      end

      touch_reconcile_timestamp!(network)
    rescue StandardError => e
      Rails.logger.warn("[TokenReconciler] Failed: #{e.class}: #{e.message}")
    end

    private

    def should_reconcile?(network)
      last = Rails.cache.read("token_reconcile:#{network.id}")
      return true unless last
      Time.current - Time.parse(last) > RECONCILE_INTERVAL
    rescue StandardError
      true
    end

    def touch_reconcile_timestamp!(network)
      Rails.cache.write("token_reconcile:#{network.id}", Time.current.iso8601)
    end

    # Mark tokens that are past their expiry date
    def expire_stale_tokens!(pending)
      count = 0
      pending.each do |token|
        if token.expired?
          token.update!(status: "expired")
          count += 1
          Rails.logger.info("[TokenReconciler] Token #{token.token_id}: expired (past #{token.expires_at})")
        end
      end
      count
    end

    # Fetch enrollment log from NS via ZTLP tunnel's /token_status endpoint
    def fetch_ns_enrollments(ns_machine)
      return nil unless ZtlpTunnel.available? && ZtlpTunnel.enrolled?

      gateway_port = SshProvisioner.gateway_port_for(ns_machine)
      gateway_addr = "#{ns_machine.ip_address}:#{gateway_port}"
      relay_addr = find_relay_addr(ns_machine)

      tunnel = ZtlpTunnel.new(
        gateway_addr: gateway_addr,
        service: "metrics",
        relay_addr: relay_addr
      )

      result = tunnel.fetch_endpoint("/token_status")
      unless result[:available] && result[:body]
        Rails.logger.debug("[TokenReconciler] fetch_endpoint failed: #{result[:error]}")
        return nil
      end

      parsed = JSON.parse(result[:body])
      parsed["enrollments"] || []
    rescue JSON::ParserError => e
      Rails.logger.warn("[TokenReconciler] JSON parse error: #{e.message}")
      nil
    rescue StandardError => e
      Rails.logger.warn("[TokenReconciler] Error fetching enrollments: #{e.class}: #{e.message}")
      nil
    end

    # NS machines are reached directly (same VPC); only relay machines need relay routing.
    # Matches the logic in HealthChecker#find_relay_addr and ZtlpConnectivity.find_relay_addr.
    def find_relay_addr(machine)
      return nil unless machine.role_list.include?("relay")
      relay_port = SshProvisioner::ZTLP_PORTS.dig("relay", :udp) || 23095
      "#{machine.ip_address}:#{relay_port}"
    end

    # Match NS enrollments against pending tokens.
    # Logic: for each enrollment, find the oldest pending token that was
    # created before the enrollment timestamp and is in the same zone.
    # Mark it as exhausted.
    def match_enrollments_to_tokens!(pending_tokens, enrollments)
      return 0 if enrollments.empty?

      # Build a list of enrollment timestamps
      enrollment_times = enrollments.map { |e| Time.at(e["enrolled_at"].to_i).utc }
                                    .sort

      # Track which tokens we've already matched
      matched_token_ids = Set.new
      reconciled = 0

      # For each enrollment (oldest first), find the oldest unmatched pending token
      # that was created before this enrollment
      enrollment_times.each do |enrolled_at|
        token = pending_tokens.find do |t|
          !matched_token_ids.include?(t.id) &&
            t.status == "active" &&
            t.created_at <= enrolled_at
        end

        next unless token

        token.increment!(:current_uses)
        token.update!(status: "exhausted") if token.current_uses >= token.max_uses
        matched_token_ids.add(token.id)
        reconciled += 1
        Rails.logger.info("[TokenReconciler] ✓ Token #{token.token_id}: marked exhausted (matched enrollment at #{enrolled_at})")
      end

      reconciled
    end
  end
end
