# frozen_string_literal: true

# Ztlp::SyncNsToBootstrap — the reconciler that mirrors NS DEVICE
# records into Bootstrap's `ztlp_devices` table.
#
# Run on a cron (T8) and on demand from the dashboard. Sources of
# truth:
#   * NS owns the DEVICE record itself (pubkey, TTL, serial).
#   * Bootstrap owns the per-device metadata (owner, machine binding,
#     assurance level, audit trail).
#
# This service is the seam between those two sources. It pulls the
# NS-owned half over `Ztlp::NsAdminClient` (T5) and produces or updates
# a `ZtlpDevice` row per name with `origin="ns_sync"` so it can be
# safely overwritten on the next run.
#
# ## Routing — longest-zone-suffix wins
#
# Each NS device name is FQDN-shaped: `host.zone.tld`. We pick the
# `Network` whose `zone` column is the LONGEST suffix of the name
# (case-insensitive). Examples:
#
#   name: "alice.adms.trs.ztlp"
#   networks: trs.ztlp (id=1), adms.trs.ztlp (id=6)
#   → matches both, picks adms.trs.ztlp (longer)
#
# Records with no matching network are SKIPPED (not raised) — the
# reconciler is the wrong place to enforce "every NS record must have
# a Bootstrap home". Those are logged in `result.errors`.
#
# ## Orphan sweep
#
# After all incoming records have been upserted, any row with
# `origin="ns_sync"` that wasn't touched this run is marked
# `status="orphaned"`. We NEVER delete — keeps the audit trail and
# lets operators see what disappeared.
#
# `origin="bootstrap"` rows (hand-entered devices, e.g. the
# operator's own laptop the operator created via the dashboard) are
# IMMUNE: we never read, write, or even consider them. NS doesn't
# know about them, and we trust the operator's hand-entry over NS.
#
# ## Failure model
#
# `NsAdminClient` raises one of four typed errors (Configuration,
# Authentication, Server, Transport — all subclasses of
# `NsAdminClient::Error`). We catch the parent and return a
# `Result(status: :error)` — callers (rake task / controller) decide
# whether to alert, retry, or just log.
module Ztlp
  class SyncNsToBootstrap
    Result = Struct.new(
      :status, :created, :updated, :orphaned, :skipped,
      :errors, :message, keyword_init: true
    ) do
      def success? = status == :ok
      def error?   = status == :error
    end

    def self.call(**kwargs) = new(**kwargs).call

    def initialize(client: Ztlp::NsAdminClient, clock: Time)
      @client = client
      @clock  = clock
    end

    def call
      payload = @client.list_records(type: "key")
      records = payload["records"] || []

      # Pre-index all networks by zone (lowercased) so we can hit the
      # routing decision in O(zones) per record without re-querying.
      networks_by_zone = Network.all.each_with_object({}) { |n, h| h[n.zone.downcase] = n }
      sorted_zones     = networks_by_zone.keys.sort_by { |z| -z.length }

      seen        = []   # [[name, network_id], ...] of rows touched this run
      counts      = { created: 0, updated: 0, orphaned: 0, skipped: 0 }
      errors      = []

      records.each do |rec|
        name    = rec["name"].to_s
        network = match_network(name, sorted_zones, networks_by_zone)
        unless network
          counts[:skipped] += 1
          errors << { name: name, reason: "no_matching_network" }
          next
        end

        device = ZtlpDevice.find_by(name: name, network_id: network.id)
        if device.nil?
          ZtlpDevice.create!(
            name:            name,
            network_id:      network.id,
            origin:          "ns_sync",
            status:          "enrolled",
            pubkey:          rec["pubkey_hex"],
            enrolled_at:     timestamp_from(rec["created_at"]),
            last_synced_at:  @clock.current
          )
          counts[:created] += 1
        else
          # NEVER overwrite a bootstrap-origin row — even if a name
          # collision somehow lined up with an NS record, the
          # operator's hand entry wins. Belt-and-braces; the
          # outer-loop fetch shouldn't find these in practice.
          if device.origin == "bootstrap"
            counts[:skipped] += 1
            errors << { name: name, reason: "bootstrap_origin_collision" }
            next
          end

          new_status = (device.status == "orphaned") ? "enrolled" : device.status
          device.update!(
            pubkey:         rec["pubkey_hex"],
            status:         new_status,
            last_synced_at: @clock.current
          )
          counts[:updated] += 1
        end

        seen << [name, network.id]
      end

      # Orphan sweep — only touch ns_sync rows we haven't just
      # touched, and only if they're not already orphaned (idempotent
      # across runs). origin="bootstrap" rows are excluded by the
      # `where(origin: "ns_sync")` scope on the very first line.
      ZtlpDevice.where(origin: "ns_sync").where.not(status: "orphaned").find_each do |d|
        next if seen.include?([d.name, d.network_id])
        d.update!(status: "orphaned")
        counts[:orphaned] += 1
      end

      Result.new(status: :ok, errors: errors, message: "sync ok", **counts)
    rescue Ztlp::NsAdminClient::Error => e
      Result.new(
        status:   :error,
        message:  "#{e.class}: #{e.message}",
        created:  0,
        updated:  0,
        orphaned: 0,
        skipped:  0,
        errors:   []
      )
    end

    private

    # Longest-suffix-wins zone match. Case-insensitive on both sides
    # (NS may return capitalized device names, networks store zones
    # lowercased). Accepts exact-match too (rare — happens when a
    # zone-only DEVICE record lands).
    def match_network(name, sorted_zones, networks_by_zone)
      lname = name.downcase
      hit = sorted_zones.find { |z| lname == z || lname.end_with?(".#{z}") }
      hit && networks_by_zone[hit]
    end

    # NS `created_at` is a UNIX epoch integer. Tolerate nil/missing
    # gracefully — no record has the right to break the whole run.
    def timestamp_from(epoch)
      return nil if epoch.nil?
      Time.at(epoch.to_i)
    end
  end
end
