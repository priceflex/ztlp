# frozen_string_literal: true

# Ztlp::EnsureSharedMachines — boot-time seeding of the per-tenant Network
# with the shared production NS + Relay as Machine rows.
#
# ## Why this exists (sibling of EnsureNetworkFromEnv / BS-PR-4)
#
# Before this lands the tenant operator sees:
#   - Their Network row already exists (BS-PR-4 created it).
#   - The Machines tab is empty.
#   - Clicking "Generate enrollment token" fails with
#     "Network must have at least one NS machine" because the
#     TokenGenerator reads the NS IP off `network.ns_machines.first`.
#
# Walking the operator through "Add Machine → hostname=primary-ns →
# ip=35.91.88.177 → roles=ns" before they can do anything useful is a
# customer-onboarding paper cut. The NS+Relay are shared production
# infrastructure — every tenant uses the SAME IPs. There's no scenario
# where the operator picks different ones for their first onboarding.
#
# This service is called from the entrypoint right after
# EnsureNetworkFromEnv and seeds those two Machine rows automatically.
# The operator can still add their own NS/Relay machines later
# (self-hosted ZTLP) — those go to different IPs.
#
# ## Where the addresses come from
#
# Launch injects `ZTLP_SHARED_NS_ADDR` and `ZTLP_SHARED_RELAY_ADDR` into
# the bootstrap container. We fall back to the addresses Launch already
# injects for other reasons (`ZTLP_NS_SERVER`, `ZTLP_BOOTSTRAP_LISTENER_ADDR`)
# so legacy/dev/test runs that pre-date the shared-machine env vars still
# work. Both are accepted as `host:port` — we strip the port for the
# Machine row (Machine#ip_address validates as IPv4, no port).
#
# ## Idempotency contract
#
# The entrypoint runs this on EVERY container start. The service MUST be
# a no-op when both machines already exist for this network. We look up
# by ip_address (the canonical identity) — name collisions are tolerated
# (operator may have renamed `primary-ns` → something else; we leave
# the rename alone).
#
# ## Discriminator: ssh_user = "unmanaged"
#
# These pseudo-machines are NOT SSH-managed — the operator can't run a
# `Provision` button against the shared production NS. We use the
# string "unmanaged" in `ssh_user` as a structural marker. Machine#shared?
# returns true for any row with this marker, and the controllers guard
# Provision / Destroy on shared machines (see machines_controller.rb).
#
# ## Audit log
#
# One AuditLog row per seeded machine, action
# `machine.seeded_from_shared_env`. Idempotent re-runs write nothing.
module Ztlp
  class EnsureSharedMachines
    Result = Struct.new(:status, :machines, :message, keyword_init: true) do
      def created?  = status == :created
      def existing? = status == :existing
      def partial?  = status == :partial
      def skipped?  = status == :skipped
      def error?    = status == :error
    end

    # Marker stored in `ssh_user`. Machine#shared? matches against this
    # exact string. Don't change without a data migration on every
    # production bootstrap container.
    UNMANAGED_SSH_USER = "unmanaged"

    # Static defaults so dev/test/legacy boots without env vars still
    # produce the right rows. The production env vars from Launch
    # override these.
    DEFAULT_NS_ADDR    = "35.91.88.177:23096"
    DEFAULT_RELAY_ADDR = "34.218.240.106:23095"

    def self.call(env: ENV.to_h)
      new(env).call
    end

    def self.call_safely(env: ENV.to_h)
      call(env: env)
    rescue => e
      Rails.logger.error("[EnsureSharedMachines] unexpected error: #{e.class}: #{e.message}")
      Result.new(status: :error, message: "#{e.class}: #{e.message}")
    end

    def initialize(env)
      @env = env || {}
    end

    def call
      zone = @env["ZONE"].to_s.strip
      return Result.new(status: :skipped, message: "ZONE not set; nothing to do") if zone.empty?

      network = Network.find_by(zone: zone)
      return Result.new(status: :skipped, message: "no Network for zone=#{zone} yet (did EnsureNetworkFromEnv run?)") unless network

      ns_ip    = ip_from_addr(@env["ZTLP_SHARED_NS_ADDR"].presence || @env["ZTLP_NS_SERVER"].presence || DEFAULT_NS_ADDR)
      relay_ip = ip_from_addr(@env["ZTLP_SHARED_RELAY_ADDR"].presence || @env["ZTLP_BOOTSTRAP_LISTENER_ADDR"].presence || DEFAULT_RELAY_ADDR)

      created = []
      created << seed_machine(network: network, hostname: "primary-ns",    ip: ns_ip,    roles: "ns")
      created << seed_machine(network: network, hostname: "primary-relay", ip: relay_ip, roles: "relay")
      created.compact!

      if created.empty?
        Result.new(status: :existing, machines: network.machines.where(ssh_user: UNMANAGED_SSH_USER).to_a,
                   message: "shared machines already present")
      elsif created.length == 2
        Result.new(status: :created, machines: created, message: "seeded #{created.length} shared machines")
      else
        Result.new(status: :partial, machines: created, message: "seeded #{created.length}/2 shared machines (other already existed)")
      end
    end

    private

    # Accepts "host:port" or bare "host" and returns the host portion.
    # The Machine.ip_address column is validated as IPv4 dotted-quad with
    # no port — Launch passes "host:port" everywhere else, so we strip
    # here rather than at every call site.
    def ip_from_addr(addr)
      raw = addr.to_s.strip
      return nil if raw.empty?
      raw.split(":", 2).first
    end

    # Idempotent seed of a single Machine row. Returns the Machine on
    # creation, nil if a row with this ip already exists in this network.
    def seed_machine(network:, hostname:, ip:, roles:)
      return nil if ip.nil? || ip.empty?
      return nil if network.machines.exists?(ip_address: ip)

      # Hostname collision is possible if the operator already added a
      # machine named "primary-ns" pointing at a different IP. Disambiguate
      # by appending a short marker.
      effective_hostname = network.machines.exists?(hostname: hostname) ? "#{hostname}-shared" : hostname

      machine = network.machines.create!(
        hostname:         effective_hostname,
        ip_address:       ip,
        ssh_port:         22,
        ssh_user:         UNMANAGED_SSH_USER,
        ssh_auth_method:  "agent", # agent path skips the key/password ciphertext requirement
        roles:            roles,
        status:           "ready", # shared infra is always "ready" from the tenant's perspective
        # Machine has no `notes` column; reuse `last_error` as the marker
        # text. It's null on normal machines and visible in the dashboard
        # show page next to a "shared production infra" badge.
        last_error:       "Shared production #{roles.upcase} — provisioned by ztlp.net. Do not delete; token-mint depends on this row."
      )

      AuditLog.create!(
        action:      "machine.seeded_from_shared_env",
        target_type: "Machine",
        target_id:   machine.id,
        status:      "success",
        details:     { network_id: network.id, hostname: machine.hostname,
                       ip: machine.ip_address, roles: machine.roles }.to_json
      )
      machine
    rescue => e
      Rails.logger.warn("[EnsureSharedMachines] failed to seed #{hostname} ip=#{ip} for network=#{network.id}: #{e.class}: #{e.message}")
      nil
    end
  end
end
