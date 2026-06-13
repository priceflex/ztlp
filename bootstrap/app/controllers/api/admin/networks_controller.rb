# frozen_string_literal: true

# POST /api/admin/networks — Gateway-auth Network-creation API for Z2LS.
#
# The Phase-1 companion to Api::Admin::EnrollmentTokensController. Before this
# endpoint existed, a per-customer Network row (zone) could only be created via
# the HTML dashboard (cookie + CSRF), the Wizard, or EnsureNetworkFromEnv at
# container boot — none reachable from the Z2LS one-click onboarding flow. The
# mint endpoint hard-requires a pre-existing Network (returns "could not
# resolve a Network" / 503 otherwise), so Z2LS had to ask an operator to create
# the zone by hand first. This endpoint closes that gap.
#
# Same auth model as EnrollmentTokensController: reachable ONLY over the ZTLP
# gateway-auth path (signed X-ZTLP-* headers injected by the per-tenant
# gateway), never via cookie session. See that controller's header for the full
# threat model and why CSRF is safe to skip here.
#
# Creating the Network fires Network#after_create_commit, which (when
# seed_shared_machines_on_create is enabled in the real container) auto-seeds
# the shared NS+Relay Machine rows — so a subsequent mint on the new zone
# succeeds without any manual machine attachment.
#
# Request payload (JSON):
#
#   { "zone": "acme-dental.trs.ztlp", "name": "Acme Dental" }
#
#   zone — required; RFC1035-ish ZTLP zone label (lowercase alnum + - + .).
#   name — optional; defaults to the zone string. Never overwrites an existing
#          row's name on a re-onboard (idempotency contract).
#
# Responses:
#   201 Created  — new Network. Body: { status:"created", network_id, zone, name }
#   200 OK       — zone already existed (idempotent). Body: { status:"existing", ... }
#   401          — gateway-auth missing/invalid, or cookie-only admin.
#   422          — zone missing or malformed. Body: { error:"validation_failed", message }
module Api
  module Admin
    class NetworksController < ApplicationController
      skip_forgery_protection
      skip_before_action :require_authentication
      before_action :require_gateway_auth!

      # Mirrors Network model + EnsureNetworkFromEnv zone validation.
      ZONE_FORMAT = /\A[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\z/.freeze

      def create
        zone = params[:zone].to_s.strip.downcase

        return render_validation_error("zone is required") if zone.empty?
        unless zone.match?(ZONE_FORMAT)
          return render_validation_error(
            "zone must be a valid ZTLP zone name (lowercase alphanumeric + hyphens/dots)"
          )
        end

        existing = Network.find_by(zone: zone)
        if existing
          # Idempotent re-onboard: do NOT clobber the operator's name/status.
          return render json: build_response(existing, "existing"), status: :ok
        end

        name = params[:name].to_s.strip
        name = zone if name.empty?
        name = unique_name_for(name, zone)

        network = Network.new(zone: zone, name: name, status: "created")
        network.enrollment_secret_ciphertext = SecureRandom.hex(32) if network.enrollment_secret_ciphertext.blank?

        unless network.save
          return render_validation_error(network.errors.full_messages.join(", "))
        end

        AuditLog.record(
          action: "api.admin.network.created",
          target: network,
          details: {
            network_id:  network.id,
            zone:        network.zone,
            name:        network.name,
            admin_email: current_admin&.email
          },
          ip_address: request.remote_ip
        )

        render json: build_response(network, "created"), status: :created
      end

      private

      def require_gateway_auth!
        return if trusted_gateway_admin

        render json: { error: "unauthorized" }, status: :unauthorized
      end

      # Resolve UNIQUE(name) collisions the same way EnsureNetworkFromEnv does:
      # append the zone, then a numeric suffix, so a duplicate display name from
      # a different zone doesn't 422 the caller.
      def unique_name_for(base, zone)
        return base unless Network.exists?(name: base)
        candidate = "#{base} (#{zone})"
        return candidate unless Network.exists?(name: candidate)
        (2..10).each do |n|
          suffix = "#{candidate} ##{n}"
          return suffix unless Network.exists?(name: suffix)
        end
        "#{candidate} #{SecureRandom.hex(2)}"
      end

      def render_validation_error(message)
        render json: { error: "validation_failed", message: message },
               status: :unprocessable_entity
      end

      def build_response(network, status)
        {
          status:     status,
          network_id: network.id,
          zone:       network.zone,
          name:       network.name
        }
      end
    end
  end
end
