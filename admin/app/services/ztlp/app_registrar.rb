# frozen_string_literal: true

module Ztlp
  # Register an application by its full ZTLP name (www.chooseforce.ztlp, blitz.trs.ztlp): find the
  # zone from the name, look the service up on the NS (SVC record via the admin API), and create the
  # gateway + application rows. READ-ONLY toward the NS: registering never publishes anything.
  # PLAN-multizone-and-app-registration.md, Phase B.
  class AppRegistrar
    class Error < StandardError; end

    LABEL = Admin::USERNAME

    # The configured zone the name belongs to: the LONGEST zone suffix, matched on a whole label
    # ("www.evilcf.test" is not in "cf.test"); the zone name itself is not a service.
    def self.zone_for(fqdn)
      name = fqdn.to_s.strip.downcase
      Zone.all.select { |z| name.end_with?(".#{z.name}") }.max_by { |z| z.name.length }
    end

    # The service label inside its zone ("www" for www.chooseforce.ztlp). nil unless ONE DNS label.
    def self.label_for(fqdn, zone)
      label = fqdn.to_s.strip.downcase.delete_suffix(".#{zone.name}")
      label.match?(LABEL) ? label : nil
    end

    # SVC record for the name, or nil (not on the NS). :not_configured without an NS admin secret.
    def self.lookup(fqdn, zone, ns_client: NsClient)
      secret = zone.ns_admin_secret
      return :not_configured if secret.blank?

      svc_records(zone, secret, ns_client).find { |r| r[:name] == fqdn.to_s.strip.downcase }
    end

    # Services on the NS (in configured zones) that have no gateway row yet.
    # Returns [ [rows], [errors] ].
    def self.discover(ns_client: NsClient)
      rows = []
      errors = []
      Zone.order(:name).each do |zone|
        secret = zone.ns_admin_secret
        next if secret.blank?

        svc_records(zone, secret, ns_client).each do |r|
          next unless zone_for(r[:name]) == zone && label_for(r[:name], zone)
          next if zone.gateways.exists?(ns_name: r[:name])

          rows << { fqdn: r[:name], zone: zone, data: r[:data] || {}, created_at: r[:created_at] }
        end
      rescue NsClient::NsError, SystemCallError, IOError, Timeout::Error, Net::OpenTimeout => e
        errors << "#{zone.name}: #{e.class}"
      end
      [ rows.sort_by { |row| row[:fqdn] }, errors ]
    end

    # Create (or return the existing) gateway + application for the name. `record` is the SVC
    # record from #lookup (nil = not running yet -> planned). Returns the Application.
    def self.register!(fqdn, zone, record:, backend: nil)
      label = label_for(fqdn, zone) or raise Error, "#{fqdn} must be one DNS label inside #{zone.name}"
      data = (record && record[:data]) || {}
      Gateway.transaction do
        gateway = zone.gateways.find_or_initialize_by(name: label)
        if gateway.new_record?
          gateway.assign_attributes(
            kind: "rust_listen",
            status: record ? "registered" : "planned",
            node_id_hex: data["node_id"].presence,
            addresses: addresses_of(data).presence,
            host_note: data["address"].present? ? "registered from the NS (#{data['address']})" : nil
          )
          gateway.save!
        end
        app = gateway.applications.find_or_initialize_by(name: label)
        if app.new_record?
          app.backend = backend.to_s.strip.presence
          app.save!
        end
        app
      end
    end

    # The relay secret env var the Rust gateway reads for its zone (ztlp-cli.rs relay_hmac_env_var).
    def self.relay_env_var(zone) = "ZTLP_HMAC_SECRET_#{zone.name.upcase.gsub(/[^A-Z0-9]+/, '_')}"

    # The exact commands to start a gateway for a planned application (no secret values, ever).
    def self.gateway_command(app)
      zone = app.gateway.zone
      label = app.gateway.name
      relay = Array(zone.relay_addrs).first || Array(Zone.default&.relay_addrs).first || "<relay host:port>"
      backend = app.backend.presence || "<backend host:port>"
      <<~CMD
        # 1. Once, on the gateway box: create this gateway's identity (keep the file private)
        ztlp keygen --output /etc/ztlp/#{label}-gateway.json

        # 2. Run the gateway. Put the #{zone.name} relay secret in the environment from your secret
        #    store; it is never shown in this panel.
        export #{relay_env_var(zone)}=...
        ztlp listen --gateway --bind 0.0.0.0:23097 \\
          --key /etc/ztlp/#{label}-gateway.json \\
          --forward #{label}:#{backend} --service-name #{label} \\
          --zone #{zone.name} --ns-register-name #{app.ztlp_name} \\
          --ns-server #{zone.ns_addr} --relay #{relay} \\
          --policy /etc/ztlp/#{label}-policy.toml

        # 3. Save this gateway's policy from the Policies page as /etc/ztlp/#{label}-policy.toml
        #    (no file = allow everyone). The app shows as registered once the gateway is on the NS.
      CMD
    end

    def self.svc_records(zone, secret, ns_client)
      ns_client.list(Reconciler.ns_admin_port(zone), secret, type: "svc", zone: zone.name)
    end

    def self.addresses_of(data)
      list = data["addresses"].to_s.split(",").map(&:strip).reject(&:empty?)
      list.presence || [ data["address"] ].compact_blank
    end
    private_class_method :svc_records, :addresses_of
  end
end
