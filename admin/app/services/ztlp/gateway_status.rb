# frozen_string_literal: true

module Ztlp
  # Is the gateway on the name server? (slice 5: "Check now" + GatewayStatusJob). A gateway
  # publishes its own SVC record; finding it means online. A gateway that was online/registered and
  # has disappeared goes stale; a planned one stays planned until its first SVC shows up.
  class GatewayStatus
    def self.check!(gateway, ns_client: NsClient)
      record = ServiceRegistrar.lookup(gateway.ns_name, gateway.zone, ns_client: ns_client)
      return :not_configured if record == :not_configured

      if record
        data = record[:data] || {}
        gateway.update!(status: "online", last_svc_seen_at: Time.current,
                        node_id_hex: data["node_id"].presence || gateway.node_id_hex,
                        addresses: ServiceRegistrar.addresses_of(data).presence || gateway.addresses)
        record_pin!(gateway, data, ns_client)
        :online
      else
        gateway.update!(status: "stale") if %w[online registered].include?(gateway.status)
        :not_found
      end
    end

    PIN = /\A\h{64}\z/
    NS_ERRORS = [ NsClient::NsError, SystemCallError, IOError, Timeout::Error, SocketError ].freeze

    # The QUIC cert pin clients will trust. With the zone's NS key, read it from the SVC record the name
    # server SIGNED (what v0.5 clients verify); without one, from the admin-API record, marked unverified.
    # A transport error leaves what is stored alone.
    def self.record_pin!(gateway, admin_data, ns_client)
      zone = gateway.zone
      if zone.ns_pubkey_hex.present?
        begin
          rec = ns_client.query_verified(zone.ns_addr, 3, name: gateway.ns_name, type: "svc",
                                                         trusted_keys: [ zone.ns_pubkey_hex ])
          pin = rec.is_a?(Hash) ? (rec[:data] || {})["quic_cert_sha256"] : nil
          store_pin!(gateway, pin, signed: true)
        rescue NsClient::UntrustedAnswer => e
          Rails.logger.warn("gateway_status #{gateway.ns_name}: SVC did not verify (#{e.message})")
          gateway.update!(quic_cert_sha256: nil, quic_cert_verified: false, quic_cert_status: "untrusted",
                          quic_cert_seen_at: Time.current)
        rescue *NS_ERRORS => e
          Rails.logger.warn("gateway_status #{gateway.ns_name}: signed SVC lookup failed (#{e.class})")
        end
      else
        store_pin!(gateway, admin_data["quic_cert_sha256"], signed: false)
      end
    end

    def self.store_pin!(gateway, raw, signed:)
      pin = raw.to_s.strip.downcase
      pin = nil unless pin.match?(PIN)
      attrs = { quic_cert_sha256: pin, quic_cert_verified: signed && pin.present?,
                quic_cert_status: if pin.nil? then "none" elsif signed then "verified" else "unverified" end,
                quic_cert_seen_at: Time.current }
      old = gateway.quic_cert_sha256
      if pin && old.present? && old != pin
        attrs[:quic_cert_previous_sha256] = old
        attrs[:quic_cert_changed_at] = Time.current
      end
      gateway.update!(attrs)
    end
    private_class_method :record_pin!, :store_pin!
  end
end
