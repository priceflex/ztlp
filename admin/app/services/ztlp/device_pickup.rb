# frozen_string_literal: true

module Ztlp
  # Finds enrolled devices on the name server (docs/admin-panel/PLAN-enrollment-token-trust.md).
  #
  # `ztlp setup` with a binary token enrolls straight against the NS and never calls the panel back
  # (the client only confirms query-param tokens), so the panel looks for the device itself: the
  # NS writes KEY "<device>.<zone>" at enrollment, carrying the device's node id and public key.
  #
  #   check(enrollment)          pending token -> device row (enrolled) + token redeemed, once the KEY
  #                              exists and is newer than the token
  #   adopt!(zone, user, name)   list a device that is ALREADY enrolled (e.g. with a CLI token) under a
  #                              user, from its existing KEY record: no re-key, nothing published
  #
  # Read-only toward the NS: a plain KEY query, no secrets needed.
  module DevicePickup
    class NotFound < StandardError; end

    NS_TIMEOUT = 3
    # A KEY record a little older than the token is still this redemption (clock skew between the
    # panel and the NS); anything older is an earlier enrollment of the same name.
    CLOCK_SKEW = 120
    NS_ERRORS = [ Ztlp::NsClient::NsError, SystemCallError, IOError, Timeout::Error, SocketError ].freeze

    def self.check(enrollment, ns_client: NsClient)
      return :not_pending unless enrollment.pending? && !enrollment.expired?
      return :no_device_name if enrollment.device_name.blank?

      zone = enrollment.zone
      rec = lookup_key(zone, enrollment.device_name, ns_client)
      return :pending unless rec
      return :stale_key if rec[:created_at].to_i < enrollment.created_at.to_i - CLOCK_SKEW

      Enrollment.transaction do
        device = upsert_device!(zone, enrollment.user, enrollment.device_name, rec, enrollment: enrollment)
        enrollment.update!(status: "redeemed", uses: enrollment.uses.to_i + 1, redeemed_device: device)
        AuditLog.record!("enrollment.redeem", admin: nil, target: enrollment, status: "ok",
                                              details: { code: enrollment.code, device: device.ns_name,
                                                         node_id: device.node_id_hex, via: "ns_key_lookup" })
      end
      :redeemed
    rescue *NS_ERRORS
      :ns_error
    end

    def self.adopt!(zone, user, name, ns_client: NsClient, admin: nil)
      name = name.to_s.strip
      probe = zone.devices.new(name: name)
      probe.validate
      raise ActiveRecord::RecordInvalid, probe if probe.errors[:name].any?

      rec = lookup_key(zone, name, ns_client)
      raise NotFound, "no KEY record for #{name}.#{zone.name} on the name server" unless rec

      Device.transaction do
        device = upsert_device!(zone, user, name, rec)
        AuditLog.record!("device.adopt", admin: admin, target: device, status: "ok",
                                         details: { device: device.ns_name, user: user&.username,
                                                    node_id: device.node_id_hex })
        device
      end
    end

    def self.lookup_key(zone, name, ns_client)
      rec = ns_client.query(zone.ns_addr, NS_TIMEOUT, name: "#{name}.#{zone.name}", type: "key")
      rec.is_a?(Hash) ? rec : nil
    end

    def self.upsert_device!(zone, user, name, rec, enrollment: nil)
      data = rec[:data].is_a?(Hash) ? rec[:data].transform_keys(&:to_s) : {}
      device = zone.devices.find_or_initialize_by(name: name)
      device.assign_attributes(user: user || device.user, status: "enrolled",
                               node_id_hex: data["node_id"].to_s.downcase.presence,
                               noise_pubkey_hex: data["public_key"].to_s.downcase.presence,
                               enrolled_at: Time.current, revoked_at: nil, revocation_reason: nil)
      device.enrollment_id = enrollment.id if enrollment
      device.save!
      user.update!(status: "active") if user&.status == "invited"
      device
    end
    private_class_method :lookup_key, :upsert_device!
  end
end
