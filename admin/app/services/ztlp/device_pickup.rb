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
  # Read-only toward the NS: a KEY query, accepted only when the zone's name server signed the answer
  # (NsClient.query_verified with zones.ns_pubkey_hex). A zone without that key cannot pick devices up:
  # an unsigned UDP answer would let anyone on the path list their own key as a user's device.
  module DevicePickup
    class NotFound < StandardError; end

    NS_TIMEOUT = 3
    # A KEY record a little older than the token is still this redemption (clock skew between the
    # panel and the NS); anything older is an earlier enrollment of the same name.
    CLOCK_SKEW = 120
    NS_ERRORS = [ Ztlp::NsClient::NsError, SystemCallError, IOError, Timeout::Error, SocketError ].freeze
    NO_NS_KEY = "set the zone's name server key first (Name server page): without it the panel cannot verify the answer"

    def self.check(enrollment, ns_client: NsClient)
      return :not_pending unless enrollment.pending? && !enrollment.expired?
      return :no_device_name if enrollment.device_name.blank? && enrollment.token_ref.blank?
      return :revoked_user if enrollment.user&.revoked?

      zone = enrollment.zone
      return :no_ns_key if zone.ns_pubkey_hex.blank?

      # The client may enroll under a different name than the one typed into the token (the
      # Windows and Mac apps append the computer's user name), so look for the KEY record carrying
      # this token's fingerprint first. Tokens minted before token_ref existed fall back to the name.
      name, rec = find_by_token_ref(zone, enrollment.token_ref, ns_client)
      via = "ns_enrollment_ref"
      if rec.nil? && enrollment.device_name.present?
        name = enrollment.device_name
        rec = lookup_key(zone, name, ns_client)
        via = "ns_key_lookup"
      end
      return :pending unless rec
      return :stale_key if rec[:created_at].to_i < enrollment.created_at.to_i - CLOCK_SKEW

      Enrollment.transaction do
        device = upsert_device!(zone, enrollment.user, name, rec, enrollment: enrollment)
        enrollment.update!(status: "redeemed", uses: enrollment.uses.to_i + 1, redeemed_device: device,
                           redeemed_at: Time.current)
        AuditLog.record!("enrollment.redeem", admin: nil, target: enrollment, status: "ok",
                                              details: { code: enrollment.code, device: device.ns_name,
                                                         node_id: device.node_id_hex, via: via })
      end
      :redeemed
    rescue Ztlp::NsClient::UntrustedAnswer => e
      Rails.logger.warn("device_pickup #{enrollment.code}: #{e.message}")
      :untrusted
    rescue *NS_ERRORS
      :ns_error
    end

    def self.adopt!(zone, user, name, ns_client: NsClient, admin: nil)
      name = name.to_s.strip
      probe = zone.devices.new(name: name)
      probe.validate
      raise ActiveRecord::RecordInvalid, probe if probe.errors[:name].any?
      raise NotFound, "#{user.display_name} is revoked; a revoked user cannot get devices" if user&.revoked?
      raise NotFound, NO_NS_KEY if zone.ns_pubkey_hex.blank?

      rec = begin
        lookup_key(zone, name, ns_client)
      rescue Ztlp::NsClient::UntrustedAnswer => e
        raise NotFound, "the name server's answer for #{name}.#{zone.name} did not verify (#{e.message})"
      end
      raise NotFound, "no KEY record for #{name}.#{zone.name} on the name server" unless rec

      Device.transaction do
        device = upsert_device!(zone, user, name, rec)
        AuditLog.record!("device.adopt", admin: admin, target: device, status: "ok",
                                         details: { device: device.ns_name, user: user&.username,
                                                    node_id: device.node_id_hex })
        device
      end
    end

    # [label, record] for the zone's KEY record whose `enrollment_ref` is this token's fingerprint,
    # or nil. Found through the NS admin API listing, then re-read with a SIGNED query (the listing is
    # only a hint) and the fingerprint checked again on the signed answer.
    def self.find_by_token_ref(zone, ref, ns_client)
      return nil if ref.blank? || zone.ns_admin_secret.blank? || !ns_client.respond_to?(:list)

      records = ns_client.list(Reconciler.ns_admin_port(zone), zone.ns_admin_secret, type: "key", zone: zone.name)
      hit = Array(records).find { |r| ref_of(r) == ref }
      return nil unless hit

      label = (hit[:name] || hit["name"]).to_s.delete_suffix(".#{zone.name}")
      return nil if label.empty? || label.include?(".")

      rec = lookup_key(zone, label, ns_client)
      rec && ref_of(rec) == ref ? [ label, rec ] : nil
    rescue *NS_ERRORS => e
      Rails.logger.warn("device_pickup: NS listing failed (#{e.class}); falling back to the device name")
      nil
    end

    def self.ref_of(rec)
      data = rec[:data] || rec["data"]
      data.is_a?(Hash) ? data.transform_keys(&:to_s)["enrollment_ref"].to_s.downcase : nil
    end

    def self.lookup_key(zone, name, ns_client)
      rec = ns_client.query_verified(zone.ns_addr, NS_TIMEOUT, name: "#{name}.#{zone.name}", type: "key",
                                                              trusted_keys: [ zone.ns_pubkey_hex ])
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
