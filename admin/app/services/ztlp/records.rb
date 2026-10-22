# frozen_string_literal: true

module Ztlp
  # Maps panel rows → NS record data.
  #
  # THE PII BOUNDARY (spec §3, decision 10): this module is the single place
  # that decides what leaves the panel DB for the name server. It MUST NOT
  # include display_name, email (non-empty), phone, first_name, last_name,
  # attributes or notes. The NS is the authentication authority (Service A);
  # PII lives only in the panel DB (Service B).
  #
  # Record shapes follow spec §6.3 and `ns/lib/ztlp_ns/record.ex`:
  #   USER   0x11  {public_key, role, devices:[ns names], email:""}
  #   GROUP  0x12  {members:[user ns names], description:""}
  #   DEVICE 0x10  {node_id, public_key, owner:<user ns name>, assurance, key_source}
  #   REVOKE 0x05  {revoked_ids:[name], reason, effective_at:"now"}
  class Records
    class Error < StandardError; end

    # USER record (type 0x11). `email` is always "" — the NS USER record
    # schema allows the field but the panel writes it empty (G7, spec §3).
    def self.user_data(user)
      raise Error, "user has no ns_name" if user.ns_name.nil?

      {
        "public_key" => user.signing_pubkey_hex.to_s,
        "role" => user.role.to_s,
        "devices" => user.devices.order(:name).map(&:ns_name),
        "email" => ""
      }
    end

    # GROUP record (type 0x12). `description` is always "" — panel-only.
    def self.group_data(group)
      raise Error, "group has no ns_name" if group.ns_name.nil?

      {
        "members" => group.users.order(:username).map(&:ns_name),
        "description" => ""
      }
    end

    # DEVICE record (type 0x10). `assurance` is the wire value
    # ("hardware|device-bound|software|unknown"), never the display label.
    def self.device_data(device)
      owner = device.user
      {
        "node_id" => device.node_id_hex.to_s,
        "public_key" => device.noise_pubkey_hex.to_s,
        "owner" => owner ? owner.ns_name : "",
        "assurance" => Assurance.wire(device.assurance),
        "key_source" => device.key_source.to_s
      }
    end

    # Zone authority KEY record data (type 0x01). Self-registration is
    # permitted when public_key == signer (registration_auth.ex:290-298).
    def self.authority_data(zone)
      raise Error, "zone has no authority seed" unless zone.authority_configured?

      pubkey = OpenSSL::PKey.new_raw_private_key(
        "ED25519", [ zone.authority_seed_ct ].pack("H*")
      ).raw_public_key.unpack1("H*")

      {
        "algorithm" => "Ed25519",
        "node_id" => "zone:#{zone.name}",
        "public_key" => pubkey,
        "delegation" => true,
        "role" => "zone-authority"
      }
    end

    # REVOKE record data (type 0x05). TTL 0 — never expires.
    def self.revoke_data(name, reason)
      {
        "revoked_ids" => [ name ],
        "reason" => reason.to_s,
        "effective_at" => "now"
      }
    end
  end
end
