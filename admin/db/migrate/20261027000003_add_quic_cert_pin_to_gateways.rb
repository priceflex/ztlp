# frozen_string_literal: true

# The gateway's QUIC certificate pin as published in its own SVC record (`quic_cert_sha256`), read by
# Check now / GatewayStatusJob. Public values. `quic_cert_status`: verified (signed by the zone's NS key),
# unverified (zone has no NS key; taken from the admin API), untrusted (the signed record did not verify),
# none (the record carries no pin). The previous pin is kept when it changes, which is what explains a
# client's "certificate does not match the pinned value".
class AddQuicCertPinToGateways < ActiveRecord::Migration[7.1]
  def change
    change_table :gateways, bulk: true do |t|
      t.string :quic_cert_sha256, limit: 64
      t.boolean :quic_cert_verified, null: false, default: false
      t.string :quic_cert_status, limit: 16
      t.datetime :quic_cert_seen_at
      t.string :quic_cert_previous_sha256, limit: 64
      t.datetime :quic_cert_changed_at
    end
  end
end
