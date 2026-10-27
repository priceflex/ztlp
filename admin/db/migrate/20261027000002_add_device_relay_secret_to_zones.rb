# frozen_string_literal: true

# The relay secret DEVICES sign CLIENT_ROUTE with, carried in enrollment tokens (flag 0x08). Separate
# from relay_secret_ct (the per-zone ZTLP_HMAC_SECRET_<ZONE> a gateway registers with): the relay keys
# client routes on the gateway's service name, so a device secret must be one the relay accepts for
# every service it dials (in practice its legacy registration secret). Encrypted at rest.
class AddDeviceRelaySecretToZones < ActiveRecord::Migration[7.1]
  def change
    add_column :zones, :device_relay_secret_ct, :text
  end
end
