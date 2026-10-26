# frozen_string_literal: true

# The home name server's Ed25519 PUBLIC key (64 hex). Minted into enrollment tokens as flag 0x10 so
# enrolled devices verify NS answers (and take the gateway cert pin from the signed SVC record)
# instead of trusting first-use pins. Public value: not encrypted.
class AddNsPubkeyHexToZones < ActiveRecord::Migration[7.1]
  def change
    add_column :zones, :ns_pubkey_hex, :string, limit: 64
  end
end
