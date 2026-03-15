class CreateIdentityProviders < ActiveRecord::Migration[7.1]
  def change
    create_table :identity_providers do |t|
      t.references :network, null: false, foreign_key: true
      t.string :name, null: false
      t.string :provider_type, null: false
      t.string :client_id, null: false
      t.text :client_secret_ciphertext
      t.string :issuer_url
      t.string :allowed_domains
      t.boolean :auto_create_users, default: false, null: false
      t.string :role_default, default: "user", null: false
      t.boolean :enabled, default: true, null: false
      t.timestamps
    end

    add_index :identity_providers, [:network_id, :provider_type], name: "index_identity_providers_on_network_and_type"
  end
end
