class CreateNetworks < ActiveRecord::Migration[7.1]
  def change
    create_table :networks do |t|
      t.string :name, null: false
      t.string :zone, null: false             # e.g. "office.acme.ztlp"
      t.text :enrollment_secret_ciphertext     # encrypted 32-byte hex secret
      t.text :zone_key_ciphertext              # encrypted Ed25519 zone signing key
      t.string :status, null: false, default: "created" # created, deploying, active, error
      t.text :notes

      t.timestamps
    end

    add_index :networks, :zone, unique: true
    add_index :networks, :name, unique: true
  end
end
