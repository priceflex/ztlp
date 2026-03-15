class CreateZtlpUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :ztlp_users do |t|
      t.string :name, null: false
      t.references :network, null: false, foreign_key: true
      t.text :pubkey
      t.string :email
      t.string :role, null: false, default: "user"
      t.string :status, null: false, default: "active"
      t.datetime :revoked_at
      t.string :revocation_reason

      t.timestamps
    end

    add_index :ztlp_users, [:network_id, :name], unique: true
  end
end
