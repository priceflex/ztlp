class CreateZtlpDevices < ActiveRecord::Migration[7.1]
  def change
    create_table :ztlp_devices do |t|
      t.string :name, null: false
      t.references :network, null: false, foreign_key: true
      t.references :ztlp_user, null: true, foreign_key: true
      t.references :machine, null: true, foreign_key: true
      t.string :node_id
      t.text :pubkey
      t.string :hardware_id
      t.string :status, null: false, default: "enrolled"
      t.datetime :enrolled_at
      t.datetime :revoked_at
      t.string :revocation_reason

      t.timestamps
    end

    add_index :ztlp_devices, [:network_id, :name], unique: true
  end
end
