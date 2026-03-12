class CreateMachines < ActiveRecord::Migration[7.1]
  def change
    create_table :machines do |t|
      t.references :network, null: false, foreign_key: true
      t.string :hostname, null: false
      t.string :ip_address, null: false
      t.integer :ssh_port, null: false, default: 22
      t.string :ssh_user, null: false, default: "root"
      t.text :ssh_private_key_ciphertext       # encrypted SSH private key
      t.string :ssh_auth_method, null: false, default: "key" # key, password, agent
      t.text :ssh_password_ciphertext           # encrypted password (if password auth)
      t.string :roles, null: false, default: "" # comma-separated: ns, relay, gateway
      t.string :status, null: false, default: "pending" # pending, provisioning, ready, error, offline
      t.text :last_error
      t.datetime :last_health_check_at
      t.boolean :docker_installed, null: false, default: false

      t.timestamps
    end

    add_index :machines, [:network_id, :hostname], unique: true
    add_index :machines, [:network_id, :ip_address], unique: true
  end
end
