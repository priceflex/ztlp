class CreateAuditLogs < ActiveRecord::Migration[7.1]
  def change
    create_table :audit_logs do |t|
      t.string :action, null: false             # ssh_connect, deploy, token_generate, etc.
      t.string :target_type                     # Machine, Network, etc.
      t.integer :target_id
      t.string :status, null: false, default: "success" # success, failure
      t.text :details                           # JSON blob with extra info
      t.string :ip_address                      # remote IP (SSH target or request origin)

      t.timestamps
    end

    add_index :audit_logs, [:target_type, :target_id]
    add_index :audit_logs, :action
    add_index :audit_logs, :created_at
  end
end
