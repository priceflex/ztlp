# frozen_string_literal: true

class CreateAdminUsers < ActiveRecord::Migration[7.1]
  def change
    create_table :admin_users do |t|
      t.string :email, null: false
      t.string :name, null: false
      t.string :password_digest, null: false
      t.string :role, null: false, default: "admin"
      t.string :totp_secret
      t.boolean :totp_enabled, default: false
      t.datetime :last_login_at
      t.string :last_login_ip
      t.integer :failed_login_attempts, default: 0
      t.datetime :locked_until
      t.timestamps
    end

    add_index :admin_users, :email, unique: true
  end
end
