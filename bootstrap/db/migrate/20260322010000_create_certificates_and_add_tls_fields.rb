# frozen_string_literal: true

class CreateCertificatesAndAddTlsFields < ActiveRecord::Migration[7.1]
  def change
    create_table :certificates do |t|
      t.references :network, null: false, foreign_key: true
      t.string :hostname, null: false
      t.string :serial, null: false
      t.string :subject
      t.string :issuer
      t.string :status, default: "active", null: false
      t.string :assurance_level, default: "software"
      t.string :key_source
      t.datetime :issued_at, null: false
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.string :revocation_reason
      t.text :pem_data
      t.text :notes

      t.timestamps
    end

    add_index :certificates, :serial, unique: true
    add_index :certificates, [:network_id, :hostname]
    add_index :certificates, :status
    add_index :certificates, :expires_at

    # Add assurance_level to ztlp_devices
    add_column :ztlp_devices, :assurance_level, :string, default: "software"
    add_column :ztlp_devices, :cert_serial, :string
    add_column :ztlp_devices, :cert_expires_at, :datetime

    # Add TLS auth fields to policies
    add_column :policies, :auth_mode, :string, default: "passthrough"
    add_column :policies, :min_assurance, :string
  end
end
