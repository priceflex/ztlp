# frozen_string_literal: true

class CreateDeviceHeartbeats < ActiveRecord::Migration[7.1]
  def change
    create_table :device_heartbeats do |t|
      t.integer :ztlp_device_id, null: false
      t.integer :network_id, null: false
      t.string :source_ip
      t.integer :source_port
      t.string :relay_name
      t.integer :latency_ms
      t.integer :bytes_sent, default: 0
      t.integer :bytes_received, default: 0
      t.integer :active_streams, default: 0
      t.string :client_version
      t.string :os_info
      t.datetime :created_at, null: false
    end

    add_index :device_heartbeats, [:ztlp_device_id, :created_at]
    add_index :device_heartbeats, [:network_id, :created_at]
  end
end
