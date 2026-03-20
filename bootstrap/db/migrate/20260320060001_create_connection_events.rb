# frozen_string_literal: true

class CreateConnectionEvents < ActiveRecord::Migration[7.1]
  def change
    create_table :connection_events do |t|
      t.integer :ztlp_device_id, null: false
      t.integer :network_id, null: false
      t.integer :ztlp_user_id
      t.string :event_type, null: false
      t.string :source_ip
      t.string :relay_name
      t.string :disconnect_reason
      t.integer :session_duration_seconds
      t.text :details
      t.datetime :created_at, null: false
    end

    add_index :connection_events, [:network_id, :created_at]
    add_index :connection_events, [:ztlp_device_id, :created_at]
    add_index :connection_events, [:ztlp_user_id, :created_at]
  end
end
