# frozen_string_literal: true

class CreateNotificationChannels < ActiveRecord::Migration[7.1]
  def change
    create_table :notification_channels do |t|
      t.integer :network_id
      t.string :name, null: false
      t.string :channel_type, null: false
      t.text :config_json, null: false
      t.boolean :enabled, default: true
      t.string :severity_filter, default: "all"
      t.string :event_filter
      t.datetime :last_sent_at
      t.integer :send_count, default: 0
      t.text :last_error
      t.timestamps
    end

    add_index :notification_channels, :network_id
    add_index :notification_channels, [:channel_type, :enabled]
  end
end
