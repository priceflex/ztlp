# frozen_string_literal: true

class CreateNotificationLogs < ActiveRecord::Migration[7.1]
  def change
    create_table :notification_logs do |t|
      t.integer :notification_channel_id, null: false
      t.string :event_type, null: false
      t.string :subject
      t.text :body
      t.string :status, null: false, default: "pending"
      t.text :error_message
      t.datetime :sent_at
      t.datetime :created_at, null: false
    end

    add_index :notification_logs, [:notification_channel_id, :created_at]
    add_index :notification_logs, :status
  end
end
