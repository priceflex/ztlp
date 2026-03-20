# frozen_string_literal: true

class AddOnlineStatusToZtlpDevices < ActiveRecord::Migration[7.1]
  def change
    add_column :ztlp_devices, :last_seen_at, :datetime
    add_column :ztlp_devices, :last_source_ip, :string
    add_column :ztlp_devices, :last_relay, :string
    add_column :ztlp_devices, :client_version, :string
    add_column :ztlp_devices, :os_info, :string
    add_index :ztlp_devices, :last_seen_at
  end
end
