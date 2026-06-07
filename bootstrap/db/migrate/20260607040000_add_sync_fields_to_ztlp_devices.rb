# frozen_string_literal: true

class AddSyncFieldsToZtlpDevices < ActiveRecord::Migration[7.1]
  def change
    add_column :ztlp_devices, :origin, :string, null: false, default: "bootstrap"
    add_column :ztlp_devices, :last_synced_at, :datetime
    add_index  :ztlp_devices, :origin
  end
end
