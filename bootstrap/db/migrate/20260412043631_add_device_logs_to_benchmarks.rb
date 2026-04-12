class AddDeviceLogsToBenchmarks < ActiveRecord::Migration[7.1]
  def change
    add_column :benchmarks, :device_logs, :text
  end
end
