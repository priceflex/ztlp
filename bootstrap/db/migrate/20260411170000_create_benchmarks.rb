# frozen_string_literal: true

class CreateBenchmarks < ActiveRecord::Migration[7.1]
  def change
    create_table :benchmarks do |t|
      t.references :ztlp_device, null: true, foreign_key: true
      t.references :network, null: false, foreign_key: true
      t.string :device_id
      t.string :node_id
      t.string :app_version
      t.string :build_tag
      t.string :device_model
      t.string :ios_version
      t.integer :ne_memory_mb
      t.integer :ne_virtual_mb
      t.boolean :ne_memory_pass
      t.integer :benchmarks_passed
      t.integer :benchmarks_total
      t.json :individual_results
      t.string :relay_address
      t.string :gateway_address
      t.string :ns_address
      t.integer :latency_ms
      t.integer :throughput_kbps
      t.integer :p99_latency_ms
      t.integer :packet_loss_pct
      t.text :error_details
      t.timestamps
    end

    add_index :benchmarks, [:network_id, :created_at]
    add_index :benchmarks, [:node_id, :created_at]
    add_index :benchmarks, :device_id
  end
end
