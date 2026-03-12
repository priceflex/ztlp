class CreateHealthChecks < ActiveRecord::Migration[7.1]
  def change
    create_table :health_checks do |t|
      t.references :machine, null: false, foreign_key: true
      t.string :component, null: false
      t.string :status, null: false, default: "unknown"
      t.text :metrics
      t.string :container_state
      t.text :error_message
      t.integer :response_time_ms
      t.datetime :checked_at, null: false

      t.timestamps
    end

    add_index :health_checks, [:machine_id, :component]
    add_index :health_checks, :status
    add_index :health_checks, :checked_at
    add_index :health_checks, [:machine_id, :component, :checked_at], name: "index_health_checks_on_machine_component_time"
  end
end
