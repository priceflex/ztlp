class CreateAlerts < ActiveRecord::Migration[7.1]
  def change
    create_table :alerts do |t|
      t.references :network, null: false, foreign_key: true
      t.references :machine, null: false, foreign_key: true
      t.string :component, null: false
      t.string :severity, null: false, default: "warning"
      t.text :message, null: false
      t.boolean :acknowledged, null: false, default: false
      t.datetime :acknowledged_at
      t.datetime :resolved_at

      t.timestamps
    end

    add_index :alerts, :severity
    add_index :alerts, :acknowledged
    add_index :alerts, [:machine_id, :component]
    add_index :alerts, :resolved_at
  end
end
