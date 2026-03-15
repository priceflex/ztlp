class CreateZtlpGroups < ActiveRecord::Migration[7.1]
  def change
    create_table :ztlp_groups do |t|
      t.string :name, null: false
      t.references :network, null: false, foreign_key: true
      t.text :description

      t.timestamps
    end

    add_index :ztlp_groups, [:network_id, :name], unique: true
  end
end
