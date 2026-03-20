# frozen_string_literal: true

class CreatePolicyTemplates < ActiveRecord::Migration[7.1]
  def change
    create_table :policy_templates do |t|
      t.string :name, null: false
      t.text :description
      t.string :category, null: false     # "employee", "contractor", "guest", "security"
      t.text :rules_json, null: false     # JSON array of policy rules
      t.boolean :built_in, default: false

      t.timestamps
    end
  end
end
