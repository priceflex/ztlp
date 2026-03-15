class CreateGroupMemberships < ActiveRecord::Migration[7.1]
  def change
    create_table :group_memberships do |t|
      t.references :ztlp_group, null: false, foreign_key: true
      t.references :ztlp_user, null: false, foreign_key: true

      t.timestamps
    end

    add_index :group_memberships, [:ztlp_group_id, :ztlp_user_id], unique: true
  end
end
