class AddSuspendedAtToZtlpUsers < ActiveRecord::Migration[7.1]
  def change
    add_column :ztlp_users, :suspended_at, :datetime
  end
end
