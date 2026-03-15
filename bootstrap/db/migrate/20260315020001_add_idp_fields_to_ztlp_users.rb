class AddIdpFieldsToZtlpUsers < ActiveRecord::Migration[7.1]
  def change
    add_column :ztlp_users, :external_id, :string
    add_column :ztlp_users, :idp_issuer, :string
    add_column :ztlp_users, :last_login_at, :datetime

    add_index :ztlp_users, [:network_id, :external_id, :idp_issuer],
              name: "index_ztlp_users_on_network_external_idp",
              unique: true,
              where: "external_id IS NOT NULL"
  end
end
