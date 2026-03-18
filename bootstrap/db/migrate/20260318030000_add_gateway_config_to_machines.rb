class AddGatewayConfigToMachines < ActiveRecord::Migration[7.1]
  def change
    add_column :machines, :gateway_backends, :text
    add_column :machines, :gateway_policies, :text
  end
end
