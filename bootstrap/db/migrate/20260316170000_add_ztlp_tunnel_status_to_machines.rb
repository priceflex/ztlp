class AddZtlpTunnelStatusToMachines < ActiveRecord::Migration[7.1]
  def change
    add_column :machines, :ztlp_tunnel_reachable, :boolean, default: false
    add_column :machines, :ztlp_tunnel_latency_ms, :integer
    add_column :machines, :ztlp_tunnel_error, :string
    add_column :machines, :ztlp_tunnel_checked_at, :datetime
  end
end
