class AddReplayRejectCountToBenchmarks < ActiveRecord::Migration[7.1]
  def change
    add_column :benchmarks, :replay_reject_count, :integer
  end
end
