# frozen_string_literal: true

# When the gateway install script (which carries secrets) was first shown: it stays viewable for
# 30 minutes, then showing it again means Regenerate (rotates the header secret). Slice 5.
class AddInstallShownAtToGateways < ActiveRecord::Migration[7.1]
  def change
    add_column :gateways, :install_shown_at, :datetime
  end
end
