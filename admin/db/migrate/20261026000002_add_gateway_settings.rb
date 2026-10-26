# frozen_string_literal: true

# Every `ztlp listen` parameter the Add Service form sets (PLAN-services-wizard-and-helpdesk.md
# slice 4). NULL ns_server / relay_addr / image_tag = the zone's (or deployment's) default.
# policy_file NULL = unknown (gateways adopted from the name server: the panel can't see their flags).
class AddGatewaySettings < ActiveRecord::Migration[7.1]
  def change
    change_table :gateways, bulk: true do |t|
      t.integer :bind_port, null: false, default: 23_097
      t.integer :max_sessions, null: false, default: 100
      t.boolean :punch, null: false, default: true
      t.boolean :inject_headers, null: false, default: false
      t.text :header_secret_ct # encrypts
      t.text :subject_map      # JSON array of "<noise pubkey hex>=<subject>"
      t.boolean :policy_file
      t.string :ns_server
      t.string :relay_addr
      t.string :image_tag
    end
  end
end
