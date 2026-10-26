# frozen_string_literal: true

# "Applications" are called Services everywhere now (PLAN-services-wizard-and-helpdesk.md, slice 2):
# the gateway flag is --forward <service>, the NS record is SVC, the policy file says [[services]].
class RenameApplicationsToServices < ActiveRecord::Migration[7.1]
  def up
    rename_table :applications, :services
    rename_index :services, "idx_applications_gw_name", "idx_services_gw_name"
    rename_column :policy_rules, :application_id, :service_id
    rename_index :policy_rules, "idx_policy_rules_app", "idx_policy_rules_service"
    # Old audit rows point at the old class name; keep them resolvable.
    execute "UPDATE audit_logs SET target_type = 'Service' WHERE target_type = 'Application'"
  end

  def down
    execute "UPDATE audit_logs SET target_type = 'Application' WHERE target_type = 'Service'"
    rename_index :policy_rules, "idx_policy_rules_service", "idx_policy_rules_app"
    rename_column :policy_rules, :service_id, :application_id
    rename_index :services, "idx_services_gw_name", "idx_applications_gw_name"
    rename_table :services, :applications
  end
end
