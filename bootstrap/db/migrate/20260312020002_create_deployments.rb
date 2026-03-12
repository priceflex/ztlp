class CreateDeployments < ActiveRecord::Migration[7.1]
  def change
    create_table :deployments do |t|
      t.references :machine, null: false, foreign_key: true
      t.string :status, null: false, default: "pending" # pending, running, success, failed
      t.string :component, null: false          # ns, relay, gateway
      t.text :log                               # full deploy log
      t.text :config_generated                  # the config file written to remote
      t.string :docker_image                    # image:tag used
      t.string :container_id                    # docker container ID on remote
      t.datetime :started_at
      t.datetime :finished_at

      t.timestamps
    end

    add_index :deployments, [:machine_id, :component]
    add_index :deployments, :status
  end
end
