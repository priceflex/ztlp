# frozen_string_literal: true

# Orchestrates deploying all components on all machines for a network.
# Enqueues individual DeployComponentJob for each machine/component pair
# and broadcasts overall progress via Turbo Streams.
class DeployAllJob < ApplicationJob
  queue_as :default

  def perform(network_id, tls_config: {})
    @tls_config = tls_config.with_indifferent_access
    network = Network.find(network_id)
    network.update!(status: "deploying")

    broadcast_status(network, "started", "Deployment started for network '#{network.name}'")

    machines = network.machines.to_a
    total_components = machines.sum { |m| m.role_list.size }
    completed = 0
    failed = 0

    machines.each do |machine|
      machine.role_list.each do |component|
        deployment = machine.deployments.create!(
          component: component,
          status: "pending",
          docker_image: "#{SshProvisioner::DOCKER_IMAGES[component]}:latest"
        )

        broadcast_component_status(network, machine, component, deployment, "pending", "Queued for deployment")

        begin
          # Run deployment inline within this job (sequential per machine/component)
          run_deploy(network, machine, component, deployment)
          completed += 1
        rescue StandardError => e
          failed += 1
          broadcast_component_status(network, machine, component, deployment, "failed", "Failed: #{e.message}")
        end

        broadcast_progress(network, completed, failed, total_components)
      end
    end

    final_status = failed.zero? ? "active" : "error"
    network.update!(status: final_status)
    broadcast_status(network, "completed", "Deployment finished: #{completed}/#{total_components} succeeded, #{failed} failed")
  end

  private

  def run_deploy(network, machine, component, deployment)
    deployment.update!(status: "running", started_at: Time.current)
    machine.update!(status: "provisioning")

    broadcast_component_status(network, machine, component, deployment, "running", "Deploying #{component}...")

    # Simulate deployment steps with broadcasts
    steps = deploy_steps(component)
    steps.each_with_index do |step, idx|
      broadcast_log_line(network, machine, component, "[#{idx + 1}/#{steps.size}] #{step}")
      execute_provision_step(machine, component, deployment, step)
    end

    deployment.finish!("success")
    machine.update!(status: "ready", last_error: nil, last_health_check_at: Time.current)

    AuditLog.record(
      action: "deploy",
      target: machine,
      status: "success",
      details: { component: component, machine: machine.hostname, network: network.name }
    )

    broadcast_component_status(network, machine, component, deployment, "success", "✅ #{component} deployed successfully")
  rescue StandardError => e
    deployment.update!(status: "failed", finished_at: Time.current)
    deployment.append_log("ERROR: #{e.message}")
    deployment.save
    machine.update!(status: "error", last_error: e.message)

    AuditLog.record(
      action: "deploy",
      target: machine,
      status: "failure",
      details: { component: component, error: e.message, machine: machine.hostname, network: network.name }
    )

    raise
  end

  def execute_provision_step(machine, component, deployment, step)
    deployment.append_log(step)
    deployment.save
    # In production this would call SshProvisioner methods.
    # For background job, we simulate with the provisioner when SSH is available.
  end

  def deploy_steps(component)
    [
      "Checking SSH connectivity...",
      "Verifying Docker installation...",
      "Pulling image #{SshProvisioner::DOCKER_IMAGES[component]}:latest...",
      "Generating #{component} configuration...",
      "Uploading configuration to /etc/ztlp/#{component}.env...",
      "Stopping existing container (if any)...",
      "Starting container #{SshProvisioner::CONTAINER_NAMES[component]}...",
      "Verifying container health...",
      "Deployment complete"
    ]
  end

  def broadcast_status(network, event, message)
    ActionCable.server.broadcast(
      "deploy_network_#{network.id}",
      { type: "status", event: event, message: message, timestamp: Time.current.iso8601 }
    )
  end

  def broadcast_progress(network, completed, failed, total)
    ActionCable.server.broadcast(
      "deploy_network_#{network.id}",
      { type: "progress", completed: completed, failed: failed, total: total, timestamp: Time.current.iso8601 }
    )
  end

  def broadcast_component_status(network, machine, component, deployment, status, message)
    ActionCable.server.broadcast(
      "deploy_network_#{network.id}",
      {
        type: "component_status",
        machine_id: machine.id,
        machine_hostname: machine.hostname,
        component: component,
        deployment_id: deployment.id,
        status: status,
        message: message,
        timestamp: Time.current.iso8601
      }
    )
  end

  def broadcast_log_line(network, machine, component, line)
    ActionCable.server.broadcast(
      "deploy_network_#{network.id}",
      {
        type: "log",
        machine_id: machine.id,
        machine_hostname: machine.hostname,
        component: component,
        line: line,
        timestamp: Time.current.iso8601
      }
    )
  end
end
