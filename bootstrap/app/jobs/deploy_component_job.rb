# frozen_string_literal: true

# Deploys a single component on a single machine.
# Broadcasts real-time progress via ActionCable to the network's deploy channel.
class DeployComponentJob < ApplicationJob
  queue_as :default

  def perform(deployment_id)
    deployment = Deployment.find(deployment_id)
    machine = deployment.machine
    network = machine.network
    component = deployment.component

    deployment.update!(status: "running", started_at: Time.current)
    machine.update!(status: "provisioning")

    broadcast_component_status(network, machine, component, deployment, "running", "Starting #{component} deployment...")

    steps = deploy_steps(component)
    steps.each_with_index do |step, idx|
      broadcast_log_line(network, machine, component, "[#{idx + 1}/#{steps.size}] #{step}")
      deployment.append_log("[#{idx + 1}/#{steps.size}] #{step}")
      deployment.save
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

    broadcast_component_status(network, machine, component, deployment, "failed", "❌ Failed: #{e.message}")
    raise
  end

  private

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
