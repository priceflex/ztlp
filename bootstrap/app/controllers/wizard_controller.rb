# frozen_string_literal: true

# Multi-step setup wizard for creating a network, adding machines,
# reviewing the configuration, and triggering a live deploy.
class WizardController < ApplicationController
  before_action :load_wizard_network, only: [:machines, :add_machine, :remove_machine, :review, :deploy, :start_deploy]

  # Step 1: Create Network
  def new
    @network = Network.new
  end

  # Step 1: Submit network
  def create_network
    @network = Network.new(network_params)
    @network.enrollment_secret_ciphertext = SecureRandom.hex(32)

    if @network.save
      AuditLog.record(action: "network_create", target: @network, details: { zone: @network.zone, via: "wizard" })
      session[:wizard_network_id] = @network.id
      redirect_to wizard_machines_path
    else
      render :new, status: :unprocessable_entity
    end
  end

  # Step 2: Add Machines
  def machines
    @machines = @network.machines.to_a
    @new_machine = @network.machines.new(ssh_port: 22, ssh_user: "root", ssh_auth_method: "key")
  end

  # Step 2: Add a machine (Turbo Stream or redirect)
  def add_machine
    @machine = @network.machines.new(machine_params)

    if @machine.save
      AuditLog.record(action: "machine_add", target: @machine, details: {
        hostname: @machine.hostname, ip: @machine.ip_address, roles: @machine.roles, via: "wizard"
      })

      respond_to do |format|
        format.turbo_stream do
          @machines = @network.machines.reload.to_a
          @new_machine = @network.machines.new(ssh_port: 22, ssh_user: "root", ssh_auth_method: "key")
          render turbo_stream: [
            turbo_stream.replace("machine-list", partial: "wizard/machine_list", locals: { machines: @machines, network: @network }),
            turbo_stream.replace("new-machine-form", partial: "wizard/machine_form", locals: { machine: @new_machine, network: @network }),
            turbo_stream.replace("wizard-nav", partial: "wizard/machine_nav", locals: { machines: @machines })
          ]
        end
        format.html { redirect_to wizard_machines_path, notice: "Machine '#{@machine.hostname}' added." }
      end
    else
      @new_machine = @machine
      @machines = @network.machines.reload.to_a
      respond_to do |format|
        format.turbo_stream do
          render turbo_stream: turbo_stream.replace("new-machine-form",
            partial: "wizard/machine_form", locals: { machine: @new_machine, network: @network })
        end
        format.html { render :machines, status: :unprocessable_entity }
      end
    end
  end

  # Step 2: Remove a machine
  def remove_machine
    machine = @network.machines.find(params[:machine_id])
    hostname = machine.hostname
    machine.destroy

    respond_to do |format|
      format.turbo_stream do
        @machines = @network.machines.reload.to_a
        render turbo_stream: [
          turbo_stream.replace("machine-list", partial: "wizard/machine_list", locals: { machines: @machines, network: @network }),
          turbo_stream.replace("wizard-nav", partial: "wizard/machine_nav", locals: { machines: @machines })
        ]
      end
      format.html { redirect_to wizard_machines_path, notice: "Machine '#{hostname}' removed." }
    end
  end

  # Step 3: Review & Deploy
  def review
    @machines = @network.machines.includes(:deployments).to_a
    @role_counts = @network.machine_count_by_role
  end

  # Step 4: Live Deploy
  def deploy
    @machines = @network.machines.includes(:deployments).to_a
  end

  # Step 4: Kick off deployment (POST)
  def start_deploy
    @network.update!(status: "deploying")

    # Create pending deployments for each machine/component
    @network.machines.each do |machine|
      machine.role_list.each do |component|
        machine.deployments.create!(
          component: component,
          status: "pending",
          docker_image: "#{SshProvisioner::DOCKER_IMAGES[component]}:latest"
        )
      end
    end

    # Enqueue the background job
    DeployAllJob.perform_later(@network.id)

    respond_to do |format|
      format.turbo_stream do
        @machines = @network.machines.reload.includes(:deployments).to_a
        render turbo_stream: turbo_stream.replace("deploy-area",
          partial: "wizard/deploy_live", locals: { network: @network, machines: @machines })
      end
      format.html { redirect_to wizard_deploy_path }
    end
  end

  # Auto-suggest zone from network name
  def suggest_zone
    name = params[:name].to_s.strip.downcase
    zone = name.gsub(/[^a-z0-9\-]/, "-").gsub(/-+/, "-").gsub(/^-|-$/, "")
    zone = "#{zone}.ztlp" unless zone.empty?
    render json: { zone: zone }
  end

  private

  def load_wizard_network
    @network = Network.find_by(id: session[:wizard_network_id])
    unless @network
      redirect_to wizard_new_path, alert: "Please create a network first."
    end
  end

  def network_params
    params.require(:network).permit(:name, :zone, :notes)
  end

  def machine_params
    params.require(:machine).permit(
      :hostname, :ip_address, :ssh_port, :ssh_user,
      :ssh_auth_method, :ssh_private_key_ciphertext, :ssh_password_ciphertext,
      :roles
    )
  end
end
