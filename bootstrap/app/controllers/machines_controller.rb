class MachinesController < ApplicationController
  before_action :set_network
  before_action :set_machine, only: [:show, :edit, :update, :destroy, :provision, :test_connection, :health_check]

  def index
    @machines = @network.machines.includes(:deployments)
  end

  def show
    @deployments = @machine.deployments.recent.limit(20)
  end

  def new
    @machine = @network.machines.new(ssh_port: 22, ssh_user: "root", ssh_auth_method: "key")
  end

  def create
    @machine = @network.machines.new(machine_params)

    if @machine.save
      AuditLog.record(action: "machine_add", target: @machine, details: {
        hostname: @machine.hostname, ip: @machine.ip_address, roles: @machine.roles
      })
      redirect_to network_machine_path(@network, @machine), notice: "Machine '#{@machine.hostname}' added."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @machine.update(machine_params)
      redirect_to network_machine_path(@network, @machine), notice: "Machine updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    hostname = @machine.hostname
    @machine.destroy
    redirect_to network_machines_path(@network), notice: "Machine '#{hostname}' removed."
  end

  # POST /networks/:network_id/machines/:id/provision
  def provision
    component = params[:component]
    unless Machine::VALID_ROLES.include?(component)
      redirect_to network_machine_path(@network, @machine), alert: "Invalid component: #{component}"
      return
    end

    begin
      provisioner = SshProvisioner.new(@machine)
      provisioner.provision!(component)
      redirect_to network_machine_path(@network, @machine), notice: "#{component} deployed successfully!"
    rescue SshProvisioner::ProvisionError => e
      redirect_to network_machine_path(@network, @machine), alert: "Deploy failed: #{e.message}"
    end
  end

  # POST /networks/:network_id/machines/:id/test_connection
  def test_connection
    begin
      SshProvisioner.new(@machine).test_connection!
      redirect_to network_machine_path(@network, @machine), notice: "SSH connection successful!"
    rescue SshProvisioner::ProvisionError => e
      redirect_to network_machine_path(@network, @machine), alert: e.message
    end
  end

  # POST /networks/:network_id/machines/:id/health_check
  def health_check
    checker = HealthChecker.new(@machine)
    @results = checker.check_all

    if @results.all?(&:healthy)
      redirect_to network_machine_path(@network, @machine), notice: "All components healthy!"
    else
      unhealthy = @results.reject(&:healthy).map { |r| "#{r.component}: #{r.details}" }
      redirect_to network_machine_path(@network, @machine), alert: "Issues found: #{unhealthy.join('; ')}"
    end
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_machine
    @machine = @network.machines.find(params[:id])
  end

  def machine_params
    params.require(:machine).permit(
      :hostname, :ip_address, :ssh_port, :ssh_user,
      :ssh_auth_method, :ssh_private_key_ciphertext, :ssh_password_ciphertext,
      :roles, :notes
    )
  end
end
