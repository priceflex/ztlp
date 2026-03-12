class NetworksController < ApplicationController
  before_action :set_network, only: [:show, :edit, :update, :destroy, :deploy]

  def index
    @networks = Network.all.includes(:machines, :enrollment_tokens)
  end

  def show
    @machines = @network.machines.includes(:deployments)
    @recent_deployments = @network.deployments.recent.limit(10)
    @active_tokens = @network.enrollment_tokens.active
  end

  def new
    @network = Network.new
  end

  def create
    @network = Network.new(network_params)
    @network.enrollment_secret_ciphertext = SecureRandom.hex(32) if @network.enrollment_secret_ciphertext.blank?

    if @network.save
      AuditLog.record(action: "network_create", target: @network, details: { zone: @network.zone })
      redirect_to @network, notice: "Network '#{@network.name}' created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit
  end

  def update
    if @network.update(network_params)
      redirect_to @network, notice: "Network updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    name = @network.name
    @network.destroy
    AuditLog.record(action: "network_destroy", details: { name: name })
    redirect_to networks_path, notice: "Network '#{name}' deleted."
  end

  # POST /networks/:id/deploy - Deploy all machines
  def deploy
    errors = []
    @network.machines.each do |machine|
      machine.role_list.each do |component|
        begin
          SshProvisioner.new(machine).provision!(component)
        rescue SshProvisioner::ProvisionError => e
          errors << "#{machine.hostname}/#{component}: #{e.message}"
        end
      end
    end

    if errors.empty?
      @network.update!(status: "active")
      redirect_to @network, notice: "All components deployed successfully!"
    else
      @network.update!(status: "error")
      redirect_to @network, alert: "Some deployments failed: #{errors.join('; ')}"
    end
  end

  private

  def set_network
    @network = Network.find(params[:id])
  end

  def network_params
    params.require(:network).permit(:name, :zone, :notes)
  end
end
