class NetworksController < ApplicationController
  before_action :set_network, only: [:show, :edit, :update, :destroy, :deploy, :register_ns, :run_health_check]

  def index
    @networks = Network.all.includes(:machines, :enrollment_tokens)
  end

  def show
    @machines = @network.machines.includes(:deployments)
    @recent_deployments = @network.deployments.recent.limit(10)
    @active_tokens = @network.enrollment_tokens.active
    @relays = @network.machines.with_role("relay")
    @ns_machines = @network.machines.with_role("ns")
    @gateways = @network.machines.with_role("gateway")
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

  # POST /networks/:id/register_ns — Register Bootstrap with the NS
  def register_ns
    registrar = NsRegistrar.new(@network)
    result = registrar.register!
    AuditLog.record(
      action: "ns_register_bootstrap",
      target: @network,
      details: { name: result[:name], addr: result[:addr], ns: result[:ns] }
    )
    redirect_to @network, notice: "Registered #{result[:name]} → #{result[:addr]} with NS"
  rescue NsRegistrar::RegistrationError => e
    redirect_to @network, alert: "NS registration failed: #{e.message}"
  end

  # POST /networks/:id/run_health_check — Run health checks on all machines
  def run_health_check
    results = []
    errors = []
    @network.machines.each do |machine|
      next unless machine.role_list.any?
      begin
        checker = HealthChecker.new(machine)
        results.concat(checker.check_all)
      rescue StandardError => e
        errors << "#{machine.hostname}: #{e.message}"
      end
    end

    healthy = results.count { |r| r.status == "healthy" }
    total = results.count
    msg = "Health check complete: #{healthy}/#{total} healthy"
    msg += ". Errors: #{errors.join('; ')}" if errors.any?

    redirect_to @network, notice: msg
  end

  private

  def set_network
    @network = Network.find(params[:id])
  end

  def network_params
    params.require(:network).permit(:name, :zone, :notes)
  end
end
