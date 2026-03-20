# frozen_string_literal: true

class PoliciesController < ApplicationController
  before_action :set_network
  before_action :set_policy, only: [:show, :edit, :update, :destroy, :toggle, :duplicate]
  before_action :require_write_access, only: [:new, :create, :edit, :update, :destroy, :toggle, :duplicate, :apply_template]

  def index
    @policies = @network.policies.order(:policy_type, :name)

    # Filters
    @policies = @policies.by_type(params[:type]) if params[:type].present?
    @policies = @policies.where(enabled: params[:status] == "enabled") if params[:status].present?
    @policies = @policies.where(action: params[:action_filter]) if params[:action_filter].present?
    @policies = @policies.search(params[:search]) if params[:search].present?

    @grouped_policies = @policies.group_by(&:policy_type)
  end

  def show
    @effective_users = @policy.effective_users.limit(20)
    @conflicts = @policy.conflicting_policies
    @audit_logs = AuditLog.for_target("Policy", @policy.id).recent.limit(10)
  end

  def new
    @policy = @network.policies.new(
      policy_type: params[:policy_type] || "access",
      priority: "normal",
      action: "allow",
      timezone: "UTC"
    )
    load_form_data
  end

  def create
    @policy = @network.policies.new(policy_params)

    if @policy.save
      AuditLog.record(
        action: "policy_create",
        target: @policy,
        details: { name: @policy.name, network: @network.name, policy_type: @policy.policy_type }
      )

      if @policy.has_conflicts?
        redirect_to network_policy_path(@network, @policy),
          notice: "Policy '#{@policy.name}' created. ⚠️ Warning: conflicting policies detected."
      else
        redirect_to network_policy_path(@network, @policy),
          notice: "Policy '#{@policy.name}' created."
      end
    else
      load_form_data
      render :new, status: :unprocessable_entity
    end
  end

  def edit
    load_form_data
  end

  def update
    if @policy.update(policy_params)
      AuditLog.record(
        action: "policy_update",
        target: @policy,
        details: { name: @policy.name, network: @network.name }
      )
      redirect_to network_policy_path(@network, @policy), notice: "Policy '#{@policy.name}' updated."
    else
      load_form_data
      render :edit, status: :unprocessable_entity
    end
  end

  def destroy
    name = @policy.name
    @policy.destroy
    AuditLog.record(
      action: "policy_destroy",
      details: { name: name, network: @network.name }
    )
    redirect_to network_policies_path(@network), notice: "Policy '#{name}' deleted."
  end

  # POST /networks/:network_id/policies/:id/toggle
  def toggle
    @policy.update!(enabled: !@policy.enabled?)
    status_text = @policy.enabled? ? "enabled" : "disabled"
    AuditLog.record(
      action: "policy_toggle",
      target: @policy,
      details: { name: @policy.name, enabled: @policy.enabled?, network: @network.name }
    )
    redirect_to network_policies_path(@network), notice: "Policy '#{@policy.name}' #{status_text}."
  end

  # POST /networks/:network_id/policies/:id/duplicate
  def duplicate
    new_policy = @policy.duplicate!
    AuditLog.record(
      action: "policy_duplicate",
      target: new_policy,
      details: { original: @policy.name, network: @network.name }
    )
    redirect_to edit_network_policy_path(@network, new_policy), notice: "Policy duplicated. Edit the copy below."
  end

  # GET /networks/:network_id/policies/templates
  def templates
    @templates = PolicyTemplate.all.order(:category, :name)
    @grouped_templates = @templates.group_by(&:category)
  end

  # POST /networks/:network_id/policies/apply_template
  def apply_template
    template = PolicyTemplate.find(params[:template_id])
    created = template.apply_to_network!(@network)
    AuditLog.record(
      action: "policy_template_apply",
      details: {
        template: template.name,
        network: @network.name,
        policies_created: created.count
      }
    )
    redirect_to network_policies_path(@network),
      notice: "Template '#{template.name}' applied — #{created.count} policies created."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_policy
    @policy = @network.policies.find(params[:id])
  end

  def require_write_access
    if current_admin&.read_only?
      redirect_to network_policies_path(@network), alert: "You don't have permission to modify policies."
    end
  end

  def load_form_data
    @users = @network.ztlp_users.active.order(:name)
    @groups = @network.ztlp_groups.order(:name)
  end

  def policy_params
    params.require(:policy).permit(
      :name, :description, :policy_type, :priority, :enabled,
      :subject_type, :subject_value,
      :resource_type, :resource_value,
      :action, :time_schedule, :timezone, :expires_at
    )
  end
end
