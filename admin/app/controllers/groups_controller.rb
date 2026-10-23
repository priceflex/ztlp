# frozen_string_literal: true

# Slice 7a: Groups directory — read side (spec Slice 7).
# Slice 7b: mutations (spec Slice 7): new/create, edit/update, destroy, and
# add_member / remove_member on the show page. Every membership change calls
# Publisher.publish_group! immediately (spec F13) — the gateway allow-list
# picks the new members up without a restart. Per the 6b rule the DB change
# is the source of truth: an NS failure never 500s after the save, it is a
# warning toast and the 6-hourly republish retries. Destroy is blocked while
# any policy rule references the group and for the default `admins` group.
# Slice 9a seam: index "Applications" column + show "Policies" panel are
# computed from policy_rules (Ztlp::PolicyRenderer.apps_for_group).
class GroupsController < ApplicationController
  before_action :set_group, only: %i[show edit update destroy add_member remove_member]
  before_action :require_write_access, only: %i[new create edit update destroy add_member remove_member]

  # Form fields; the name is normalized (lowercased DNS label) by the model
  # and drives ns_name. Description is free text.
  GROUP_FIELDS = %i[name description].freeze

  def index
    @groups = @zone.groups.includes(:users).order(:name)
    @group_refs = group_refs_by_ns_name
  end

  def show
    @members = @group.users.includes(:devices).order(:username)
    @candidates = @zone.users.where.not(id: @group.users.select(:id)).order(:username)
    @referencing = @zone.gateways.flat_map { |gw| Ztlp::PolicyRenderer.apps_for_group(gw, @group) }
    render layout: false if drawer_request?
  end

  def new
    @group = @zone.groups.build
  end

  def create
    @group = @zone.groups.build(group_params)

    if @group.save
      warning = publish_group!(@group)
      audit!("group.create", target: @group, details: { name: @group.name, ns_name: @group.ns_name })
      redirect_to group_path(@group), notice: "Group #{@group.name} created.", alert: warning
    else
      render :new, status: :unprocessable_content
    end
  end

  def edit
  end

  def update
    # Name is immutable after create: it drives ns_name, and a rename would leave the old GROUP
    # record (with its members) live in the NS.
    if @group.update(group_params.except(:name))
      warning = publish_group!(@group)
      audit!("group.update", target: @group, details: { name: @group.name })
      redirect_to group_path(@group), notice: "Group #{@group.name} updated.", alert: warning
    else
      render :edit, status: :unprocessable_content
    end
  end

  # A membership change is an access change: publish the GROUP record NOW so
  # gateway allow-lists see it without a restart (spec F13).
  def add_member
    user = @zone.users.find_by(id: params[:user_id])
    if user.nil?
      return redirect_to group_path(@group), alert: "Unknown user."
    end
    if @group.member?(user)
      return redirect_to group_path(@group), notice: "#{user.display_name} is already a member of #{@group.name}."
    end

    @group.group_memberships.create!(user: user, added_by_admin: current_admin)
    warning = publish_group!(@group)
    audit!("group.add_member", target: @group, details: { user: user.username })
    redirect_to group_path(@group), notice: "#{user.display_name} added to #{@group.name}.", alert: warning
  end

  def remove_member
    user = @zone.users.find_by(id: params[:user_id])
    membership = @group.group_memberships.find_by(user: user)
    if membership.nil?
      return redirect_to group_path(@group), alert: "Not a member of #{@group.name}."
    end

    membership.destroy!
    warning = publish_group!(@group)
    audit!("group.remove_member", target: @group, details: { user: user.username })
    redirect_to group_path(@group), notice: "#{user.display_name} removed from #{@group.name}.", alert: warning
  end

  # The `admins` group is the default first-admin group (Slice 3): it must
  # always exist so at least one administrator keeps panel access. A group
  # referenced by a policy rule would silently break access if deleted, so
  # the rule must be removed first (Slice 9).
  def destroy
    if @group.name == "admins"
      audit!("group.destroy", target: @group, status: "skipped", details: { reason: "admins_group" })
      return redirect_to groups_path, alert: "The admins group cannot be deleted."
    end
    referenced = PolicyRule.where(subject_type: "group", subject_id: @group.id)
                            .where(application_id: Application.where(gateway_id: @zone.gateways.select(:id)))
                            .exists?
    if referenced
      audit!("group.destroy", target: @group, status: "skipped", details: { reason: "referenced_by_policy" })
      return redirect_to group_path(@group), alert: "#{@group.name} is referenced by a policy rule. Remove the rule first."
    end

    # The GROUP record must not outlive the row with its members still listed (a rule keyed on
    # the group name would keep granting access with no panel row left to fix it). Publish an
    # EMPTY group first, inside the transaction: if the NS refuses, everything rolls back.
    begin
      Group.transaction do
        @group.group_memberships.delete_all
        Ztlp::Publisher.publish_group!(@group, admin: current_admin)
        @group.destroy!
      end
    rescue Ztlp::NsClient::NsError => e
      audit!("group.destroy", target: @group, status: "failed",
                              details: { name: @group.name, result: format("0x%02X %s", e.code, e.reason) })
      return redirect_to group_path(@group),
                         alert: format("%s was NOT deleted: the name server refused the empty-group publish " \
                                       "(0x%02X %s). Nothing changed.", @group.name, e.code, e.reason)
    end
    audit!("group.destroy", target: @group, details: { name: @group.name })
    redirect_to groups_path, notice: "Group #{@group.name} deleted."
  end

  private

  # { ns_name => [Application, ...] } for every `group:` policy rule in the
  # zone's gateways. A rule whose group row was deleted still shows (stale but
  # honest — the ns_name is pinned in subject_value at rule-create time).
  def group_refs_by_ns_name
    refs = Hash.new { |h, k| h[k] = [] }
    @zone.gateways.each do |gw|
      group_refs_for_gateway(gw).each { |ns, apps| refs[ns] |= apps } # accumulate, never overwrite
    end
    refs
  end

  def group_refs_for_gateway(gateway)
    app_ids = gateway.applications.pluck(:id)
    refs = {}
    PolicyRule.where(subject_type: "group", application_id: app_ids).each do |rule|
      refs[rule.subject_value] = Array(refs[rule.subject_value])
      app = rule.application
      refs[rule.subject_value] << app unless refs[rule.subject_value].include?(app)
    end
    refs
  end

  # 6b rule: the DB save stands; an NS failure is a warning, never a 500.
  def publish_group!(group)
    Ztlp::Publisher.publish_group!(group, admin: current_admin)
    nil
  rescue Ztlp::NsClient::NsError => e
    format("Saved, but not published to the name server (0x%02X %s). " \
           "The 6-hourly republish will retry.", e.code, e.reason)
  end

  def set_group
    @group = @zone.groups.find(params[:id])
  end

  def drawer_request? = request.headers["X-Drawer"] == "1"

  def group_params
    params.require(:group).permit(*GROUP_FIELDS)
  end
end
