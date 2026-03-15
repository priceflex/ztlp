# frozen_string_literal: true

class ZtlpGroupsController < ApplicationController
  before_action :set_network
  before_action :set_group, only: [:show, :destroy, :add_member, :remove_member]

  def index
    @groups = @network.ztlp_groups.includes(:group_memberships).order(:name)
  end

  def show
    @members = @group.ztlp_users.order(:name)
    @available_users = @network.ztlp_users.active.where.not(id: @members.pluck(:id)).order(:name)
  end

  def new
    @group = @network.ztlp_groups.new
  end

  def create
    @group = @network.ztlp_groups.new(group_params)

    if @group.save
      AuditLog.record(
        action: "ztlp_group_create",
        target: @group,
        details: { name: @group.name, network: @network.name }
      )
      redirect_to network_ztlp_group_path(@network, @group), notice: "Group '#{@group.name}' created."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    name = @group.name
    @group.destroy
    AuditLog.record(
      action: "ztlp_group_destroy",
      details: { name: name, network: @network.name }
    )
    redirect_to network_ztlp_groups_path(@network), notice: "Group '#{name}' deleted."
  end

  # POST /networks/:network_id/groups/:id/add_member
  def add_member
    user = @network.ztlp_users.find(params[:user_id])
    membership = @group.group_memberships.build(ztlp_user: user)

    if membership.save
      AuditLog.record(
        action: "ztlp_group_add_member",
        target: @group,
        details: { group: @group.name, user: user.name, network: @network.name }
      )
      redirect_to network_ztlp_group_path(@network, @group), notice: "#{user.name} added to #{@group.name}."
    else
      redirect_to network_ztlp_group_path(@network, @group), alert: membership.errors.full_messages.join(", ")
    end
  end

  # DELETE /networks/:network_id/groups/:id/remove_member
  def remove_member
    user = @network.ztlp_users.find(params[:user_id])
    membership = @group.group_memberships.find_by!(ztlp_user: user)
    membership.destroy
    AuditLog.record(
      action: "ztlp_group_remove_member",
      target: @group,
      details: { group: @group.name, user: user.name, network: @network.name }
    )
    redirect_to network_ztlp_group_path(@network, @group), notice: "#{user.name} removed from #{@group.name}."
  end

  private

  def set_network
    @network = Network.find(params[:network_id])
  end

  def set_group
    @group = @network.ztlp_groups.find(params[:id])
  end

  def group_params
    params.require(:ztlp_group).permit(:name, :description)
  end
end
