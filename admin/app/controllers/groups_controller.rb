# frozen_string_literal: true

# Slice 7a: Groups directory — read side (spec Slice 7).
#
# Index: name, ns_name, description, member count, applications referencing
# the group (none until Slice 9; honest zero). Show: full page or the drawer
# fragment under X-Drawer: 1 (same contract as users#show), with the members
# table (user, role, status) and the read-only policy-reference panel.
# Read-only slice: Publisher is not called.
class GroupsController < ApplicationController
  def index
    @groups = @zone.groups.includes(:users).order(:name)
  end

  def show
    @group = @zone.groups.find(params[:id])
    @members = @group.users.includes(:devices).order(:username)
    render layout: false if drawer_request?
  end

  private

  def drawer_request? = request.headers["X-Drawer"] == "1"
end
