# frozen_string_literal: true

class AdminsController < ApplicationController
  before_action :require_super_admin, except: [ :index ]
  before_action :set_admin, only: %i[edit update]

  def index
    @admins = Admin.order(:username)
  end

  # Slice 11d: inline disable/enable from the list. No-op when already in the
  # requested state (no duplicate audit row); a disabled admin cannot sign in
  # (sessions gate), so this is the fast path, with the edit form as fallback.
  def toggle
    @admin = set_admin
    want = params[:disabled] == "1"
    # Same rule as update: a sole super_admin disabling themselves would lock the panel.
    return redirect_to(admins_path, alert: "You cannot disable your own account.") if @admin == current_admin
    if @admin.disabled? != want
      @admin.update!(disabled_at: want ? Time.current : nil)
      audit!("admin.updated", target: @admin,
              details: { username: @admin.username, disabled: want })
      redirect_to admins_path, notice: "Administrator #{@admin.username} #{want ? 'disabled' : 're-enabled'}."
    else
      redirect_to admins_path
    end
  end

  def new
    @admin = Admin.new(role: "admin")
  end

  def create
    @admin = Admin.new(admin_params)
    if @admin.save
      audit!("admin.created", target: @admin, username: @admin.username, role: @admin.role)
      redirect_to admins_path, notice: "Administrator #{@admin.username} added."
    else
      render :new, status: :unprocessable_entity
    end
  end

  def edit; end

  def update
    attrs = admin_params.except(:pubkey_hex)
    attrs[:disabled_at] = params.dig(:admin, :disabled) == "1" ? (@admin.disabled_at || Time.current) : nil
    if @admin == current_admin && (attrs[:role] != "super_admin" || attrs[:disabled_at])
      return redirect_to(edit_admin_path(@admin), alert: "You cannot demote or disable your own account.")
    end

    if @admin.update(attrs)
      audit!("admin.updated", target: @admin, changes: @admin.previous_changes.except("updated_at").keys)
      redirect_to admins_path, notice: "Administrator #{@admin.username} updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end

  private

  def set_admin = @admin = Admin.find(params[:id])

  def admin_params
    params.require(:admin).permit(:username, :display_name, :email, :role, :pubkey_hex)
  end
end
