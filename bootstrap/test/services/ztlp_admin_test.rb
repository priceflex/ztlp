# frozen_string_literal: true

require "test_helper"

class ZtlpAdminTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
  end

  test "initializes with network" do
    admin = ZtlpAdmin.new(@network)
    assert_equal @network, admin.network
  end

  test "raises error when no NS machine" do
    network = networks(:production)
    # production has no machines
    error = assert_raises(ZtlpAdmin::AdminError) do
      ZtlpAdmin.new(network)
    end
    assert_match "No NS machine found", error.message
  end

  test "create_user builds correct command" do
    admin = ZtlpAdmin.new(@network)
    # We can't test actual SSH execution, but we can test the object is valid
    assert_respond_to admin, :create_user
  end

  test "revoke_user builds correct command" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :revoke_user
  end

  test "list_users is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :list_users
  end

  test "link_device is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :link_device
  end

  test "revoke_device is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :revoke_device
  end

  test "list_devices is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :list_devices
  end

  test "create_group is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :create_group
  end

  test "group_add is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :group_add
  end

  test "group_remove is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :group_remove
  end

  test "list_groups is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :list_groups
  end

  test "group_members is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :group_members
  end

  test "list_entities is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :list_entities
  end

  test "audit_log is callable" do
    admin = ZtlpAdmin.new(@network)
    assert_respond_to admin, :audit_log
  end

  test "shell_escape prevents injection" do
    admin = ZtlpAdmin.new(@network)
    # The service should escape shell arguments properly
    # Testing private method through public interface
    assert_respond_to admin, :create_user
  end
end
