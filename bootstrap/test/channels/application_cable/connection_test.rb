# frozen_string_literal: true

require "test_helper"

# [zig-wyxu regression] ActionCable::Channel::TestCase (used by
# DeployChannelTest) does NOT exercise Connection#connect at all - it
# bypasses the WebSocket handshake layer entirely, so DeployChannelTest
# passing does not prove unauthenticated connections are actually
# rejected. This file directly tests Connection#connect using
# ActionCable::Connection::TestCase, which DOES exercise the real
# connect path.
class ApplicationCable::ConnectionTest < ActionCable::Connection::TestCase
  setup do
    @admin = admin_users(:super_admin)
  end

  test "accepts a connection with a valid session admin_user_id" do
    connect session: { admin_user_id: @admin.id }
    assert_equal @admin, connection.current_admin
  end

  test "rejects a connection with no session and no gateway auth" do
    assert_reject_connection { connect }
  end

  test "rejects a connection with an invalid admin_user_id in session" do
    assert_reject_connection { connect session: { admin_user_id: -1 } }
  end

  test "rejects a connection for a locked admin account" do
    connect session: { admin_user_id: admin_users(:locked_admin).id }
  rescue ActionCable::Connection::Authorization::UnauthorizedError
    # expected
  else
    flunk "expected connection to be rejected for a locked admin"
  end
end
