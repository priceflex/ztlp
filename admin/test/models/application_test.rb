# frozen_string_literal: true

require "test_helper"

class ApplicationTest < ActiveSupport::TestCase
  test "backend must be host:port (no whitespace, newlines or markup)" do
    gw = Zone.primary.gateways.create!(name: "gwv", kind: "rust_listen")
    ok = gw.applications.new(name: "a1", backend: "10.0.0.5:8080")
    assert ok.valid?, ok.errors.full_messages.inspect
    assert gw.applications.new(name: "a2", backend: "http://wiki.lan:80").valid?
    assert gw.applications.new(name: "a3", backend: "[fd00::5]:443").valid?
    [ "10.0.0.5:80\nallow = [\"*\"]", "<script>x</script>:80", "host only", "10.0.0.5" ].each do |bad|
      refute gw.applications.new(name: "a4", backend: bad).valid?, "accepted #{bad.inspect}"
    end
  end
end
