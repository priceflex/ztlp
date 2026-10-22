# frozen_string_literal: true

require "test_helper"

class Ztlp::AssuranceTest < ActiveSupport::TestCase
  test "levels order unknown < software < device-bound < hardware" do
    assert_equal 1, Ztlp::Assurance.level("unknown")
    assert_equal 2, Ztlp::Assurance.level("software")
    assert_equal 3, Ztlp::Assurance.level("device-bound")
    assert_equal 4, Ztlp::Assurance.level("hardware")
    assert_operator Ztlp::Assurance.level("software"), :<, Ztlp::Assurance.level("device-bound")
  end

  test "device_bound alias and unknown values map to the floor" do
    assert_equal Ztlp::Assurance.level("device-bound"), Ztlp::Assurance.level("device_bound")
    assert_equal 1, Ztlp::Assurance.level("no-such-value")
    assert_equal 1, Ztlp::Assurance.level(nil)
  end

  test "label renders the human form, hardware flagged unverified without attestation" do
    assert_equal "software", Ztlp::Assurance.label(2)
    assert_equal "hardware (unverified)", Ztlp::Assurance.label(4)
  end

  test "key sources" do
    assert_includes Ztlp::Assurance::KEY_SOURCES, "yubikey"
    assert_includes Ztlp::Assurance::KEY_SOURCES, "secure-enclave"
    assert_includes Ztlp::Assurance::KEY_SOURCES, "unknown"
  end
end
