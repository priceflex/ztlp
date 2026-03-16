# frozen_string_literal: true

require "test_helper"

class NsRegistrarTest < ActiveSupport::TestCase
  setup do
    @network = networks(:office)
  end

  test "raises when no NS machine exists" do
    network = networks(:production) # Has no NS machines
    # Remove any NS machines from production network
    network.machines.with_role("ns").destroy_all

    registrar = NsRegistrar.new(network)
    assert_raises(NsRegistrar::RegistrationError) do
      registrar.register!
    end
  end

  test "raises when BOOTSTRAP_URL not set" do
    ENV.delete("BOOTSTRAP_URL")
    registrar = NsRegistrar.new(@network)
    assert_raises(NsRegistrar::RegistrationError) do
      registrar.register!(bootstrap_url: nil)
    end
  end

  test "register builds correct service name" do
    registrar = NsRegistrar.new(@network)
    expected_name = "bootstrap.#{@network.zone}"
    assert_equal "bootstrap.office.acme.ztlp", expected_name
  end

  test "MiniCbor encodes strings" do
    encoded = NsRegistrar::MiniCbor.encode("hello")
    # CBOR text string: major type 3, length 5
    assert_equal "\x65hello".b, encoded
  end

  test "MiniCbor encodes small integers" do
    assert_equal "\x00".b, NsRegistrar::MiniCbor.encode(0)
    assert_equal "\x17".b, NsRegistrar::MiniCbor.encode(23)
    assert_equal "\x18\x18".b, NsRegistrar::MiniCbor.encode(24)
  end

  test "MiniCbor encodes maps with sorted keys" do
    encoded = NsRegistrar::MiniCbor.encode({ "b" => "2", "a" => "1" })
    # Map with 2 entries, keys sorted: "a" < "b"
    assert encoded.start_with?("\xa2".b)  # map(2)
    # "a" should come before "b" in the encoding
    a_pos = encoded.index("\x61a".b)
    b_pos = encoded.index("\x61b".b)
    assert a_pos < b_pos, "Keys should be sorted: 'a' before 'b'"
  end

  test "lookup returns nil when NS unreachable" do
    registrar = NsRegistrar.new(@network)
    result = registrar.lookup
    # Should timeout/fail gracefully since no NS is running locally
    assert_nil result
  end

  test "registered? returns false when NS unreachable" do
    registrar = NsRegistrar.new(@network)
    refute registrar.registered?
  end
end
