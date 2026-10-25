defmodule ZtlpNs.RecordGoldenVectorTest do
  @moduledoc """
  Golden vectors shared with the Rust client (`proto/src/ns_verify.rs`).

  The Rust client verifies NS answers byte-for-byte against what this
  encoder produces, so the exact `Record.encode/1` output of a fixed,
  deterministically signed SVC record is committed under
  `proto/tests/fixtures/`. If this test fails, the NS wire format changed
  and every client that verifies records would reject answers: fix the
  change, do not just regenerate.

  Regenerate (only for an intentional, versioned format change):

      ZTLP_WRITE_GOLDEN=1 mix test test/ztlp_ns/record_golden_vector_test.exs
  """
  use ExUnit.Case, async: true

  alias ZtlpNs.Record

  @fixtures Path.expand("../../../proto/tests/fixtures", __DIR__)

  # Fixed Ed25519 seed: Ed25519 signatures are deterministic, so the
  # encoded bytes are stable across runs and machines.
  @seed :binary.copy(<<0x42>>, 32)

  # Matches what a gateway registers (`ztlp listen` SVC v2 data) after the
  # NS adds `registered_by`, plus the new `quic_cert_sha256` field.
  @svc_data %{
    "address" => "10.42.42.112:23097",
    "node_id" => "00112233445566778899aabbccddeeff",
    "zone" => "chooseforce.ztlp",
    "registered_by" => String.duplicate("cd", 32),
    "quic_cert_sha256" => String.duplicate("ab", 32)
  }

  defp golden(created_at, ttl, serial) do
    %Record{
      name: "www.chooseforce.ztlp",
      type: :svc,
      data: @svc_data,
      created_at: created_at,
      ttl: ttl,
      serial: serial
    }
    |> Record.sign(@seed)
  end

  defp check(file, bin) do
    path = Path.join(@fixtures, file)
    hex = Base.encode16(bin, case: :lower)

    if System.get_env("ZTLP_WRITE_GOLDEN") == "1" do
      File.mkdir_p!(@fixtures)
      File.write!(path, hex <> "\n")
    end

    assert String.trim(File.read!(path)) == hex
  end

  test "valid SVC record (created 2027-01-15, ttl 1 day) matches the committed vector" do
    rec = golden(1_800_000_000, 86_400, 1_800_000_000)
    assert Record.verify(rec)
    check("ns_signed_svc_record.hex", Record.encode(rec))
  end

  test "expired SVC record (2023, ttl 60 s) matches the committed vector" do
    rec = golden(1_700_000_000, 60, 1_700_000_000)
    assert Record.verify(rec)
    check("ns_signed_svc_record_expired.hex", Record.encode(rec))
  end

  test "signer public key matches the committed vector" do
    check("ns_signed_svc_record.pub", ZtlpNs.Crypto.public_key_from_private(@seed))
  end

  test "encoded vector round-trips through Record.decode and still verifies" do
    bin = Record.encode(golden(1_800_000_000, 86_400, 1_800_000_000))
    {:ok, decoded} = Record.decode(bin)
    assert Record.verify(decoded)
    assert decoded.data["quic_cert_sha256"] == String.duplicate("ab", 32)
  end
end
