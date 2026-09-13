defmodule ZtlpNs.DemoTrustAnchorConsistencyTest do
  @moduledoc """
  Regression guard for the DEF CON demo compose files.

  The gateway only trusts NS records whose signer matches
  `ZTLP_GATEWAY_TRUST_ANCHORS`. Device KEY records are signed by NS's
  *registration signing key*, so that key must be pinned to a committed
  seed (`demo/ns-registration.key`, mounted via `ZTLP_NS_IDENTITY_KEY_FILE`)
  and the anchor must be the Ed25519 public key derived from that seed.
  Otherwise every identity lookup fails with `:untrusted_signer` and the
  dashboard shows `unknown:<hex>`.
  """
  use ExUnit.Case, async: true

  @repo Path.expand("../../..", __DIR__)
  @key_file Path.join(@repo, "demo/ns-registration.key")
  @compose_files [
    "demo/defcon-cloud-compose.yml",
    "demo/defcon-laptop-compose.yml",
    "demo/defcon-demo-compose.yml"
  ]

  test "demo/ns-registration.key is a 32-byte hex Ed25519 seed" do
    assert File.exists?(@key_file), "missing #{@key_file}"
    assert {:ok, {pub, priv}} = ZtlpNs.ComponentAuth.load_identity_from_file(@key_file)
    assert byte_size(pub) == 32 and byte_size(priv) == 32
  end

  for compose <- @compose_files do
    test "#{compose}: gateway trust anchor == pubkey of demo/ns-registration.key" do
      path = Path.join(@repo, unquote(compose))
      body = File.read!(path)
      {:ok, {pub, _}} = ZtlpNs.ComponentAuth.load_identity_from_file(@key_file)
      expected = Base.encode16(pub, case: :lower)

      assert [_, anchor] =
               Regex.run(~r/ZTLP_GATEWAY_TRUST_ANCHORS:\s*"defcon\.ztlp:([0-9a-f]{64})"/, body),
             "no defcon.ztlp trust anchor in #{unquote(compose)}"

      assert anchor == expected,
             "#{unquote(compose)} anchors #{anchor} but ns-registration.key derives #{expected}"

      assert body =~ ~r/ZTLP_NS_IDENTITY_KEY_FILE:\s*"\/data\/ns-registration\.key"/,
             "#{unquote(compose)}: ns service must set ZTLP_NS_IDENTITY_KEY_FILE"

      assert body =~ ~r/\.\/ns-registration\.key:\/data\/ns-registration\.key:ro/,
             "#{unquote(compose)}: ns service must mount ./ns-registration.key read-only"
    end
  end
end
