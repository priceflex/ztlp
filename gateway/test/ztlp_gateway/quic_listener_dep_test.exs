defmodule ZtlpGateway.QuicListenerDepTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Task Q1 (ztlp-cloud-demo-plan.md, Session 3): pin that the `quicer`
  NIF (hex.pm `quicer` ~> 0.4.8, msquic-backed QUIC library) is present
  and can actually open a QUIC listener with the ALPN this demo's Rust
  clients require (`ztlp/1`, see `proto/src/quic_transport.rs::ZTLP_ALPN`).

  RED (before Q1's Dockerfile/mix.exs changes): `:quicer` is not a
  dependency yet, so `:quicer.listen/2` raises `UndefinedFunctionError`
  (module `:quicer` not loaded) even though this file compiles fine —
  Elixir doesn't need the module to exist at compile time for a plain
  remote call.

  GREEN (after Q1): the toolchain is bumped to OTP 26 (bookworm builder,
  cmake + build deps present so msquic compiles), `{:quicer, "~> 0.4.8"}`
  is added to `mix.exs` deps, and `:quicer.listen/2` succeeds with a
  self-signed cert/key pair generated for this test alone (NOT the
  persisted `/var/lib/ztlp/gateway/quic-{cert,key}.pem` pair Task Q4
  will wire up permanently — that's out of scope here, this test only
  proves the dependency itself is usable).
  """

  @tag :quic_dep
  test "quicer NIF can open a QUIC listener advertising ALPN ztlp/1" do
    {certfile, keyfile} = generate_ephemeral_cert_pair()

    assert {:ok, listener} =
             :quicer.listen(0, %{
               alpn: [~c"ztlp/1"],
               certfile: certfile,
               keyfile: keyfile,
               idle_timeout_ms: 10_000,
               peer_bidi_stream_count: 256
             })

    :quicer.close_listener(listener)
  after
    cleanup_ephemeral_cert_pair()
  end

  # ── Self-signed ECDSA P-256 cert/key, PEM files (quicer wants file
  # paths, not in-memory PEM blobs) ──────────────────────────────────

  defp cert_dir, do: Path.join(System.tmp_dir!(), "ztlp_quic_listener_dep_test")

  defp generate_ephemeral_cert_pair do
    dir = cert_dir()
    File.mkdir_p!(dir)
    certfile = Path.join(dir, "cert.pem") |> to_charlist()
    keyfile = Path.join(dir, "key.pem") |> to_charlist()

    {_out, 0} =
      System.cmd(
        "openssl",
        [
          "req",
          "-x509",
          "-newkey",
          "ec",
          "-pkeyopt",
          "ec_paramgen_curve:P-256",
          "-keyout",
          List.to_string(keyfile),
          "-out",
          List.to_string(certfile),
          "-days",
          "1",
          "-nodes",
          "-subj",
          "/CN=localhost"
        ],
        stderr_to_stdout: true
      )

    {certfile, keyfile}
  end

  defp cleanup_ephemeral_cert_pair do
    File.rm_rf(cert_dir())
  end
end
