defmodule ZtlpGateway.MixProject do
  use Mix.Project

  @moduledoc false

  def project do
    [
      app: :ztlp_gateway,
      # Bumped 0.24.0 → 0.29.4 in PR #14 to close the version-string drift
      # that PR #13 fixed for the relay. Bumped 0.29.4 → 0.29.5 in PR #15 to
      # cut a clean v0.29.5 tag where the git tag and all four declared
      # versions (relay, gateway, ns, proto) agree. Bumped 0.30.0 → 0.30.3
      # in PR release/v0.30.3 after the v0.30.3 git tag was cut from a5993ee
      # (PR #40 — Z2LS gateway-auth enrollment API). Bumped 0.30.3 → 0.30.4
      # in PR release/v0.30.4 to align manifests with the re-cut v0.30.4
      # tag. The release_test.exs "version reporting (regression pin)" block
      # floors this at 0.30.4 to prevent silent down-drift going forward.
      # Bumped 0.30.4 → 0.31.0 in release/v0.31.0 (resilient-connectivity).
      # Bumped 0.31.0 → 0.32.2 in PR release/v0.32.2 to align with the v0.32
      # family (multi-candidate discovery + QUIC-path dial + IPv6 fixes,
      # PRs #69/#70/#71). All three v0.32.x releases shipped while mix.exs
      # still read 0.31.0; this PR closes that drift. Floor ratcheted to
      # 0.32.2 in release_test.exs.
      # Bumped 0.34.6 → 0.34.7 in release/v0.34.7 (desktop enroll-paste handler
      # fix, PR #89). Floor ratcheted to 0.34.7 in release_test.exs.
      # Bumped 0.34.7 → 0.34.8 in release/v0.34.8 (NS self-register heartbeat
      # in `ztlp listen`, PR #91). Floor ratcheted to 0.34.8 in release_test.exs.
      # Bumped 0.34.8 → 0.34.9 in release/v0.34.9 (connect auto-reconnect
      # supervisor, PR #93). Floor ratcheted to 0.34.9 in release_test.exs.
      # Bumped 0.34.9 → 0.34.10 in release/v0.34.10 (supervisor default-on for
      # raw-IP connects, PR #95). Floor ratcheted to 0.34.10 in release_test.exs.
      version: "0.34.10",
      elixir: "~> 1.12",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases()
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :ssl],
      mod: {ZtlpGateway.Application, []}
    ]
  end

  # The NS dependency is only used for integration tests — it lets us
  # start a real ZTLP-NS server and create signed records to test the
  # gateway's NS query path end-to-end. In production, gateway and NS
  # communicate purely over UDP wire protocol.
  defp deps do
    [
      {:ztlp_ns, path: "../ns", only: :test, runtime: false}
    ]
  end

  defp releases do
    [
      ztlp_gateway: [
        include_executables_for: [:unix],
        strip_beams: true,
        cookie: System.get_env("RELEASE_COOKIE")
      ]
    ]
  end
end
