defmodule ZtlpNs.MixProject do
  use Mix.Project

  def project do
    [
      app: :ztlp_ns,
      # Bumped 0.24.0 → 0.29.4 in PR #14 to close the version-string drift
      # that PR #13 fixed for the relay. Bumped 0.29.4 → 0.29.5 in PR #15 to
      # cut a clean v0.29.5 tag where the git tag and all four declared
      # versions (relay, gateway, ns, proto) agree. The release_test.exs
      # "version reporting (regression pin)" block floors this at 0.29.4
      # to prevent silent down-drift going forward.
      version: "0.30.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      # Use ns/lib as the source directory
      elixirc_paths: elixirc_paths(Mix.env()),
      releases: releases()
    ]
  end

  def application do
    [
      # :crypto provides Ed25519 signing/verification (OTP 24+)
      # :inets provides :httpc for HTTPS bootstrap discovery
      # :mnesia provides persistent record storage (OTP built-in)
      extra_applications: [:logger, :crypto, :public_key, :ssl, :inets, :mnesia],
      mod: {ZtlpNs.Application, []}
    ]
  end

  # Zero external dependencies — pure Elixir/OTP only.
  # This is a deliberate design choice matching the relay project.
  defp deps do
    []
  end

  defp elixirc_paths(_), do: ["lib"]

  defp releases do
    [
      ztlp_ns: [
        include_executables_for: [:unix],
        strip_beams: true,
        cookie: System.get_env("RELEASE_COOKIE", "ztlp_ns_default_cookie")
      ]
    ]
  end
end
