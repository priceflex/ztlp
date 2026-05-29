defmodule ZtlpRelay.MixProject do
  use Mix.Project

  def project do
    [
      app: :ztlp_relay,
      # Bumped 0.29.4 → 0.29.5 in PR #15 to cut a clean v0.29.5 tag where
      # the git tag and all four declared versions (relay, gateway, ns,
      # proto) agree. v0.29.4 was tagged BEFORE PR #13/#14 bumped mix.exs
      # files, so containers built from the v0.29.4 tag misreport their
      # runtime vsn. v0.29.5 fixes that drift by tagging AFTER the bumps.
      # Bumped 0.30.0 → 0.30.3 in PR release/v0.30.3 after the v0.30.3 git
      # tag was cut from a5993ee (PR #40 — Z2LS gateway-auth enrollment API).
      # Bumped 0.30.3 → 0.30.4 in PR release/v0.30.4 to align with the
      # re-cut v0.30.4 tag.
      # Bumped 0.30.4 → 0.31.0 in release/v0.31.0 (resilient-connectivity).
      # Bumped 0.31.0 → 0.32.2 in PR release/v0.32.2 to align with the v0.32
      # family (PRs #69/#70/#71). Floor ratcheted to 0.32.2 in release_test.exs.
      version: "0.34.2",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :ssl],
      mod: {ZtlpRelay.Application, []}
    ]
  end

  defp deps do
    [
      {:ztlp_ns, path: "../ns", only: :test, runtime: false}
    ]
  end

  defp releases do
    [
      ztlp_relay: [
        include_executables_for: [:unix],
        strip_beams: true,
        cookie: System.get_env("RELEASE_COOKIE", "ztlp_relay_default_cookie")
      ]
    ]
  end
end
