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
      version: "0.30.0",
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
