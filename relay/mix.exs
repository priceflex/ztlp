defmodule ZtlpRelay.MixProject do
  use Mix.Project

  def project do
    [
      app: :ztlp_relay,
      version: "0.9.14",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
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
