defmodule ZtlpGateway.MixProject do
  use Mix.Project

  @moduledoc false

  def project do
    [
      app: :ztlp_gateway,
      version: "0.13.0",
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
        cookie: System.get_env("RELEASE_COOKIE", "ztlp_gateway_default_cookie")
      ]
    ]
  end
end
