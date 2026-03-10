defmodule ZtlpGateway.MixProject do
  use Mix.Project

  @moduledoc false

  def project do
    [
      app: :ztlp_gateway,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
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
end
