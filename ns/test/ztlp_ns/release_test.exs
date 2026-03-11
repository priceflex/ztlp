defmodule ZtlpNs.ReleaseTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Tests that OTP release configuration is valid for the NS service.
  """

  describe "mix.exs release config" do
    test "project has releases key" do
      project = ZtlpNs.MixProject.project()
      assert Keyword.has_key?(project, :releases)
    end

    test "release name is :ztlp_ns" do
      releases = ZtlpNs.MixProject.project()[:releases]
      assert Keyword.has_key?(releases, :ztlp_ns)
    end

    test "release strips beams" do
      release_opts = ZtlpNs.MixProject.project()[:releases][:ztlp_ns]
      assert release_opts[:strip_beams] == true
    end

    test "release includes unix executables" do
      release_opts = ZtlpNs.MixProject.project()[:releases][:ztlp_ns]
      assert :unix in release_opts[:include_executables_for]
    end
  end

  describe "runtime config" do
    test "runtime.exs exists" do
      runtime_path = Path.join([__DIR__, "..", "..", "config", "runtime.exs"])
      assert File.exists?(runtime_path), "config/runtime.exs must exist"
    end

    test "runtime.exs is valid Elixir" do
      runtime_path =
        Path.join([__DIR__, "..", "..", "config", "runtime.exs"])
        |> Path.expand()

      content = File.read!(runtime_path)
      assert {:ok, _ast} = Code.string_to_quoted(content)
    end
  end

  describe "release env script" do
    test "env.sh.eex template exists" do
      env_path = Path.join([__DIR__, "..", "..", "rel", "env.sh.eex"])
      assert File.exists?(env_path), "rel/env.sh.eex must exist"
    end

    test "env.sh.eex contains RELEASE_COOKIE" do
      env_path = Path.join([__DIR__, "..", "..", "rel", "env.sh.eex"])
      content = File.read!(env_path)
      assert content =~ "RELEASE_COOKIE"
    end

    test "env.sh.eex contains RELEASE_NODE" do
      env_path = Path.join([__DIR__, "..", "..", "rel", "env.sh.eex"])
      content = File.read!(env_path)
      assert content =~ "RELEASE_NODE"
    end

    test "env.sh.eex contains RELEASE_DISTRIBUTION" do
      env_path = Path.join([__DIR__, "..", "..", "rel", "env.sh.eex"])
      content = File.read!(env_path)
      assert content =~ "RELEASE_DISTRIBUTION"
    end
  end

  describe "appup template" do
    test "appup file exists" do
      appup_path = Path.join([__DIR__, "..", "..", "rel", "appups", "ztlp_ns.appup"])
      assert File.exists?(appup_path), "rel/appups/ztlp_ns.appup must exist"
    end

    test "appup file is valid Erlang term" do
      appup_path =
        Path.join([__DIR__, "..", "..", "rel", "appups", "ztlp_ns.appup"])
        |> Path.expand()

      assert {:ok, [term]} = :file.consult(String.to_charlist(appup_path))
      assert {vsn, up_instructions, down_instructions} = term
      assert is_list(up_instructions)
      assert is_list(down_instructions)
      assert is_list(vsn) or is_binary(vsn)
    end
  end
end
