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

  describe "version reporting (regression pin)" do
    # These tests mirror the regression pins added to relay/test/.../release_test.exs
    # in PR #13. The relay defect that motivated them — git tag cut without
    # bumping mix.exs, so `Application.spec(_, :vsn)` lied at runtime — is
    # structurally possible in every Elixir component in this repo. NS is
    # one of those components; it stayed pinned at 0.24.0 for five minor
    # versions while the rest of the stack moved on, which is exactly the kind
    # of silent drift these tests are designed to surface.
    #
    # See also: gateway/test/ztlp_gateway/release_test.exs (sibling block),
    # and the "Known Problems #6 / Open Question #1" entries in
    # hermes_session_handoff.md.

    test "mix.exs version is a parseable semver string" do
      version = ZtlpNs.MixProject.project()[:version]
      assert is_binary(version), "project version must be a string"

      assert Regex.match?(~r/^\d+\.\d+\.\d+(-[A-Za-z0-9.+-]+)?$/, version),
             "version #{inspect(version)} must look like MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-PRE"
    end

    test "runtime-reported vsn matches mix.exs version (no drift between tag and OTP release)" do
      # `Application.spec/2` reads the value the OTP release was compiled with.
      # Mismatch == the .app file is stale, OR mix.exs was bumped without a
      # recompile, OR (the case PR #13 caught) a git tag was cut without
      # touching mix.exs. Any of those make `docker exec ... rpc
      # 'Application.spec(:ztlp_ns, :vsn)'` lie about which tag is live.
      declared = ZtlpNs.MixProject.project()[:version]
      runtime = to_string(Application.spec(:ztlp_ns, :vsn))

      assert declared == runtime,
             """
             ns/mix.exs declares version #{inspect(declared)} but the loaded
             :ztlp_ns application reports vsn=#{inspect(runtime)}.
             This drift means runtime health checks will misreport the deployed
             version. Either re-run `mix compile` after the bump, or update
             mix.exs to match the intended release.
             """
    end

    test "mix.exs version is at least 0.32.2 (v0.32.2 multi-candidate-QUIC-path tag)" do
      # Floor guard: prevents an accidental down-bump that would make the NS
      # misreport itself as a pre-v0.32.2 version. Ratcheted from 0.30.5 →
      # 0.32.2 in PR release/v0.32.2 to align the floor with the v0.32 family:
      # v0.32 (multi-candidate discovery, PR #69), v0.32.1 (keepalive-port +
      # IPv6 dual-stack + loopback classifier, PR #70), v0.32.2
      # (multi-candidate dial moves into QUIC path + punch IPv6 fix, PR #71).
      # All three releases shipped while mix.exs still read 0.31.0; this PR
      # closes that drift. Using Version.compare (rather than asserting a
      # literal string) means this test does NOT need maintenance on every
      # routine version bump — it only fails on a down-bump below the 0.32.2
      # floor.
      declared = ZtlpNs.MixProject.project()[:version]
      assert Version.compare(declared, "0.34.6") in [:gt, :eq],
             "mix.exs version #{declared} is older than the v0.34.6 desktop-ipc-fast-fail tag"
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
