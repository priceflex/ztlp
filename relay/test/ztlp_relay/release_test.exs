defmodule ZtlpRelay.ReleaseTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Tests that OTP release configuration is valid for the relay service.
  """

  describe "mix.exs release config" do
    test "project has releases key" do
      project = ZtlpRelay.MixProject.project()
      assert Keyword.has_key?(project, :releases)
    end

    test "release name is :ztlp_relay" do
      releases = ZtlpRelay.MixProject.project()[:releases]
      assert Keyword.has_key?(releases, :ztlp_relay)
    end

    test "release strips beams" do
      release_opts = ZtlpRelay.MixProject.project()[:releases][:ztlp_relay]
      assert release_opts[:strip_beams] == true
    end

    test "release includes unix executables" do
      release_opts = ZtlpRelay.MixProject.project()[:releases][:ztlp_relay]
      assert :unix in release_opts[:include_executables_for]
    end
  end

  describe "version reporting (regression pin)" do
    # These tests exist because of a v0.29.4 release defect:
    # the git tag `v0.29.4` was cut without bumping `relay/mix.exs`,
    # so a relay container built from the tag reports
    # `Application.spec(:ztlp_relay, :vsn) == '0.29.3'`.
    # Health checks and on-call diagnostics rely on this value
    # matching the deployed tag, so we pin it here to prevent
    # the same drift on future tags.

    test "mix.exs version is a parseable semver string" do
      version = ZtlpRelay.MixProject.project()[:version]
      assert is_binary(version), "project version must be a string"

      assert Regex.match?(~r/^\d+\.\d+\.\d+(-[A-Za-z0-9.+-]+)?$/, version),
             "version #{inspect(version)} must look like MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-PRE"
    end

    test "runtime-reported vsn matches mix.exs version (no drift between tag and OTP release)" do
      # `Application.spec/2` reads the value the OTP release was compiled with.
      # If `mix.exs` was bumped but the release was rebuilt from a stale .app
      # cache, this catches it. More importantly, it catches the inverse:
      # someone tagging a new git version without touching mix.exs.
      declared = ZtlpRelay.MixProject.project()[:version]
      runtime = to_string(Application.spec(:ztlp_relay, :vsn))

      assert declared == runtime,
             """
             relay/mix.exs declares version #{inspect(declared)} but the loaded
             :ztlp_relay application reports vsn=#{inspect(runtime)}.
             This drift means `docker exec ztlp-relay /app/bin/ztlp_relay rpc
             'Application.spec(:ztlp_relay, :vsn)'` will lie about which tag
             is actually running. Either re-run `mix compile` after the bump,
             or update mix.exs to match the intended release.
             """
    end

    test "mix.exs version is at least 0.32.2 (v0.32.2 multi-candidate-QUIC-path tag)" do
      # Floor guard: prevents an accidental down-bump that would make
      # the relay misreport itself as a pre-v0.32.2 version.
      # Ratcheted 0.30.5 → 0.32.2 in PR release/v0.32.2 to align the floor
      # with the v0.32 family: v0.32 (multi-candidate discovery, PR #69),
      # v0.32.1 (keepalive-port + IPv6 dual-stack + loopback classifier,
      # PR #70), v0.32.2 (multi-candidate dial moves into QUIC path + punch
      # IPv6 fix, PR #71). All three releases shipped while mix.exs still
      # read 0.31.0; this PR closes that drift.
      declared = ZtlpRelay.MixProject.project()[:version]
      assert Version.compare(declared, "0.32.2") in [:gt, :eq],
             "mix.exs version #{declared} is older than the v0.32.2 multi-candidate-QUIC-path tag"
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

      # Code.string_to_quoted will parse without evaluating
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
      appup_path = Path.join([__DIR__, "..", "..", "rel", "appups", "ztlp_relay.appup"])
      assert File.exists?(appup_path), "rel/appups/ztlp_relay.appup must exist"
    end

    test "appup file is valid Erlang term" do
      appup_path =
        Path.join([__DIR__, "..", "..", "rel", "appups", "ztlp_relay.appup"])
        |> Path.expand()

      assert {:ok, [term]} = :file.consult(String.to_charlist(appup_path))
      # Appup format: {Vsn, UpFromVsn, DownToVsn}
      assert {vsn, up_instructions, down_instructions} = term
      assert is_list(up_instructions)
      assert is_list(down_instructions)
      assert is_list(vsn) or is_binary(vsn)
    end
  end
end
