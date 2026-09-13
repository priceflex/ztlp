defmodule ZtlpNs.DemoComposeConsistencyTest do
  @moduledoc """
  Regression guards for the DEF CON cloud demo compose files (follow-ups 4
  and 5 of ztlp-cloud-demo-plan.md, 2026-09-13).

  5) `demo/local-loopback.override.yml` uses `volumes: !override`, which
     REPLACES the base service's volume list. Any mount added to
     `defcon-cloud-compose.yml` for a service the override touches must be
     mirrored there, or the local loopback stack silently runs without it
     (bit us once with `ns-registration.key`). This test diffs the two.

  4) Relay prod HMAC mode: relay1, relay2 and the gateway must agree on ONE
     `ZTLP_RELAY_REGISTRATION_SECRET`, both relays must be in `prod` mode,
     and the client-facing docs must publish the same secret, otherwise
     every GATEWAY_REGISTER_ADDR / CLIENT_ROUTE frame is rejected.
  """
  use ExUnit.Case, async: true

  @repo Path.expand("../../..", __DIR__)
  @base Path.join(@repo, "demo/defcon-cloud-compose.yml")
  @override Path.join(@repo, "demo/local-loopback.override.yml")
  @quickstart Path.join(@repo, "demo/CLOUD-QUICKSTART.md")

  # Minimal compose reader: returns %{service => %{"volumes" => [..], "environment" => %{k => v}}}
  # using indentation, good enough for these hand-maintained demo files
  # (the ns app has no YAML dependency).
  defp parse(path) do
    lines = File.read!(path) |> String.split("\n")

    {services, _cur, _section} =
      Enum.reduce(lines, {%{}, nil, nil}, fn line, {acc, cur, section} ->
        trimmed = String.trim_trailing(line)

        cond do
          trimmed == "" or String.starts_with?(String.trim(trimmed), "#") ->
            {acc, cur, section}

          Regex.match?(~r/^  [a-z0-9_-]+:\s*$/, trimmed) ->
            [_, name] = Regex.run(~r/^  ([a-z0-9_-]+):/, trimmed)
            {Map.put_new(acc, name, %{"volumes" => [], "environment" => %{}}), name, nil}

          cur != nil and Regex.match?(~r/^    volumes:/, trimmed) ->
            {acc, cur, "volumes"}

          cur != nil and Regex.match?(~r/^    environment:/, trimmed) ->
            {acc, cur, "environment"}

          cur != nil and Regex.match?(~r/^    [a-z_]+:/, trimmed) ->
            {acc, cur, nil}

          cur != nil and section == "volumes" and Regex.match?(~r/^      - /, trimmed) ->
            [_, v] = Regex.run(~r/^      - "?([^"]+)"?\s*$/, trimmed)
            {update_in(acc, [cur, "volumes"], &(&1 ++ [v])), cur, section}

          cur != nil and section == "environment" and Regex.match?(~r/^      [A-Z0-9_]+:/, trimmed) ->
            [_, k, v] = Regex.run(~r/^      ([A-Z0-9_]+):\s*"?([^"]*)"?\s*$/, trimmed)
            {put_in(acc, [cur, "environment", k], v), cur, section}

          true ->
            {acc, cur, section}
        end
      end)

    services
  end

  # The container-side path is what matters for parity: the override may
  # legitimately remap the HOST side (e.g. /var/lib/ztlp/ca -> /tmp/...).
  defp container_paths(volumes) do
    volumes
    |> Enum.map(fn v ->
      case String.split(v, ":") do
        [_host, container | _] -> container
        [only] -> only
      end
    end)
    |> Enum.sort()
  end

  test "override mirrors every container mount of the base compose for the services it overrides" do
    base = parse(@base)
    override = parse(@override)
    override_body = File.read!(@override)

    for {svc, %{"volumes" => ov}} <- override, ov != [] do
      assert override_body =~ ~r/^  #{svc}:\n(?:.*\n)*?    volumes: !override/m,
             "#{svc}: override volumes list must use `!override` (that is the footgun this guards)"

      base_paths = container_paths(base[svc]["volumes"])
      over_paths = container_paths(ov)

      missing = base_paths -- over_paths
      extra = over_paths -- base_paths

      assert missing == [],
             "#{svc}: mounts in defcon-cloud-compose.yml missing from local-loopback.override.yml: #{inspect(missing)}"

      assert extra == [],
             "#{svc}: mounts in local-loopback.override.yml not in defcon-cloud-compose.yml: #{inspect(extra)}"
    end
  end

  test "override does not drop a service that has volumes in the base compose" do
    base = parse(@base)
    override = parse(@override)

    for {svc, %{"volumes" => bv}} <- base, bv != [] do
      assert Map.has_key?(override, svc),
             "#{svc} has volumes in the base compose but no entry in local-loopback.override.yml"
    end
  end

  test "relays run prod HMAC mode and share one registration secret with the gateway" do
    base = parse(@base)

    for relay <- ["relay1", "relay2"] do
      assert base[relay]["environment"]["ZTLP_RELAY_HMAC_MODE"] == "prod",
             "#{relay}: ZTLP_RELAY_HMAC_MODE must be prod (fail-closed), got #{inspect(base[relay]["environment"]["ZTLP_RELAY_HMAC_MODE"])}"
    end

    secrets =
      for svc <- ["relay1", "relay2", "gateway"] do
        s = base[svc]["environment"]["ZTLP_RELAY_REGISTRATION_SECRET"]
        assert is_binary(s) and s != "", "#{svc}: ZTLP_RELAY_REGISTRATION_SECRET missing"
        assert Regex.match?(~r/^[0-9a-f]{64}$/, s), "#{svc}: secret should be 64 lowercase hex (openssl rand -hex 32)"
        s
      end

    assert length(Enum.uniq(secrets)) == 1, "relay1/relay2/gateway must share ONE secret, got #{inspect(secrets)}"

    # It must NOT be the zone enrollment secret (different trust domain).
    refute hd(secrets) == base["ns"]["environment"]["ZTLP_ENROLLMENT_SECRET"],
           "relay secret must differ from ZTLP_ENROLLMENT_SECRET"
  end

  test "CLOUD-QUICKSTART publishes the same relay secret for clients" do
    base = parse(@base)
    secret = base["relay1"]["environment"]["ZTLP_RELAY_REGISTRATION_SECRET"]
    body = File.read!(@quickstart)

    assert body =~ ~r/relay_secret\s*=\s*"#{secret}"/,
           "CLOUD-QUICKSTART.md agent.toml example must set [tunnel] relay_secret = \"#{secret}\""
  end
end
