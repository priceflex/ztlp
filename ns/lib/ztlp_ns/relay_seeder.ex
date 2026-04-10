defmodule ZtlpNs.RelaySeeder do
  @moduledoc """
  Seeds initial RELAY records into the NS store on startup.

  Reads `ZTLP_NS_RELAY_RECORDS` environment variable with comma-separated
  relay entries in the format:
    `name=address:port,region=region_name,latency_ms=N,load_pct=N,health=STATUS`

  Multiple relays are separated by `|`.

  Example:
    ZTLP_NS_RELAY_RECORDS="name=relay1,34.219.64.205:23095,region=us-west-2,latency_ms=12,load_pct=35,health=healthy|name=relay2,44.246.33.34:23096,region=us-east-1,latency_ms=45,load_pct=80,health=degraded"

  Uses the rich CBOR format compatible with iOS `ztlp_ns_resolve_relays_sync`:
    %{
      "address" => "34.219.64.205:23095",
      "region" => "us-west-2",
      "latency_ms" => 12,
      "load_pct" => 35,
      "active_connections" => 0,
      "health" => "healthy",
      "endpoints" => ["34.219.64.205:23095"],
      "node_id" => ""
    }
  """

  require Logger

  alias ZtlpNs.{Record, Store}

  @doc "Seed relay records from env on startup."
  def seed do
    raw = System.get_env("ZTLP_NS_RELAY_RECORDS") || ""

    if String.trim(raw) == "" do
      Logger.info("[ztlp-ns] No relay records to seed (ZTLP_NS_RELAY_RECORDS not set)")
      :ok
    else
      entries = String.split(raw, "|")

      seeded =
        for entry <- entries,
            String.trim(entry) != "",
            do: seed_one(entry)

      count = Enum.count(seeded, &(&1 == :ok))
      errors = Enum.count(seeded, &(&1 != :ok))

      Logger.info(
        "[ztlp-ns] Relay seeder: seeded #{count} records, #{errors} errors"
      )

      :ok
    end
  end

  defp seed_one(entry) do
    parts = String.split(entry, ",")
    kv = Enum.reduce(parts, %{}, fn part, acc ->
      case String.split(part, "=", parts: 2) do
        [k, v] -> Map.put(acc, String.trim(k), String.trim(v))
        _ -> acc
      end
    end)

    name = Map.get(kv, "name")
    address = Map.get(kv, "address") || Map.get(kv, "addr", "")
    region = Map.get(kv, "region", "unknown")
    latency_ms = parse_int(Map.get(kv, "latency_ms", "0"))
    load_pct = parse_int(Map.get(kv, "load_pct", "0"))
    active_conns = parse_int(Map.get(kv, "active_connections", "0"))
    health = Map.get(kv, "health", "healthy")
    node_id_hex = Map.get(kv, "node_id", "")

    cond do
      is_nil(name) or name == "" -> {:error, "missing name in #{entry}"}
      is_nil(address) or address == "" -> {:error, "missing address in #{entry}"}
      true ->
        record = Record.new_relay_rich(name, address, region,
          latency_ms: latency_ms,
          load_pct: load_pct,
          active_connections: active_conns,
          health: health,
          node_id_hex: node_id_hex
        )

        case Store.insert(record) do
          :ok ->
            Logger.info("[ztlp-ns] Seeded relay: #{name} -> #{address} (#{region}, #{health})")
            :ok

          {:error, reason} ->
            Logger.warning("[ztlp-ns] Failed to seed relay #{name}: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  defp parse_int(s) do
    case Integer.parse(s) do
      {n, ""} -> n
      _ -> 0
    end
  end
end
