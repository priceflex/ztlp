defmodule ZtlpNs.NssetSeeder do
  @moduledoc """
  Authors the signed NSSET for each zone this name server is home for
  (NS-anchored gateway trust, Phase 3).

  An NSSET tells enrolled clients which name servers (and their keys) they
  may trust for a zone. Clients accept it only when it is signed by their
  HOME name-server key (received in the enrollment token), so the home
  server vouches for its replicas / peers and can withdraw that trust
  fleet-wide by dropping a server from the list.

  Record: name = the zone apex (e.g. `trs.ztlp`), type `:operator` (0x07,
  reserved for NS-authored records: registrations of this type are refused),
  data:

      %{"kind" => "nsset", "zone" => zone,
        "servers" => [%{"addr" => "ip:port", "pubkey" => hex, "zones" => [..]}, ...]}

  `servers` lists this server first, then peers serving the zone. Serial =
  unix time, re-seeded every `ttl/2`.

  Config (all must be set to enable; otherwise the seeder is idle):

    * `ZTLP_NS_NSSET_ZONES` — comma-separated zones this NS is home for
    * `ZTLP_NS_SELF_ADDR`   — this server's public `ip:port`
    * `ZTLP_NS_PEERS`       — optional, `label=ip:port=hexpubkey=zone1,zone2;…`
    * `ZTLP_NS_NSSET_TTL`   — optional seconds (default 86400)

  A peer listed for a zone this NS is not home for is refused (the home
  server can only vouch for zones it is authoritative for). An NSSET that
  would not fit the client's 2 KB reply budget is not published.
  """

  use GenServer
  require Logger

  alias ZtlpNs.{Crypto, Record, Store}

  @default_ttl 86_400
  # Client queries are padded to 256 B and the NS caps replies at 8x; keep
  # the encoded record well under 2048 B (status byte + headroom).
  @max_encoded 1900

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc "Re-seed now (tests / admin)."
  def seed_now, do: GenServer.call(__MODULE__, :seed)

  @doc """
  Parse config into `{:ok, cfg}` / `:disabled` / `{:error, reason}`.
  `env` is a map of env-var name => value (defaults to the process env).
  """
  def config(env \\ nil) do
    get = fn k -> if env, do: Map.get(env, k), else: System.get_env(k) end
    zones = split_list(get.("ZTLP_NS_NSSET_ZONES"), ",")
    self_addr = trim(get.("ZTLP_NS_SELF_ADDR"))

    cond do
      zones == [] -> :disabled
      self_addr == "" -> {:error, :missing_self_addr}
      true ->
        ttl =
          case Integer.parse(trim(get.("ZTLP_NS_NSSET_TTL"))) do
            {n, ""} when n >= 120 -> n
            _ -> @default_ttl
          end

        with {:ok, peers} <- parse_peers(get.("ZTLP_NS_PEERS") || "", zones) do
          {:ok, %{zones: zones, self_addr: self_addr, peers: peers, ttl: ttl}}
        end
    end
  end

  @doc """
  Build the signed NSSET records (one per zone). Pure apart from the clock.
  Returns `{:ok, [record]}` or `{:error, {:too_large, zone, bytes}}`.
  """
  def build(cfg, private_key, now \\ System.system_time(:second)) do
    self_pub = Base.encode16(Crypto.public_key_from_private(private_key), case: :lower)

    Enum.reduce_while(cfg.zones, {:ok, []}, fn zone, {:ok, acc} ->
      servers =
        [%{"addr" => cfg.self_addr, "pubkey" => self_pub, "zones" => cfg.zones}] ++
          for p <- cfg.peers, zone in p.zones do
            %{"addr" => p.addr, "pubkey" => p.pubkey, "zones" => p.zones}
          end

      rec =
        %Record{
          name: zone,
          type: :operator,
          data: %{"kind" => "nsset", "zone" => zone, "servers" => servers},
          created_at: now,
          ttl: cfg.ttl,
          serial: now
        }
        |> Record.sign(private_key)

      size = byte_size(Record.encode(rec))

      if size > @max_encoded do
        {:halt, {:error, {:too_large, zone, size}}}
      else
        {:cont, {:ok, acc ++ [rec]}}
      end
    end)
  end

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    case config() do
      :disabled ->
        Logger.info("[ztlp-ns] NSSET seeder idle (ZTLP_NS_NSSET_ZONES not set)")
        {:ok, %{cfg: nil}}

      {:error, reason} ->
        Logger.error("[ztlp-ns] NSSET seeder disabled: invalid config (#{inspect(reason)})")
        {:ok, %{cfg: nil}}

      {:ok, cfg} ->
        send(self(), :tick)
        {:ok, %{cfg: cfg}}
    end
  end

  @impl true
  def handle_info(:tick, %{cfg: cfg} = state) do
    seed(cfg)
    Process.send_after(self(), :tick, div(cfg.ttl, 2) * 1000)
    {:noreply, state}
  end

  @impl true
  def handle_call(:seed, _from, %{cfg: nil} = state), do: {:reply, :disabled, state}
  def handle_call(:seed, _from, %{cfg: cfg} = state), do: {:reply, seed(cfg), state}

  defp seed(cfg) do
    case Application.get_env(:ztlp_ns, :registration_private_key) do
      nil ->
        Logger.error("[ztlp-ns] NSSET not seeded: no NS registration key")
        {:error, :no_registration_key}

      priv ->
        case build(cfg, priv) do
          {:ok, records} ->
            Enum.each(records, fn r ->
              case Store.insert(r) do
                :ok ->
                  Logger.info(
                    "[ztlp-ns] NSSET #{r.name}: #{length(r.data["servers"])} servers, serial #{r.serial}"
                  )

                {:error, reason} ->
                  Logger.error("[ztlp-ns] NSSET #{r.name} insert failed: #{inspect(reason)}")
              end
            end)

            :ok

          {:error, reason} ->
            Logger.error("[ztlp-ns] NSSET not seeded: #{inspect(reason)}")
            {:error, reason}
        end
    end
  end

  # ── Parsing ─────────────────────────────────────────────────────────

  defp parse_peers(raw, home_zones) do
    raw
    |> split_list(";")
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case String.split(entry, "=", parts: 4) do
        [label, addr, pubkey, zones_raw] ->
          zones = split_list(zones_raw, ",")
          pubkey = String.downcase(trim(pubkey))
          foreign = zones -- home_zones

          cond do
            not Regex.match?(~r/^[0-9a-f]{64}$/, pubkey) ->
              {:halt, {:error, {:bad_peer_pubkey, trim(label)}}}

            trim(addr) == "" ->
              {:halt, {:error, {:bad_peer_addr, trim(label)}}}

            zones == [] ->
              {:halt, {:error, {:peer_without_zones, trim(label)}}}

            foreign != [] ->
              {:halt, {:error, {:peer_zone_not_authoritative, trim(label), foreign}}}

            true ->
              {:cont, {:ok, acc ++ [%{label: trim(label), addr: trim(addr), pubkey: pubkey, zones: zones}]}}
          end

        _ ->
          {:halt, {:error, {:bad_peer_entry, entry}}}
      end
    end)
  end

  defp split_list(nil, _sep), do: []

  defp split_list(raw, sep) do
    raw
    |> String.split(sep)
    |> Enum.map(&(&1 |> String.trim() |> String.trim_trailing(".") |> String.downcase()))
    |> Enum.reject(&(&1 == ""))
  end

  defp trim(nil), do: ""
  defp trim(s), do: String.trim(s)
end
