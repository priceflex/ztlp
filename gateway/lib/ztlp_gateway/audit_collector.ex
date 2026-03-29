defmodule ZtlpGateway.AuditCollector do
  @moduledoc """
  Unified Audit Collector for the ZTLP Gateway.

  Collects structured audit events from all ZTLP components (gateway, NS,
  relay, clients) into a searchable in-memory store. Events are stored in
  an ETS ordered_set keyed by auto-incrementing ID.

  ## Features

  - **Event storage** — ETS table with auto-incrementing IDs
  - **Query API** — filter by component, level, event, service, time range
  - **Stats** — aggregate counts by component, level, service
  - **Retention sweep** — hourly cleanup of old events (configurable)
  - **Wire protocol 0x15** — accept events from remote components via UDP

  ## Standard Event Envelope

      %{
        id: 1,
        timestamp: "2026-03-29T16:48:00.000Z",
        component: "gateway",
        hostname: "gw-prod-1",
        event: "session_established",
        level: "info",
        service: "vault.techrockstars.ztlp",
        username: "steve@techrockstars.ztlp",
        node_id: "0x1234abcd...",
        source_ip: "174.236.97.20",
        details: %{}
      }

  ## Configuration

  - `ZTLP_GATEWAY_AUDIT_ENABLED` — enable/disable (default: true)
  - `ZTLP_GATEWAY_AUDIT_PORT` — HTTP API port (default: 9104)
  - `ZTLP_GATEWAY_AUDIT_MAX_EVENTS` — max events before oldest pruned (default: 10,000)
  - `ZTLP_GATEWAY_AUDIT_RETENTION_DAYS` — retention period (default: 30)
  """

  use GenServer

  require Logger

  @table :ztlp_gateway_audit_events
  @counter :ztlp_gateway_audit_counter
  @sweep_interval_ms :timer.hours(1)

  # Wire protocol opcode for audit events
  @opcode_audit 0x15

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the Audit Collector."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an audit event.

  Accepts a map with event fields. Required: `:event`, `:component`, `:level`.
  Missing fields are filled with defaults (hostname, timestamp).

  Returns `:ok` immediately (non-blocking ETS insert).
  """
  @spec log_event(map()) :: :ok
  def log_event(event) when is_map(event) do
    if enabled?() and ets_exists?() do
      do_log_event(event)
    else
      :ok
    end
  end

  @doc """
  Query audit events with filters.

  ## Options

  - `:component` — filter by component (string)
  - `:level` — filter by level (string)
  - `:event` — filter by event type (string)
  - `:service` — filter by service (string)
  - `:since` — ISO 8601 start time (string)
  - `:until` — ISO 8601 end time (string)
  - `:limit` — max results (default 100)
  - `:offset` — pagination offset (default 0)

  Returns `%{total: integer, offset: integer, limit: integer, events: [map]}`.
  """
  @spec query(keyword()) :: map()
  def query(opts \\ []) do
    unless ets_exists?() do
      return_empty_query(opts)
    else
      do_query(opts)
    end
  end

  defp return_empty_query(opts) do
    limit = Keyword.get(opts, :limit, 100) |> min(10_000)
    offset = Keyword.get(opts, :offset, 0)
    %{total: 0, offset: offset, limit: limit, events: []}
  end

  defp do_query(opts) do
    limit = Keyword.get(opts, :limit, 100) |> min(10_000)
    offset = Keyword.get(opts, :offset, 0)

    all_events =
      :ets.tab2list(@table)
      |> Enum.map(fn {_id, event} -> event end)
      |> Enum.sort_by(& &1.id, :desc)

    filtered = apply_filters(all_events, opts)
    total = length(filtered)

    events =
      filtered
      |> Enum.drop(offset)
      |> Enum.take(limit)

    %{total: total, offset: offset, limit: limit, events: events}
  end

  @doc """
  Get aggregate statistics.

  Returns a map with total events, counts by component, level, service,
  and oldest/newest timestamps.
  """
  @spec stats() :: map()
  def stats do
    unless ets_exists?() do
      %{total_events: 0, by_component: %{}, by_level: %{}, by_service: %{}, oldest_event: nil, newest_event: nil}
    else
      do_stats()
    end
  end

  defp do_stats do
    all =
      :ets.tab2list(@table)
      |> Enum.map(fn {_id, event} -> event end)

    total = length(all)

    by_component =
      all
      |> Enum.group_by(& &1.component)
      |> Enum.map(fn {k, v} -> {k, length(v)} end)
      |> Map.new()

    by_level =
      all
      |> Enum.group_by(& &1.level)
      |> Enum.map(fn {k, v} -> {k, length(v)} end)
      |> Map.new()

    by_service =
      all
      |> Enum.reject(fn e -> is_nil(e.service) or e.service == "" end)
      |> Enum.group_by(& &1.service)
      |> Enum.map(fn {k, v} -> {k, length(v)} end)
      |> Map.new()

    timestamps = Enum.map(all, & &1.timestamp) |> Enum.sort()

    %{
      total_events: total,
      by_component: by_component,
      by_level: by_level,
      by_service: by_service,
      oldest_event: List.first(timestamps),
      newest_event: List.last(timestamps)
    }
  end

  @doc """
  Handle a wire protocol 0x15 audit event packet.

  Format: `<<0x15, event_json_bytes::binary>>`

  Parses the JSON, validates required fields, and stores the event.
  Returns `:ok` on success, `{:error, reason}` on failure.
  """
  @spec handle_wire_event(binary()) :: :ok | {:error, atom()}
  def handle_wire_event(<<@opcode_audit, json_bytes::binary>>) do
    case json_decode(json_bytes) do
      {:ok, map} ->
        required = ["event", "component", "level"]
        missing = Enum.filter(required, fn k -> not Map.has_key?(map, k) end)

        if missing == [] do
          # Convert string keys to atom keys for internal envelope
          event = normalize_wire_event(map)
          do_log_event(event)
          :ok
        else
          {:error, :missing_fields}
        end

      {:error, _} ->
        {:error, :invalid_json}
    end
  end

  def handle_wire_event(_), do: {:error, :invalid_opcode}

  @doc "Returns the wire protocol opcode for audit events."
  @spec opcode() :: non_neg_integer()
  def opcode, do: @opcode_audit

  @doc "Check if audit collection is enabled."
  @spec enabled?() :: boolean()
  def enabled? do
    ZtlpGateway.Config.get(:audit_enabled)
  end

  @doc "Force a retention sweep (used in tests)."
  @spec sweep() :: :ok
  def sweep do
    GenServer.call(__MODULE__, :sweep)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create the ETS table for event storage
    :ets.new(@table, [:named_table, :ordered_set, :public, read_concurrency: true])

    # Create the counter table for auto-incrementing IDs
    :ets.new(@counter, [:named_table, :set, :public])
    :ets.insert(@counter, {:next_id, 0})

    # Schedule periodic retention sweep
    schedule_sweep()

    Logger.info("[AuditCollector] Started (max_events=#{max_events()}, retention_days=#{retention_days()})")
    {:ok, %{}}
  end

  @impl true
  def handle_call(:sweep, _from, state) do
    do_sweep()
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:retention_sweep, state) do
    do_sweep()
    schedule_sweep()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Internal — Event Storage
  # ---------------------------------------------------------------------------

  defp do_log_event(event) do
    id = :ets.update_counter(@counter, :next_id, 1)
    hostname = Map.get(event, :hostname) || get_hostname()
    timestamp = Map.get(event, :timestamp) || DateTime.utc_now() |> DateTime.to_iso8601()

    full_event = %{
      id: id,
      timestamp: timestamp,
      component: to_string(Map.get(event, :component, "gateway")),
      hostname: to_string(hostname),
      event: to_string(Map.get(event, :event, "unknown")),
      level: to_string(Map.get(event, :level, "info")),
      service: if(Map.get(event, :service), do: to_string(event.service), else: nil),
      username: if(Map.get(event, :username), do: to_string(event.username), else: nil),
      node_id: if(Map.get(event, :node_id), do: to_string(event.node_id), else: nil),
      source_ip: if(Map.get(event, :source_ip), do: to_string(event.source_ip), else: nil),
      details: Map.get(event, :details, %{})
    }

    :ets.insert(@table, {id, full_event})

    # Enforce max events cap
    enforce_max_events()

    :ok
  end

  defp enforce_max_events do
    max = max_events()
    size = :ets.info(@table, :size)

    if size > max do
      # Delete oldest events (lowest IDs) until within cap
      to_delete = size - max
      delete_oldest(to_delete)
    end
  end

  defp delete_oldest(0), do: :ok

  defp delete_oldest(count) do
    case :ets.first(@table) do
      :"$end_of_table" -> :ok
      key ->
        :ets.delete(@table, key)
        delete_oldest(count - 1)
    end
  end

  # ---------------------------------------------------------------------------
  # Internal — Retention Sweep
  # ---------------------------------------------------------------------------

  defp do_sweep do
    cutoff = retention_cutoff()

    :ets.tab2list(@table)
    |> Enum.each(fn {id, event} ->
      if event.timestamp < cutoff do
        :ets.delete(@table, id)
      end
    end)
  end

  defp retention_cutoff do
    days = retention_days()
    now = DateTime.utc_now()

    now
    |> DateTime.add(-days * 86_400, :second)
    |> DateTime.to_iso8601()
  end

  defp schedule_sweep do
    Process.send_after(self(), :retention_sweep, @sweep_interval_ms)
  end

  # ---------------------------------------------------------------------------
  # Internal — Query Filters
  # ---------------------------------------------------------------------------

  defp apply_filters(events, opts) do
    events
    |> filter_by(:component, Keyword.get(opts, :component))
    |> filter_by(:level, Keyword.get(opts, :level))
    |> filter_by(:event, Keyword.get(opts, :event))
    |> filter_by(:service, Keyword.get(opts, :service))
    |> filter_since(Keyword.get(opts, :since))
    |> filter_until(Keyword.get(opts, :until))
  end

  defp filter_by(events, _field, nil), do: events

  defp filter_by(events, field, value) do
    Enum.filter(events, fn e -> Map.get(e, field) == value end)
  end

  defp filter_since(events, nil), do: events

  defp filter_since(events, since) do
    Enum.filter(events, fn e -> e.timestamp >= since end)
  end

  defp filter_until(events, nil), do: events

  defp filter_until(events, until_ts) do
    Enum.filter(events, fn e -> e.timestamp <= until_ts end)
  end

  # ---------------------------------------------------------------------------
  # Internal — Wire Protocol JSON (minimal, no external deps)
  # ---------------------------------------------------------------------------

  defp normalize_wire_event(map) do
    %{
      event: Map.get(map, "event"),
      component: Map.get(map, "component"),
      level: Map.get(map, "level"),
      hostname: Map.get(map, "hostname"),
      timestamp: Map.get(map, "ts"),
      service: Map.get(map, "service"),
      username: Map.get(map, "username"),
      node_id: Map.get(map, "node_id"),
      source_ip: Map.get(map, "source_ip"),
      details: Map.get(map, "details", %{})
    }
  end

  @doc false
  # Minimal JSON decoder — handles objects, arrays, strings, numbers, booleans, null.
  # No external dependencies. Sufficient for audit event payloads.
  @spec json_decode(binary()) :: {:ok, term()} | {:error, :invalid_json}
  def json_decode(bin) when is_binary(bin) do
    try do
      {value, _rest} = parse_value(String.trim(bin))
      {:ok, value}
    rescue
      _ -> {:error, :invalid_json}
    catch
      :throw, :invalid_json -> {:error, :invalid_json}
    end
  end

  defp parse_value(<<"{", rest::binary>>), do: parse_object(String.trim_leading(rest), %{})
  defp parse_value(<<"[", rest::binary>>), do: parse_array(String.trim_leading(rest), [])
  defp parse_value(<<"\"", _::binary>> = s), do: parse_string(s)
  defp parse_value(<<"true", rest::binary>>), do: {true, rest}
  defp parse_value(<<"false", rest::binary>>), do: {false, rest}
  defp parse_value(<<"null", rest::binary>>), do: {nil, rest}
  defp parse_value(<<c, _::binary>> = s) when c in [?-, ?0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9] do
    parse_number(s)
  end
  defp parse_value(_), do: throw(:invalid_json)

  defp parse_object(<<"}", rest::binary>>, acc), do: {acc, rest}

  defp parse_object(s, acc) do
    {key, rest} = parse_string(s)
    rest = expect_colon(String.trim_leading(rest))
    {value, rest} = parse_value(String.trim_leading(rest))
    acc = Map.put(acc, key, value)
    rest = String.trim_leading(rest)

    case rest do
      <<"}", r::binary>> -> {acc, r}
      <<",", r::binary>> -> parse_object(String.trim_leading(r), acc)
      _ -> throw(:invalid_json)
    end
  end

  defp parse_array(<<"]", rest::binary>>, acc), do: {Enum.reverse(acc), rest}

  defp parse_array(s, acc) do
    {value, rest} = parse_value(String.trim_leading(s))
    rest = String.trim_leading(rest)

    case rest do
      <<"]", r::binary>> -> {Enum.reverse([value | acc]), r}
      <<",", r::binary>> -> parse_array(String.trim_leading(r), [value | acc])
      _ -> throw(:invalid_json)
    end
  end

  defp parse_string(<<"\"", rest::binary>>), do: parse_string_chars(rest, [])

  defp parse_string_chars(<<"\\\"", rest::binary>>, acc), do: parse_string_chars(rest, [?" | acc])
  defp parse_string_chars(<<"\\\\", rest::binary>>, acc), do: parse_string_chars(rest, [?\\ | acc])
  defp parse_string_chars(<<"\\/", rest::binary>>, acc), do: parse_string_chars(rest, [?/ | acc])
  defp parse_string_chars(<<"\\n", rest::binary>>, acc), do: parse_string_chars(rest, [?\n | acc])
  defp parse_string_chars(<<"\\t", rest::binary>>, acc), do: parse_string_chars(rest, [?\t | acc])
  defp parse_string_chars(<<"\\r", rest::binary>>, acc), do: parse_string_chars(rest, [?\r | acc])
  defp parse_string_chars(<<"\"", rest::binary>>, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}
  defp parse_string_chars(<<c, rest::binary>>, acc), do: parse_string_chars(rest, [c | acc])
  defp parse_string_chars(<<>>, _acc), do: throw(:invalid_json)

  defp parse_number(s) do
    {num_str, rest} = take_number_chars(s, [])
    num = if String.contains?(num_str, ".") or String.contains?(num_str, "e") or String.contains?(num_str, "E") do
      String.to_float(num_str)
    else
      String.to_integer(num_str)
    end
    {num, rest}
  end

  defp take_number_chars(<<c, rest::binary>>, acc)
       when c in [?0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?., ?-, ?+, ?e, ?E] do
    take_number_chars(rest, [c | acc])
  end
  defp take_number_chars(rest, acc), do: {acc |> Enum.reverse() |> IO.iodata_to_binary(), rest}

  defp expect_colon(<<":", rest::binary>>), do: String.trim_leading(rest)
  defp expect_colon(_), do: throw(:invalid_json)

  @doc false
  # Minimal JSON encoder — handles maps, lists, strings, numbers, booleans, nil, atoms.
  @spec json_encode(term()) :: binary()
  def json_encode(nil), do: "null"
  def json_encode(true), do: "true"
  def json_encode(false), do: "false"
  def json_encode(n) when is_integer(n), do: Integer.to_string(n)
  def json_encode(n) when is_float(n), do: Float.to_string(n)
  def json_encode(a) when is_atom(a), do: json_encode(Atom.to_string(a))

  def json_encode(s) when is_binary(s) do
    escaped =
      s
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
      |> String.replace("\n", "\\n")
      |> String.replace("\r", "\\r")
      |> String.replace("\t", "\\t")

    "\"" <> escaped <> "\""
  end

  def json_encode(map) when is_map(map) do
    pairs =
      map
      |> Enum.map(fn {k, v} ->
        key = if is_atom(k), do: Atom.to_string(k), else: to_string(k)
        json_encode(key) <> ":" <> json_encode(v)
      end)
      |> Enum.join(",")

    "{" <> pairs <> "}"
  end

  def json_encode(list) when is_list(list) do
    items = Enum.map(list, &json_encode/1) |> Enum.join(",")
    "[" <> items <> "]"
  end

  def json_encode(other), do: json_encode(inspect(other))

  # ---------------------------------------------------------------------------
  # Internal — Helpers
  # ---------------------------------------------------------------------------

  defp ets_exists? do
    :ets.whereis(@table) != :undefined
  end

  defp get_hostname do
    case :inet.gethostname() do
      {:ok, name} -> List.to_string(name)
      _ -> "unknown"
    end
  end

  defp max_events, do: ZtlpGateway.Config.get(:audit_max_events)
  defp retention_days, do: ZtlpGateway.Config.get(:audit_retention_days)
end
