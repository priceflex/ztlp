defmodule ZtlpGateway.CrlServer do
  @moduledoc """
  Certificate Revocation List (CRL) server for the ZTLP Gateway.

  Maintains a list of revoked certificate fingerprints and serial numbers.
  Provides both an API for checking revocation status and an HTTP endpoint
  for distributing CRL data.

  ## Storage

  Revoked certificates are stored in an ETS table for fast lookups.
  The CRL is also periodically serialized to disk for persistence.
  """

  use GenServer
  require Logger

  @table :ztlp_crl

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check if a certificate is revoked by fingerprint.
  """
  @spec revoked?(String.t()) :: boolean()
  def revoked?(fingerprint) when is_binary(fingerprint) do
    case :ets.lookup(@table, {:fingerprint, fingerprint}) do
      [_] -> true
      [] -> false
    end
  end

  @doc """
  Check if a certificate is revoked by serial number.
  """
  @spec revoked_serial?(String.t() | integer()) :: boolean()
  def revoked_serial?(serial) do
    serial_str = to_string(serial)
    case :ets.lookup(@table, {:serial, serial_str}) do
      [_] -> true
      [] -> false
    end
  end

  @doc """
  Revoke a certificate.

  ## Parameters
  - `fingerprint` — SHA-256 fingerprint of the certificate
  - `opts` — options:
    - `:serial` — certificate serial number
    - `:reason` — revocation reason
    - `:revoked_at` — revocation timestamp (default: now)
  """
  @spec revoke(String.t(), keyword()) :: :ok
  def revoke(fingerprint, opts \\ []) do
    GenServer.call(__MODULE__, {:revoke, fingerprint, opts})
  end

  @doc """
  Unrevoke a certificate (remove from CRL).
  """
  @spec unrevoke(String.t()) :: :ok
  def unrevoke(fingerprint) do
    GenServer.call(__MODULE__, {:unrevoke, fingerprint})
  end

  @doc """
  List all revoked certificates.
  """
  @spec list_revoked() :: [map()]
  def list_revoked do
    :ets.tab2list(@table)
    |> Enum.flat_map(fn
      {{:fingerprint, fp}, info} -> [Map.put(info, :fingerprint, fp)]
      _ -> []
    end)
  end

  @doc "Get the count of revoked certificates."
  @spec count() :: non_neg_integer()
  def count do
    list_revoked() |> length()
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:revoke, fingerprint, opts}, _from, state) do
    serial = Keyword.get(opts, :serial)
    reason = Keyword.get(opts, :reason, "unspecified")
    revoked_at = Keyword.get(opts, :revoked_at, DateTime.utc_now() |> DateTime.to_iso8601())

    info = %{
      serial: serial,
      reason: reason,
      revoked_at: revoked_at
    }

    :ets.insert(@table, {{:fingerprint, fingerprint}, info})
    if serial do
      :ets.insert(@table, {{:serial, to_string(serial)}, info})
    end

    Logger.info("[CrlServer] Revoked certificate: #{fingerprint} reason: #{reason}")
    {:reply, :ok, state}
  end

  def handle_call({:unrevoke, fingerprint}, _from, state) do
    case :ets.lookup(@table, {:fingerprint, fingerprint}) do
      [{{:fingerprint, ^fingerprint}, info}] ->
        :ets.delete(@table, {:fingerprint, fingerprint})
        if info.serial do
          :ets.delete(@table, {:serial, to_string(info.serial)})
        end
      [] -> :ok
    end
    {:reply, :ok, state}
  end
end
