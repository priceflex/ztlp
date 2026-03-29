defmodule ZtlpGateway.CertProvisioner do
  @moduledoc """
  Provisions TLS certificates from the ZTLP-NS Certificate Authority.

  On startup (and periodically), fetches service certificates for all
  configured backend services. The certificates are used by Session to
  terminate TLS on mux streams when clients connect to port 443.

  ## Certificate Lifecycle

  1. Gateway starts → CertProvisioner queries NS for CA root cert
  2. For each service, requests a server cert from the NS CA
  3. Certs are stored in ETS for fast lookup by Session
  4. Renewal timer fires at cert_lifetime/2 (configurable, default 3.5 days for 7-day certs)
  5. On renewal, new cert is fetched and atomically replaced in ETS
  6. On renewal failure, exponential backoff retry (30s → 1h cap)
  7. Cert expiry is tracked; warnings at 75% lifetime, errors at 90%

  ## Wire Protocol (NS queries)

  - `0x14 0x01` — Get CA root cert (DER)
  - `0x14 0x02` — Get CA chain (PEM)
  - `0x14 0x03` — Issue server cert for hostname

  ## Environment Variables

  - `ZTLP_GATEWAY_CERT_LIFETIME_DAYS` — cert lifetime in days (default: 7)
  - `ZTLP_GATEWAY_TLS_AUTO` — set to "false" to disable auto-provisioning
  """

  use GenServer
  require Logger

  @table :ztlp_gateway_certs

  # Exponential backoff schedule for renewal failures (in milliseconds)
  @backoff_schedule [
    30_000,       # 30 seconds
    60_000,       # 1 minute
    120_000,      # 2 minutes
    300_000,      # 5 minutes
    900_000,      # 15 minutes
    1_800_000,    # 30 minutes
    3_600_000     # 1 hour (cap)
  ]

  @default_cert_lifetime_days 7

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Look up TLS credentials for a service hostname.

  Returns `{:ok, %{cert_pem: String.t(), key_pem: String.t(), chain_pem: String.t()}}`
  or `:error` if no cert is available.
  """
  @spec lookup(String.t()) :: {:ok, map()} | :error
  def lookup(hostname) do
    case :ets.lookup(@table, {:cert, hostname}) do
      [{_, creds}] -> {:ok, creds}
      [] -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @doc """
  Get the CA root certificate in DER format (for distribution to clients).
  """
  @spec get_ca_root_der() :: {:ok, binary()} | :error
  def get_ca_root_der do
    case :ets.lookup(@table, :ca_root_der) do
      [{_, der}] -> {:ok, der}
      [] -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @doc """
  Get the CA chain in PEM format.
  """
  @spec get_ca_chain_pem() :: {:ok, String.t()} | :error
  def get_ca_chain_pem do
    case :ets.lookup(@table, :ca_chain_pem) do
      [{_, pem}] -> {:ok, pem}
      [] -> :error
    end
  rescue
    ArgumentError -> :error
  end

  @doc "Check if TLS is provisioned for any service."
  @spec tls_available?() :: boolean()
  def tls_available? do
    case :ets.lookup(@table, :ca_root_der) do
      [{_, _}] -> true
      [] -> false
    end
  rescue
    ArgumentError -> false
  end

  @doc "Force re-provisioning of all certs."
  def refresh do
    GenServer.cast(__MODULE__, :provision)
  end

  @doc """
  Get the current provisioning status.

  Returns one of:
  - `:ok` — certs provisioned and valid
  - `:renewing` — renewal in progress or pending retry
  - `:expired` — certs have expired
  - `:error` — provisioning failed, no valid certs
  - `:not_started` — provisioner not yet attempted provisioning
  """
  @spec status() :: :ok | :renewing | :expired | :error | :not_started
  def status do
    GenServer.call(__MODULE__, :status)
  catch
    :exit, _ -> :not_started
  end

  @doc """
  Check cert expiry status for a hostname.

  Returns `{:ok, :valid | :warning | :critical | :expired, days_remaining}`
  or `:error` if no cert data is tracked.
  """
  @spec check_expiry(String.t()) :: {:ok, atom(), float()} | :error
  def check_expiry(hostname) do
    case :ets.lookup(@table, {:expiry, hostname}) do
      [{_, %{issued_at: issued_at, lifetime_ms: lifetime_ms}}] ->
        now = System.system_time(:millisecond)
        expires_at = issued_at + lifetime_ms
        remaining_ms = expires_at - now
        remaining_days = remaining_ms / (24 * 60 * 60 * 1000)
        elapsed_ratio = (now - issued_at) / lifetime_ms

        status =
          cond do
            remaining_ms <= 0 -> :expired
            elapsed_ratio >= 0.9 -> :critical
            elapsed_ratio >= 0.75 -> :warning
            true -> :valid
          end

        {:ok, status, remaining_days}
      [] ->
        :error
    end
  rescue
    ArgumentError -> :error
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])

    ns_server = parse_ns_server()
    services = parse_service_names()
    zone = System.get_env("ZTLP_GATEWAY_SERVICE_ZONE") || "techrockstars.ztlp"
    enabled = System.get_env("ZTLP_GATEWAY_TLS_AUTO") != "false" and ns_server != nil
    cert_lifetime_days = parse_cert_lifetime_days()

    state = %{
      table: table,
      ns_server: ns_server,
      services: services,
      zone: zone,
      enabled: enabled,
      provisioned: false,
      status: :not_started,
      retry_count: 0,
      cert_lifetime_days: cert_lifetime_days,
      test_opts: Keyword.get(opts, :test_opts, %{})
    }

    if enabled and not Map.get(state.test_opts, :skip_provision, false) do
      # Delay initial provisioning to let NS finish starting
      Process.send_after(self(), :provision, 5_000)
    end

    {:ok, state}
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.status, state}
  end

  @impl true
  def handle_cast(:provision, state) do
    state = do_provision(state)
    {:noreply, state}
  end

  @impl true
  def handle_info(:provision, state) do
    state = do_provision(state)
    {:noreply, state}
  end

  def handle_info(:renew, state) do
    Logger.info("[CertProvisioner] Renewal timer fired, re-provisioning certs")
    state = %{state | status: :renewing}
    state = do_provision(state)
    {:noreply, state}
  end

  def handle_info(:check_expiry, state) do
    check_all_expiry(state)
    # Schedule next expiry check in 1 hour
    Process.send_after(self(), :check_expiry, 3_600_000)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Internal: Provisioning ─────────────────────────────────────────

  defp do_provision(%{enabled: false} = state), do: state
  defp do_provision(%{ns_server: nil} = state), do: state

  defp do_provision(state) do
    {ns_host, ns_port} = state.ns_server

    case :gen_udp.open(0, [:binary, active: false]) do
      {:ok, socket} ->
        try do
          # Step 1: Fetch CA root cert
          case fetch_ca_root(socket, ns_host, ns_port) do
            {:ok, root_der} ->
              :ets.insert(@table, {:ca_root_der, root_der})
              Logger.info("[CertProvisioner] CA root cert fetched (#{byte_size(root_der)} bytes)")

              # Step 2: Fetch CA chain
              case fetch_ca_chain(socket, ns_host, ns_port) do
                {:ok, chain_pem} ->
                  :ets.insert(@table, {:ca_chain_pem, chain_pem})

                {:error, reason} ->
                  Logger.warning("[CertProvisioner] Failed to fetch CA chain: #{inspect(reason)}")
              end

              # Step 3: Issue certs for each service
              now_ms = System.system_time(:millisecond)
              lifetime_ms = state.cert_lifetime_days * 24 * 60 * 60 * 1000

              for svc <- state.services do
                hostname = "#{svc}.#{state.zone}"
                case issue_service_cert(socket, ns_host, ns_port, hostname) do
                  {:ok, creds} ->
                    :ets.insert(@table, {{:cert, hostname}, creds})
                    # Also store by bare service name for easy lookup
                    :ets.insert(@table, {{:cert, svc}, creds})
                    # Track expiry for this cert
                    :ets.insert(@table, {{:expiry, hostname}, %{
                      issued_at: now_ms,
                      lifetime_ms: lifetime_ms
                    }})
                    :ets.insert(@table, {{:expiry, svc}, %{
                      issued_at: now_ms,
                      lifetime_ms: lifetime_ms
                    }})
                    Logger.info("[CertProvisioner] Cert issued for #{hostname}")

                  {:error, reason} ->
                    Logger.warning("[CertProvisioner] Failed to issue cert for #{hostname}: #{inspect(reason)}")
                end
              end

              # Schedule renewal at cert_lifetime / 2
              renewal_ms = div(lifetime_ms, 2)
              Process.send_after(self(), :renew, renewal_ms)

              renewal_days = Float.round(renewal_ms / (24 * 60 * 60 * 1000), 1)
              Logger.info("[CertProvisioner] All certs provisioned (lifetime=#{state.cert_lifetime_days}d), renewal in #{renewal_days} days")

              # Schedule periodic expiry checks (every hour)
              Process.send_after(self(), :check_expiry, 3_600_000)

              %{state | provisioned: true, status: :ok, retry_count: 0}

            {:error, reason} ->
              handle_provision_failure(state, reason)
          end
        after
          :gen_udp.close(socket)
        end

      {:error, reason} ->
        Logger.error("[CertProvisioner] Failed to open UDP socket: #{inspect(reason)}")
        handle_provision_failure(state, {:socket, reason})
    end
  end

  defp handle_provision_failure(state, reason) do
    retry_count = state.retry_count
    backoff_ms = retry_backoff_ms(retry_count)

    backoff_human = cond do
      backoff_ms >= 3_600_000 -> "#{div(backoff_ms, 3_600_000)}h"
      backoff_ms >= 60_000 -> "#{div(backoff_ms, 60_000)}m"
      true -> "#{div(backoff_ms, 1000)}s"
    end

    if state.provisioned do
      # We have existing certs — keep serving with them, but warn
      Logger.warning(
        "[CertProvisioner] Renewal failed: #{inspect(reason)}. " <>
        "Keeping existing certs. Retry #{retry_count + 1} in #{backoff_human}."
      )
    else
      Logger.warning(
        "[CertProvisioner] Provisioning failed: #{inspect(reason)}. " <>
        "Retry #{retry_count + 1} in #{backoff_human}."
      )
    end

    Process.send_after(self(), :provision, backoff_ms)

    new_status = if state.provisioned, do: :renewing, else: :error
    %{state | retry_count: retry_count + 1, status: new_status}
  end

  defp retry_backoff_ms(retry_count) do
    index = min(retry_count, length(@backoff_schedule) - 1)
    Enum.at(@backoff_schedule, index)
  end

  defp check_all_expiry(state) do
    lifetime_ms = state.cert_lifetime_days * 24 * 60 * 60 * 1000

    for svc <- state.services do
      hostname = "#{svc}.#{state.zone}"
      case check_expiry(hostname) do
        {:ok, :warning, days_remaining} ->
          Logger.warning(
            "[CertProvisioner] Cert for #{hostname} approaching expiry " <>
            "(#{Float.round(days_remaining, 1)} days remaining, 75% of #{state.cert_lifetime_days}d lifetime elapsed)"
          )

        {:ok, :critical, days_remaining} ->
          Logger.error(
            "[CertProvisioner] Cert for #{hostname} critically close to expiry! " <>
            "(#{Float.round(days_remaining, 1)} days remaining, 90% of #{state.cert_lifetime_days}d lifetime elapsed)"
          )

        {:ok, :expired, _} ->
          Logger.error("[CertProvisioner] Cert for #{hostname} has EXPIRED!")

        _ ->
          :ok
      end
    end

    # Update overall status if any cert is expired
    any_expired? =
      Enum.any?(state.services, fn svc ->
        hostname = "#{svc}.#{state.zone}"
        case check_expiry(hostname) do
          {:ok, :expired, _} -> true
          _ -> false
        end
      end)

    if any_expired? do
      Logger.error("[CertProvisioner] One or more certs have expired — forcing renewal")
      send(self(), :renew)
    end

    _ = lifetime_ms
    :ok
  end

  # ── Wire Protocol Helpers ──────────────────────────────────────────

  defp fetch_ca_root(socket, host, port) do
    query = <<0x14, 0x01>>
    :gen_udp.send(socket, host, port, query)

    case :gen_udp.recv(socket, 0, 5_000) do
      {:ok, {_, _, <<0x14, 0x01, 0x00, cert_len::unsigned-big-32, cert_der::binary-size(cert_len)>>}} ->
        {:ok, cert_der}

      {:ok, {_, _, <<0x14, 0x01, 0x01>>}} ->
        {:error, :ca_not_initialized}

      {:ok, {_, _, data}} ->
        {:error, {:unexpected_response, byte_size(data)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_ca_chain(socket, host, port) do
    query = <<0x14, 0x02>>
    :gen_udp.send(socket, host, port, query)

    case :gen_udp.recv(socket, 0, 5_000) do
      {:ok, {_, _, <<0x14, 0x02, 0x00, chain_len::unsigned-big-32, chain_pem::binary-size(chain_len)>>}} ->
        {:ok, chain_pem}

      {:ok, {_, _, <<0x14, 0x02, 0x01>>}} ->
        {:error, :ca_not_initialized}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp issue_service_cert(socket, host, port, hostname) do
    hostname_bin = hostname
    query = <<0x14, 0x03, byte_size(hostname_bin)::unsigned-big-16, hostname_bin::binary>>
    :gen_udp.send(socket, host, port, query)

    # Cert issuance may take longer (RSA key generation)
    case :gen_udp.recv(socket, 0, 30_000) do
      {:ok, {_, _, <<0x14, 0x03, 0x00,
                     cert_len::unsigned-big-32, cert_pem::binary-size(cert_len),
                     key_len::unsigned-big-32, key_pem::binary-size(key_len),
                     chain_len::unsigned-big-32, chain_pem::binary-size(chain_len)>>}} ->
        {:ok, %{cert_pem: cert_pem, key_pem: key_pem, chain_pem: chain_pem}}

      {:ok, {_, _, <<0x14, 0x03, 0x01>>}} ->
        {:error, :ca_not_initialized}

      {:ok, {_, _, <<0x14, 0x03, 0x02>>}} ->
        {:error, :issuance_failed}

      {:ok, {_, _, data}} ->
        {:error, {:unexpected_response, byte_size(data)}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── Config Parsing ─────────────────────────────────────────────────

  defp parse_ns_server do
    case System.get_env("ZTLP_NS_SERVER") do
      nil -> nil
      addr ->
        case String.split(addr, ":") do
          [host, port_str] ->
            case :inet.parse_address(String.to_charlist(host)) do
              {:ok, ip} -> {ip, String.to_integer(port_str)}
              _ -> nil
            end
          _ -> nil
        end
    end
  end

  defp parse_service_names do
    case System.get_env("ZTLP_GATEWAY_SERVICE_NAMES") do
      nil -> []
      names -> String.split(names, ",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
    end
  end

  defp parse_cert_lifetime_days do
    case System.get_env("ZTLP_GATEWAY_CERT_LIFETIME_DAYS") do
      nil -> @default_cert_lifetime_days
      str ->
        case Integer.parse(str) do
          {n, _} when n > 0 -> n
          _ -> @default_cert_lifetime_days
        end
    end
  end
end
